# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Jeroen Baten <jeroen@libreplan.dev>
"""Optional OIDC single sign-on for the admin area.

When ``OIDC_ISSUER`` and ``OIDC_CLIENT_ID`` are set, ``/admin/oidc`` starts an
Authorization Code + PKCE (S256) flow against the configured issuer (discovered
via ``/.well-known/openid-configuration``). The local username/password admin
login remains the default; SSO is strictly opt-in.

The PKCE verifier and nonce are kept server-side in the ``OidcPending`` table
(keyed by the random ``state``), never in the Flask session cookie, which is
signed but not encrypted.

``OIDC_BACKCHANNEL_ORIGIN`` lets the server reach the identity provider at a
different origin than the browser (e.g. the browser uses
``https://localhost:8444`` while the server, inside a container, uses
``http://keycloak:8080``). It only rewrites server-side fetches (discovery,
token, JWKS); the browser-facing authorization URL keeps the public issuer.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from functools import lru_cache
from urllib.parse import quote, urlsplit, urlunsplit

import jwt
import requests


class OidcError(Exception):
    """A user-facing OIDC failure (misconfig, IdP unreachable, bad token)."""


def configured(app) -> bool:
    return bool(app.config.get("OIDC_ISSUER") and app.config.get("OIDC_CLIENT_ID"))


def _backchannel(app, url: str) -> str:
    """Rewrite *url*'s scheme+host to ``OIDC_BACKCHANNEL_ORIGIN`` if set."""
    origin = (app.config.get("OIDC_BACKCHANNEL_ORIGIN") or "").strip()
    if not origin:
        return url
    src = urlsplit(url)
    bc = urlsplit(origin)
    return urlunsplit(
        (bc.scheme or src.scheme, bc.netloc, src.path, src.query, src.fragment)
    )


def _timeout(app) -> float:
    return float(app.config.get("OIDC_TIMEOUT_SECONDS", 10))


def discover(app) -> dict:
    issuer = app.config["OIDC_ISSUER"]
    url = _backchannel(app, f"{issuer.rstrip('/')}/.well-known/openid-configuration")
    try:
        resp = requests.get(url, timeout=_timeout(app))
        resp.raise_for_status()
    except requests.RequestException as exc:
        raise OidcError("De identity-provider is niet bereikbaar.") from exc
    doc = resp.json()
    for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        if not doc.get(key):
            raise OidcError("De identity-provider heeft een ongeldige configuratie.")
    if doc.get("issuer") and doc["issuer"] != issuer:
        # Guard against a misconfigured proxy returning a different issuer.
        raise OidcError("De identity-provider gaf een onverwachte issuer terug.")
    return doc


def pkce_pair() -> tuple[str, str]:
    """Return ``(verifier, challenge)`` for PKCE S256."""
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def new_token() -> str:
    return secrets.token_urlsafe(32)


def authorization_url(app, doc: dict, *, redirect_uri: str, state: str,
                     nonce: str, challenge: str) -> str:
    params = {
        "response_type": "code",
        "client_id": app.config["OIDC_CLIENT_ID"],
        "redirect_uri": redirect_uri,
        "scope": app.config.get("OIDC_SCOPES", "openid profile email"),
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    from urllib.parse import urlencode

    return doc["authorization_endpoint"] + "?" + urlencode(params)


def exchange_code(app, doc: dict, *, code: str, redirect_uri: str,
                  verifier: str) -> dict:
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": app.config["OIDC_CLIENT_ID"],
        "code_verifier": verifier,
    }
    secret = app.config.get("OIDC_CLIENT_SECRET", "")
    if secret:
        data["client_secret"] = secret
    try:
        resp = requests.post(
            _backchannel(app, doc["token_endpoint"]),
            data=data,
            timeout=_timeout(app),
            allow_redirects=False,
        )
    except requests.RequestException as exc:
        raise OidcError("De identity-provider is niet bereikbaar.") from exc
    if resp.status_code != 200:
        raise OidcError("De identity-provider heeft de aanmelding geweigerd.")
    body = resp.json()
    if not body.get("access_token") or not body.get("id_token"):
        raise OidcError("De identity-provider gaf geen bruikbare sessie terug.")
    return body


@lru_cache(maxsize=8)
def _jwk_client(jwks_uri: str) -> jwt.PyJWKClient:
    return jwt.PyJWKClient(jwks_uri)


def validate_id_token(app, doc: dict, id_token: str, *, expected_nonce: str) -> dict:
    """Verify signature (JWKS), iss, aud/azp, nonce and expiry of *id_token*."""
    issuer = app.config["OIDC_ISSUER"]
    client_id = app.config["OIDC_CLIENT_ID"]
    jwks_uri = _backchannel(app, doc["jwks_uri"])
    alg = doc.get("id_token_signing_alg_values_supported") or ["RS256"]
    try:
        signing_key = _jwk_client(jwks_uri).get_signing_key_from_jwt(id_token)
        claims = jwt.decode(
            id_token,
            signing_key.key,
            algorithms=alg,
            issuer=issuer,
            options={
                "verify_aud": False,
                "require": ["exp", "iat", "iss", "sub", "aud", "nonce"],
            },
        )
    except jwt.PyJWTError as exc:
        raise OidcError("Het inlogtoken is ongeldig.") from exc
    aud = claims.get("aud")
    if isinstance(aud, str):
        aud = [aud]
    if client_id not in (aud or []) and claims.get("azp") != client_id:
        raise OidcError("Het inlogtoken is niet voor deze client.")
    if not secrets.compare_digest(str(claims.get("nonce", "")), expected_nonce):
        raise OidcError("Het inlogtoken is niet voor deze aanmelding.")
    return claims


def check_authorization(app, access_token: str, organization_id: str) -> None:
    """When ``OIDC_AUTHORIZATION_URL`` is set, ask the parent application
    (e.g. OciServe) whether this user may administer badges for *organization_id*.
    The URL template contains ``{organization_id}``. A 200/204 means allowed;
    anything else raises :class:`OidcError`."""
    template = (app.config.get("OIDC_AUTHORIZATION_URL") or "").strip()
    if not template:
        return
    check_url = template.replace("{organization_id}", quote(organization_id, safe=""))
    try:
        resp = requests.get(
            check_url,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=_timeout(app),
            allow_redirects=False,
        )
    except requests.RequestException as exc:
        raise OidcError("De autorisatiecontrole is niet bereikbaar.") from exc
    if resp.status_code not in (200, 204):
        raise OidcError("Je account mag geen badges beheren.")

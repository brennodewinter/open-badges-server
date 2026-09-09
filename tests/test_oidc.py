# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Jeroen Baten <jeroen@libreplan.dev>
"""OIDC single sign-on flow, with the identity provider mocked at the
``badgeserver.oidc`` boundary so no real Keycloak or signing keys are needed."""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import pytest

from badgeserver import oidc
from badgeserver.extensions import db
from badgeserver.models import OidcPending

# A minimal discovery document; the backchannel origin is left empty in tests
# so these public URLs are used as-is.
FAKE_DOC = {
    "issuer": "https://idp.test/realms/test",
    "authorization_endpoint": "https://idp.test/realms/test/protocol/openid-connect/auth",
    "token_endpoint": "https://idp.test/realms/test/protocol/openid-connect/token",
    "jwks_uri": "https://idp.test/realms/test/protocol/openid-connect/certs",
    "id_token_signing_alg_values_supported": ["RS256"],
}


@pytest.fixture
def oidc_app(app):
    app.config["OIDC_ISSUER"] = "https://idp.test/realms/test"
    app.config["OIDC_CLIENT_ID"] = "keiko-native"
    return app


def _enable_idp(monkeypatch, *, claims=None):
    """Replace the IdP-facing functions with canned responses."""
    monkeypatch.setattr(oidc, "discover", lambda app: FAKE_DOC)
    monkeypatch.setattr(
        oidc,
        "exchange_code",
        lambda app, doc, **kw: {"access_token": "at", "id_token": "idt", "refresh_token": "rt"},
    )
    monkeypatch.setattr(
        oidc,
        "validate_id_token",
        lambda app, doc, id_token, **kw: claims or {"sub": "user-1", "name": "Alice"},
    )


def test_oidc_disabled_by_default(client):
    # No OIDC_ISSUER configured -> the route does not exist and the login page
    # offers no SSO link.
    assert client.get("/admin/oidc").status_code == 404
    body = client.get("/admin/login").data.decode()
    assert "single sign-on" not in body


def test_oidc_login_page_offers_sso(oidc_app, client):
    body = client.get("/admin/login").data.decode()
    assert "Sign in with single sign-on" in body
    assert "/admin/oidc" in body


def test_oidc_start_redirects_to_idp_with_pkce(oidc_app, client, monkeypatch):
    _enable_idp(monkeypatch)
    r = client.get("/admin/oidc?organization_id=org-1&next=/admin/badges")
    assert r.status_code == 302
    parts = urlsplit(r.headers["Location"])
    assert parts.scheme == "https"
    assert parts.netloc == "idp.test"
    assert parts.path == "/realms/test/protocol/openid-connect/auth"
    qs = parse_qs(parts.query)
    assert qs["response_type"] == ["code"]
    assert qs["client_id"] == ["keiko-native"]
    assert qs["code_challenge_method"] == ["S256"]
    assert "code_challenge" in qs and qs["code_challenge"][0]
    assert "state" in qs and "nonce" in qs
    # The PKCE verifier is kept server-side, not in the redirect.
    state = qs["state"][0]
    with oidc_app.app_context():
        pending = db.session.get(OidcPending, state)
        assert pending is not None
        assert pending.verifier
        assert pending.organization_id == "org-1"
        assert pending.next_path == "/admin/badges"


def test_oidc_callback_establishes_session(oidc_app, client, monkeypatch):
    _enable_idp(monkeypatch)
    start = client.get("/admin/oidc?next=/admin/badges")
    state = parse_qs(urlsplit(start.headers["Location"]).query)["state"][0]

    cb = client.get(f"/admin/oidc/callback?state={state}&code=code123")
    assert cb.status_code == 302
    assert cb.headers["Location"].endswith("/admin/badges")

    # The same client (session cookie) is now authenticated as an OIDC admin.
    assert client.get("/admin/").status_code == 200
    # The pending row is consumed.
    with oidc_app.app_context():
        assert db.session.get(OidcPending, state) is None


def test_oidc_callback_rejects_open_redirect(oidc_app, client, monkeypatch):
    _enable_idp(monkeypatch)
    # An absolute 'next' must be ignored in favour of the admin dashboard.
    start = client.get("/admin/oidc?next=https://evil.example/")
    state = parse_qs(urlsplit(start.headers["Location"]).query)["state"][0]
    cb = client.get(f"/admin/oidc/callback?state={state}&code=code123")
    assert cb.headers["Location"].endswith("/admin/")


def test_oidc_callback_rejects_replay(oidc_app, client, monkeypatch):
    _enable_idp(monkeypatch)
    start = client.get("/admin/oidc")
    state = parse_qs(urlsplit(start.headers["Location"]).query)["state"][0]
    first = client.get(f"/admin/oidc/callback?state={state}&code=code123")
    assert first.status_code == 302
    # A second attempt with the same state finds no pending row -> login page.
    second = client.get(f"/admin/oidc/callback?state={state}&code=code123")
    assert second.headers["Location"].endswith("/admin/login")


def test_oidc_callback_rejects_unknown_state(oidc_app, client):
    r = client.get("/admin/oidc/callback?state=bogus&code=code123")
    assert r.headers["Location"].endswith("/admin/login")


def test_oidc_callback_handles_idp_error(oidc_app, client, monkeypatch):
    _enable_idp(monkeypatch)
    start = client.get("/admin/oidc")
    state = parse_qs(urlsplit(start.headers["Location"]).query)["state"][0]
    r = client.get(f"/admin/oidc/callback?state={state}&error=access_denied")
    assert r.headers["Location"].endswith("/admin/login")
    with oidc_app.app_context():
        assert db.session.get(OidcPending, state) is None


def test_oidc_callback_surfaces_token_error(oidc_app, client, monkeypatch):
    _enable_idp(monkeypatch)

    def _raise(*a, **k):
        raise oidc.OidcError("nope")

    monkeypatch.setattr(oidc, "exchange_code", _raise)
    start = client.get("/admin/oidc")
    state = parse_qs(urlsplit(start.headers["Location"]).query)["state"][0]
    r = client.get(f"/admin/oidc/callback?state={state}&code=code123")
    assert r.headers["Location"].endswith("/admin/login")

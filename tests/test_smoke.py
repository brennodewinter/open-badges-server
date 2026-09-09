# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Jeroen Baten <jeroen@libreplan.dev>

from __future__ import annotations

import hashlib

from badgeserver.extensions import db
from badgeserver.models import Assertion, BadgeClass


def _make_badge(app):
    with app.app_context():
        badge = BadgeClass(
            slug="tester",
            issuer_slug="main",
            name="Tester",
            description="For testing.",
            image_path="badge-tester.png",
            criteria_narrative="Run the tests.",
        )
        db.session.add(badge)
        db.session.commit()
        # a real image so baking works
        from PIL import Image

        import os

        Image.new("RGBA", (64, 64), (10, 10, 10, 255)).save(
            os.path.join(app.config["UPLOAD_DIR"], "badge-tester.png"), "PNG"
        )


def test_public_pages(client):
    assert client.get("/").status_code == 200
    assert client.get("/healthz").get_json() == {"status": "ok"}
    assert client.get("/nope").status_code == 404


def test_footer_version(client):
    from badgeserver.version import app_version

    v = app_version()
    body = client.get("/").data.decode()
    shown = '<span class="version">' in body
    assert shown == (v != "unknown")
    if shown:
        assert v in body


def test_app_version_env_override(monkeypatch):
    from badgeserver import version

    version.app_version.cache_clear()
    try:
        monkeypatch.setenv("BADGESERVER_VERSION", "v9.9.9 (deadbee)")
        assert version.app_version() == "v9.9.9 (deadbee)"
    finally:
        version.app_version.cache_clear()


def test_project_logo_links_to_repo(client, auth_client):
    repo = "https://github.com/LibrePlan/open-badges-server"
    for page in (client.get("/"), auth_client.get("/admin/")):
        body = page.data.decode()
        assert "/static/project-logo.png" in body
        assert f'href="{repo}"' in body
    assert client.get("/static/project-logo.png").status_code == 200


def test_site_logo_can_be_overridden(app, client):
    app.config["SITE_LOGO"] = "https://vigilis.example/assets/logo.png"
    body = client.get("/").data.decode()
    assert 'src="https://vigilis.example/assets/logo.png"' in body
    assert "/static/project-logo.png" not in body


def test_site_logo_can_be_a_static_filename(app, client):
    app.config["SITE_LOGO"] = "vigilis-logo.png"
    body = client.get("/").data.decode()
    assert 'src="/static/vigilis-logo.png"' in body


def test_issuer_json(client):
    doc = client.get("/issuer/main.json").get_json()
    assert doc["@context"] == "https://w3id.org/openbadges/v2"
    assert doc["type"] == "Issuer"
    assert doc["id"] == "https://badges.test/issuer/main.json"
    assert doc["email"] == "badges@example.com"


def test_badgeclass_json(app, client):
    _make_badge(app)
    doc = client.get("/b/tester.json").get_json()
    assert doc["type"] == "BadgeClass"
    assert doc["id"] == "https://badges.test/b/tester.json"
    assert doc["issuer"] == "https://badges.test/issuer/main.json"
    assert doc["image"] == "https://badges.test/b/tester/image"


def test_award_flow_and_hash(app):
    _make_badge(app)
    with app.app_context():
        from badgeserver.issuing import award_badge

        badge = db.session.get(BadgeClass, "tester")
        result = award_badge(badge, "person@example.com", send_email=False)
        uuid = result.assertion.uuid
        salt = result.assertion.salt

    doc = app.test_client().get(f"/a/{uuid}.json").get_json()
    assert doc["type"] == "Assertion"
    assert doc["verification"] == {"type": "hosted"}
    assert doc["badge"] == "https://badges.test/b/tester.json"
    expected = "sha256$" + hashlib.sha256(f"person@example.com{salt}".encode()).hexdigest()
    assert doc["recipient"]["identity"] == expected
    assert doc["recipient"]["hashed"] is True
    assert "person@example.com" not in app.test_client().get(f"/a/{uuid}.json").text


def test_revocation(app, auth_client):
    _make_badge(app)
    with app.app_context():
        from badgeserver.issuing import award_badge

        badge = db.session.get(BadgeClass, "tester")
        uuid = award_badge(badge, "revoke@example.com", send_email=False).assertion.uuid

    r = auth_client.post(f"/admin/assertions/{uuid}/revoke", data={"reason": "mistake"})
    assert r.status_code in (302, 200)
    doc = auth_client.get(f"/a/{uuid}.json").get_json()
    assert doc["revoked"] is True
    assert doc["revocationReason"] == "mistake"


def test_baked_png_contains_url(app):
    _make_badge(app)
    with app.app_context():
        from badgeserver.issuing import award_badge

        badge = db.session.get(BadgeClass, "tester")
        uuid = award_badge(badge, "bake@example.com", send_email=False).assertion.uuid

    png = app.test_client().get(f"/a/{uuid}/badge.png").data
    from io import BytesIO

    from PIL import Image

    with Image.open(BytesIO(png)) as img:
        assert img.text["openbadges"] == f"https://badges.test/a/{uuid}.json"


def test_admin_requires_login(client):
    r = client.get("/admin/", follow_redirects=False)
    assert r.status_code == 302
    assert "/admin/login" in r.headers["Location"]


def test_login_and_dashboard(auth_client):
    assert auth_client.get("/admin/").status_code == 200


def test_csrf_enforced(app):
    app.config["WTF_CSRF_ENABLED"] = True
    c = app.test_client()
    c.post("/admin/login", data={"username": "admin", "password": "correct-horse-battery"})
    # no token -> rejected
    r = c.post("/admin/change-password", data={})
    assert r.status_code == 400


# --- composed badges -------------------------------------------------------


def _png_bytes(w=120, h=90):
    from io import BytesIO

    from PIL import Image

    buf = BytesIO()
    Image.new("RGBA", (w, h), (200, 80, 40, 255)).save(buf, "PNG")
    buf.seek(0)
    return buf


def _compose(auth_client, **overrides):
    data = {
        "name": "Release Manager",
        "description": "Ships releases.",
        "art_mode": "compose",
        "art_shape": "shield",
        "art_bg": "#1f6f43",
        "art_accent": "#d4af37",
        "logo": (_png_bytes(), "logo.png"),
        "submit": "Save badge",
    }
    data.update(overrides)
    return auth_client.post(
        "/admin/badges/new", data=data, content_type="multipart/form-data",
        follow_redirects=True,
    )


def test_compose_badge(app, auth_client):
    assert _compose(auth_client, art_shape="hexagon").status_code == 200
    with app.app_context():
        badge = db.session.get(BadgeClass, "release-manager")
        assert badge.composed and badge.art_shape == "hexagon"
        assert badge.art_bg == "#1f6f43" and badge.logo_path

    from io import BytesIO

    from PIL import Image

    img = Image.open(BytesIO(auth_client.get("/b/release-manager/image").data))
    assert img.format == "PNG" and img.size == (app.config["BADGE_IMAGE_SIZE"],) * 2
    assert auth_client.get("/b/release-manager/logo").status_code == 200


def test_compose_crest_shape(app, auth_client):
    from io import BytesIO

    from PIL import Image

    assert _compose(auth_client, name="Crested", art_shape="crest").status_code == 200
    with app.app_context():
        assert db.session.get(BadgeClass, "crested").art_shape == "crest"
    img = Image.open(BytesIO(auth_client.get("/b/crested/image").data))
    n = app.config["BADGE_IMAGE_SIZE"]
    assert img.format == "PNG" and img.size == (n, n)
    # the curved outline leaves the corners transparent
    assert img.convert("RGBA").getpixel((1, 1))[3] == 0


def test_copy_badge(app, auth_client):
    import os

    _compose(
        auth_client, name="Release Manager", art_shape="crest", art_bg="#1f6f43",
        art_logo_scale="130", self_service="y", tags="eng, release",
    )

    # the copy form is pre-filled from the source
    html = auth_client.get("/admin/badges/new?copy=release-manager").data.decode()
    assert 'value="Release Manager-copy"' in html
    assert '<option selected value="crest">' in html
    assert 'value="#1f6f43"' in html
    assert 'name="self_service"' in html and "checked" in html
    assert 'name="copy" value="release-manager"' in html

    # submitting it (no new upload) makes a real duplicate with copied art
    r = auth_client.post(
        "/admin/badges/new?copy=release-manager",
        data={
            "name": "Release Manager-copy", "description": "Ships releases.",
            "art_mode": "compose", "art_shape": "crest", "art_bg": "#1f6f43",
            "art_accent": "#d4af37", "art_logo_scale": "130", "art_border_width": "8",
            "art_logo_offset": "0", "art_title_offset": "0", "self_service": "y",
            "tags": "eng, release", "copy": "release-manager", "submit": "Save badge",
        },
        content_type="multipart/form-data", follow_redirects=True,
    )
    assert r.status_code == 200
    with app.app_context():
        src = db.session.get(BadgeClass, "release-manager")
        dup = db.session.get(BadgeClass, "release-manager-copy")
        assert dup is not None and dup.slug != src.slug
        assert dup.name == "Release Manager-copy"
        assert dup.art_shape == "crest" and dup.art_logo_scale == 130
        assert dup.self_service and dup.composed
        assert dup.logo_path == "logo-release-manager-copy.png"
        assert os.path.exists(os.path.join(app.config["UPLOAD_DIR"], dup.image_path))

    # an unknown source just gives a blank form
    assert auth_client.get("/admin/badges/new?copy=nope").status_code == 200

    # and the badge list offers the Copy link
    assert b"/admin/badges/new?copy=release-manager" in auth_client.get("/admin/badges").data


def test_compose_rerenders_on_rename(app, auth_client):
    _compose(auth_client)
    import os

    path = os.path.join(app.config["UPLOAD_DIR"], "badge-release-manager.png")
    before = open(path, "rb").read()
    r = auth_client.post(
        "/admin/badges/release-manager/edit",
        data={
            "name": "Release Wrangler", "description": "Ships releases.",
            "art_mode": "compose", "art_shape": "octagon",
            "art_bg": "#1f6f43", "art_accent": "#d4af37", "submit": "Save badge",
        },
        content_type="multipart/form-data", follow_redirects=True,
    )
    assert r.status_code == 200
    assert open(path, "rb").read() != before


def test_compose_to_upload_switch_clears_logo(app, auth_client):
    _compose(auth_client)
    auth_client.post(
        "/admin/badges/release-manager/edit",
        data={
            "name": "Release Manager", "description": "d", "art_mode": "upload",
            "art_bg": "#1f6f43", "art_accent": "#d4af37",
            "image": (_png_bytes(256, 256), "final.png"), "submit": "Save badge",
        },
        content_type="multipart/form-data", follow_redirects=True,
    )
    with app.app_context():
        badge = db.session.get(BadgeClass, "release-manager")
        assert not badge.composed and badge.logo_path is None


def test_award_composed_badge_bakes(app, auth_client):
    _compose(auth_client)
    with app.app_context():
        from badgeserver.issuing import award_badge

        badge = db.session.get(BadgeClass, "release-manager")
        uuid = award_badge(badge, "r@example.com", send_email=False).assertion.uuid

    from io import BytesIO

    from PIL import Image

    png = auth_client.get(f"/a/{uuid}/badge.png").data
    with Image.open(BytesIO(png)) as img:
        assert img.text["openbadges"] == f"https://badges.test/a/{uuid}.json"


def test_logo_scale_changes_image(app, auth_client):
    import os

    _compose(auth_client, name="Small", art_shape="octagon", art_logo_scale="60")
    _compose(auth_client, name="Big", art_shape="octagon", art_logo_scale="150")
    updir = app.config["UPLOAD_DIR"]
    small = open(os.path.join(updir, "badge-small.png"), "rb").read()
    big = open(os.path.join(updir, "badge-big.png"), "rb").read()
    assert small != big
    with app.app_context():
        assert db.session.get(BadgeClass, "small").art_logo_scale == 60


def test_border_width_changes_image(app, auth_client):
    import os

    _compose(auth_client, name="Thin", art_shape="octagon", art_border_width="0")
    _compose(auth_client, name="Thick", art_shape="octagon", art_border_width="30")
    updir = app.config["UPLOAD_DIR"]
    thin = open(os.path.join(updir, "badge-thin.png"), "rb").read()
    thick = open(os.path.join(updir, "badge-thick.png"), "rb").read()
    assert thin != thick
    with app.app_context():
        assert db.session.get(BadgeClass, "thin").art_border_width == 0
        assert db.session.get(BadgeClass, "thick").art_border_width == 30


def test_position_offsets_change_image(app, auth_client):
    import os

    _compose(auth_client, name="Centered", art_shape="octagon")
    _compose(
        auth_client, name="Shifted", art_shape="octagon",
        art_logo_offset="15", art_title_offset="-15", art_logo_scale="200",
    )
    updir = app.config["UPLOAD_DIR"]
    a = open(os.path.join(updir, "badge-centered.png"), "rb").read()
    b = open(os.path.join(updir, "badge-shifted.png"), "rb").read()
    assert a != b
    with app.app_context():
        s = db.session.get(BadgeClass, "shifted")
        assert (s.art_logo_offset, s.art_title_offset, s.art_logo_scale) == (15, -15, 200)


def test_preview_endpoint(app, auth_client, client):
    r = auth_client.post(
        "/admin/badges/preview",
        data={
            "name": "Preview", "art_shape": "shield", "art_bg": "#1f6f43",
            "art_accent": "#d4af37", "art_logo_scale": "120",
            "logo": (_png_bytes(), "logo.png"),
        },
        content_type="multipart/form-data",
    )
    assert r.status_code == 200
    assert r.headers["Content-Type"] == "image/png" and len(r.data) > 500

    # not logged in -> redirected to login
    assert client.post(
        "/admin/badges/preview", data={"name": "x"}, content_type="multipart/form-data"
    ).status_code == 302


def test_preview_falls_back_to_stored_logo(app, auth_client):
    _compose(auth_client, name="Stored")
    r = auth_client.post(
        "/admin/badges/preview",
        data={
            "name": "Stored", "slug": "stored", "art_shape": "circle",
            "art_bg": "#2b6cb0", "art_accent": "#b0872b", "art_logo_scale": "100",
        },
        content_type="multipart/form-data",
    )
    assert r.status_code == 200 and r.headers["Content-Type"] == "image/png"


def test_svg_finished_upload(app, auth_client):
    import pytest

    pytest.importorskip("cairosvg")
    svg = (
        b'<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" '
        b'width="100" height="100"><circle cx="50" cy="50" r="40" fill="#369"/></svg>'
    )
    from io import BytesIO

    r = auth_client.post(
        "/admin/badges/new",
        data={
            "name": "Vector Badge", "description": "d", "art_mode": "upload",
            "image": (BytesIO(svg), "art.svg"), "submit": "Save badge",
        },
        content_type="multipart/form-data", follow_redirects=True,
    )
    assert r.status_code == 200
    from PIL import Image

    img = Image.open(BytesIO(auth_client.get("/b/vector-badge/image").data))
    assert img.format == "PNG"


# --- badge verification --------------------------------------------------


def _award_local(app, auth_client, email="alice@example.com"):
    _compose(auth_client, name="Verified", art_shape="circle")
    with app.app_context():
        from badgeserver.issuing import award_badge

        badge = db.session.get(BadgeClass, "verified")
        return award_badge(badge, email, send_email=False).assertion.uuid


def test_verify_local_valid(app, auth_client):
    uuid = _award_local(app, auth_client)
    with app.app_context():
        from badgeserver.verify import verify

        r = verify(f"{app.config['EXTERNAL_URL']}/a/{uuid}")
        assert r.verdict == "valid" and r.issued_by_us
        assert r.badge["name"] == "Verified"
        assert verify(f"{app.config['EXTERNAL_URL']}/a/{uuid}", "alice@example.com").recipient_match is True
        assert verify(f"{app.config['EXTERNAL_URL']}/a/{uuid}", "bob@example.com").recipient_match is False


def test_verify_local_revoked_and_unknown(app, auth_client):
    uuid = _award_local(app, auth_client)
    with app.app_context():
        from badgeserver.verify import verify

        db.session.get(Assertion, uuid).revoked = True
        db.session.commit()
        assert verify(f"{app.config['EXTERNAL_URL']}/a/{uuid}").verdict == "revoked"
        assert verify(f"{app.config['EXTERNAL_URL']}/a/00000000-0000-0000-0000-000000000000").verdict == "invalid"


def test_verify_ssrf_and_garbage(app):
    with app.app_context():
        from badgeserver.verify import VerifyError, check_url_allowed, verify

        for bad in ("http://127.0.0.1/", "http://169.254.169.254/", "http://[::1]/", "file:///etc/passwd"):
            try:
                check_url_allowed(bad)
                raise AssertionError(f"{bad} should be blocked")
            except VerifyError:
                pass
        assert verify("hello world").verdict == "invalid"
        assert verify("").verdict == "invalid"
        assert verify(
            '{"@context":"https://www.w3.org/ns/credentials/v2",'
            '"type":["VerifiableCredential","OpenBadgeCredential"]}'
        ).verdict == "unsupported"


def test_verify_external_hosted(app, monkeypatch):
    import json

    import badgeserver.verify as V

    docs = {
        "https://acme.test/i.json": {
            "@context": V_CONTEXT, "type": "Issuer", "id": "https://acme.test/i.json",
            "name": "Acme", "url": "https://acme.test", "email": "b@acme.test",
        },
        "https://acme.test/b.json": {
            "@context": V_CONTEXT, "type": "BadgeClass", "id": "https://acme.test/b.json",
            "name": "Widget Master", "description": "d", "image": "https://acme.test/b.png",
            "issuer": "https://acme.test/i.json",
        },
        "https://acme.test/a/1.json": {
            "@context": V_CONTEXT, "type": "Assertion", "id": "https://acme.test/a/1.json",
            "recipient": {"type": "email", "hashed": False, "identity": "u@acme.test"},
            "badge": "https://acme.test/b.json", "issuedOn": "2026-01-02T00:00:00+00:00",
            "verification": {"type": "hosted"},
        },
    }
    monkeypatch.setattr(V, "check_url_allowed", lambda u: None)
    monkeypatch.setattr(V, "_fetch", lambda url, *, max_bytes: (json.dumps(docs[url]).encode(), "application/json"))
    with app.app_context():
        r = V.verify("https://acme.test/a/1.json")
        assert r.verdict == "valid" and not r.issued_by_us and r.issuer["name"] == "Acme"
        assert V.verify("https://acme.test/a/1.json", "u@acme.test").recipient_match is True
        # served from a URL that isn't its id
        docs["https://evil.test/x.json"] = docs["https://acme.test/a/1.json"]
        assert V.verify("https://evil.test/x.json").verdict == "invalid"


def test_verify_signed(app, monkeypatch):
    import json

    pytest = __import__("pytest")
    jwt = pytest.importorskip("jwt")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    import badgeserver.verify as V

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    payload = {
        "@context": V_CONTEXT, "type": "Assertion", "id": "urn:uuid:sig1",
        "recipient": {"type": "email", "hashed": False, "identity": "z@acme.test"},
        "badge": "https://acme.test/b.json", "issuedOn": "2026-03-01T00:00:00+00:00",
        "verification": {"type": "signed", "creator": "https://acme.test/key.json"},
    }
    token = jwt.PyJWS().encode(json.dumps(payload).encode(), key, algorithm="RS256")
    docs = {
        "https://acme.test/key.json": {
            "type": "CryptographicKey", "id": "https://acme.test/key.json",
            "owner": "https://acme.test/i.json", "publicKeyPem": pem,
        },
        "https://acme.test/i.json": {
            "@context": V_CONTEXT, "type": "Issuer", "id": "https://acme.test/i.json",
            "name": "Acme", "url": "https://acme.test", "email": "b@acme.test",
            "publicKey": "https://acme.test/key.json",
            "revocationList": "https://acme.test/rl.json",
        },
        "https://acme.test/b.json": {
            "@context": V_CONTEXT, "type": "BadgeClass", "id": "https://acme.test/b.json",
            "name": "Signed Badge", "description": "d", "issuer": "https://acme.test/i.json",
        },
        "https://acme.test/rl.json": {"revokedAssertions": []},
    }
    monkeypatch.setattr(V, "check_url_allowed", lambda u: None)
    monkeypatch.setattr(V, "_fetch", lambda url, *, max_bytes: (json.dumps(docs[url]).encode(), "application/json"))
    with app.app_context():
        r = V.verify(token)
        assert r.verdict == "valid"
        assert any("Signature verified" in c.label and c.status == "pass" for c in r.checks)
        assert V.verify(token[:-6] + "AAAAAA").verdict == "invalid"
        docs["https://acme.test/rl.json"] = {"revokedAssertions": ["urn:uuid:sig1"]}
        assert V.verify(token).verdict == "revoked"


def test_verify_page(app, client, auth_client):
    uuid = _award_local(app, auth_client)
    assert client.get("/verify").status_code == 200
    r = client.get(f"/verify?url={app.config['EXTERNAL_URL']}/a/{uuid}")
    assert r.status_code == 200 and b"Valid badge" in r.data
    # admin nav links to it
    assert b'href="/verify"' in auth_client.get("/admin/").data


V_CONTEXT = "https://w3id.org/openbadges/v2"


# --- self-service claiming ---------------------------------------------


def _self_service_badge(app, auth_client, **kw):
    kw.setdefault("self_service", "y")
    _compose(auth_client, name="Fan", art_shape="circle", **kw)
    with app.app_context():
        return db.session.get(BadgeClass, "fan")


def _mailable(app, monkeypatch):
    app.config.update(MAIL_ENABLED=True, SMTP_HOST="smtp.test", MAIL_FROM="b@test")
    sent = []
    monkeypatch.setattr("badgeserver.mail._send", lambda msg: sent.append(msg))
    return sent


def test_claim_flow(app, client, auth_client, monkeypatch):
    from badgeserver.models import Assertion, BadgeClaim

    _self_service_badge(app, auth_client)
    sent = _mailable(app, monkeypatch)

    assert b'action="/b/fan/claim"' in client.get("/b/fan").data
    assert b"claimable" in client.get("/").data

    r = client.post("/b/fan/claim", data={"email": "fan@example.com", "submit": "x"})
    assert r.status_code == 200 and b"Check your e-mail" in r.data
    assert len(sent) == 1 and "Confirm your Fan badge" in sent[0]["Subject"]
    with app.app_context():
        claim = BadgeClaim.query.one()
        assert claim.confirmed_on is None and Assertion.query.count() == 0
        token = claim.token

    sent.clear()
    # the landing page is a GET that awards nothing yet
    r = client.get(f"/claim/{token}", follow_redirects=False)
    assert r.status_code == 200 and b"Get my badge" in r.data
    with app.app_context():
        assert Assertion.query.count() == 0

    # the POST performs the award
    r = client.post(f"/claim/{token}", data={"submit": "x"}, follow_redirects=False)
    assert r.status_code == 302 and "/a/" in r.headers["Location"]
    assert r.headers["Cache-Control"] == "no-store"
    uuid = r.headers["Location"].rstrip("/").rsplit("/", 1)[-1]
    with app.app_context():
        a = db.session.get(Assertion, uuid)
        assert a and a.recipient_email == "fan@example.com"
        assert db.session.get(BadgeClaim, token).confirmed_on is not None
    assert any("awarded: Fan" in m["Subject"] for m in sent)

    # idempotent: GET and POST both just return to the existing assertion
    r2 = client.get(f"/claim/{token}", follow_redirects=False)
    assert r2.status_code == 302 and r2.headers["Location"].rstrip("/").endswith(uuid)
    r3 = client.post(f"/claim/{token}", data={"submit": "x"}, follow_redirects=False)
    assert r3.status_code == 302 and r3.headers["Location"].rstrip("/").endswith(uuid)
    with app.app_context():
        assert Assertion.query.count() == 1


def test_claim_when_already_awarded(app, client, auth_client, monkeypatch):
    from badgeserver.models import Assertion, BadgeClaim

    _self_service_badge(app, auth_client)
    sent = _mailable(app, monkeypatch)

    # already hold the badge
    with app.app_context():
        from badgeserver.issuing import award_badge

        award_badge(db.session.get(BadgeClass, "fan"), "fan@example.com", send_email=False)

    # claim again -> confirm -> "already have it" page, no second award e-mail
    client.post("/b/fan/claim", data={"email": "fan@example.com", "submit": "x"})
    with app.app_context():
        token = BadgeClaim.query.filter_by(email="fan@example.com", confirmed_on=None).one().token
    sent.clear()
    r = client.post(f"/claim/{token}", data={"submit": "x"}, follow_redirects=False)
    assert r.status_code == 200
    body = r.data.decode()
    assert "You already have this badge" in body
    assert "issued to this e-mail address on" in body
    assert f'action="/claim/{token}/resend"' in body
    assert not any("awarded" in m["Subject"] for m in sent)

    # the re-send button works and only mails the recipient's own address
    r = client.post(f"/claim/{token}/resend", data={"submit": "x"}, follow_redirects=False)
    assert r.status_code == 302 and "/a/" in r.headers["Location"]
    assert len(sent) == 1 and sent[0]["To"] == "fan@example.com"
    assert "awarded: Fan" in sent[0]["Subject"]

    assert client.post("/claim/nope/resend", data={"submit": "x"}).status_code == 404
    with app.app_context():
        assert Assertion.query.count() == 1


def test_claim_expired(app, client, auth_client, monkeypatch):
    from datetime import datetime, timedelta, timezone

    from badgeserver.models import Assertion, BadgeClaim

    _self_service_badge(app, auth_client)
    _mailable(app, monkeypatch)
    with app.app_context():
        entry = BadgeClaim.make("fan", "old@example.com", 24)
        entry.expires_on = datetime.now(timezone.utc) - timedelta(hours=1)
        db.session.add(entry)
        db.session.commit()
        token = entry.token
    r = client.get(f"/claim/{token}")
    assert r.status_code == 200 and b"has expired" in r.data
    with app.app_context():
        assert Assertion.query.count() == 0


def test_claim_guards(app, client, auth_client, monkeypatch):
    _self_service_badge(app, auth_client)
    _compose(auth_client, name="Private", art_shape="circle")  # self_service off
    sent = _mailable(app, monkeypatch)

    assert client.post("/b/private/claim", data={"email": "a@b.com", "submit": "x"}).status_code == 404

    app.config["SELF_SERVICE_ENABLED"] = False
    assert client.post("/b/fan/claim", data={"email": "a@b.com", "submit": "x"}).status_code == 404
    assert b"/b/fan/claim" not in client.get("/b/fan").data
    app.config["SELF_SERVICE_ENABLED"] = True

    # SMTP not configured
    app.config["MAIL_ENABLED"] = False
    r = client.post("/b/fan/claim", data={"email": "z@b.com", "submit": "x"}, follow_redirects=False)
    assert r.status_code == 302 and r.headers["Location"].endswith("/b/fan")
    with app.app_context():
        from badgeserver.models import BadgeClaim

        assert BadgeClaim.query.count() == 0


# --- internationalisation --------------------------------------------------


def test_lang_query_switches_and_sticks(client):
    r = client.get("/?lang=es")
    assert r.status_code == 200
    assert "Insignias".encode() in r.data  # nav label, Spanish
    assert 'lang="es"'.encode() in r.data
    with client.session_transaction() as sess:
        assert sess["lang"] == "es"
    # the choice persists without ?lang= on the next request
    assert "Insignias".encode() in client.get("/").data


def test_accept_language_header_without_cookie(client):
    r = client.get("/", headers={"Accept-Language": "de"})
    assert 'lang="de"'.encode() in r.data
    assert "Abzeichen".encode() in r.data


def test_unknown_lang_is_ignored(client):
    r = client.get("/?lang=xx")
    assert 'lang="en"'.encode() in r.data
    with client.session_transaction() as sess:
        assert "lang" not in sess


def test_all_catalogs_load(app):
    from flask_babel import force_locale, gettext

    with app.test_request_context("/"):
        english = gettext("Sign in")
        for code in ("es", "de", "fr", "nl"):
            with force_locale(code):
                assert gettext("Sign in") != english


def test_confirmation_email_follows_visitor_language(app, client, auth_client, monkeypatch):
    _self_service_badge(app, auth_client)
    sent = _mailable(app, monkeypatch)

    r = client.post(
        "/b/fan/claim?lang=nl", data={"email": "fan@example.com", "submit": "x"}
    )
    assert r.status_code == 200
    assert len(sent) == 1
    assert sent[0]["Subject"] == "Bevestig je Fan-badge"
    body = sent[0].get_body(("plain",)).get_content()
    assert "Bevestig en ontvang je badge" in body


# --- security hardening --------------------------------------------------


def test_claim_does_not_leak_existing_holders(app, client, auth_client, monkeypatch):
    _self_service_badge(app, auth_client)
    _mailable(app, monkeypatch)
    with app.app_context():
        from badgeserver.issuing import award_badge

        award_badge(db.session.get(BadgeClass, "fan"), "member@example.com", send_email=False)

    r = client.post(
        "/b/fan/claim", data={"email": "member@example.com", "submit": "x"},
        follow_redirects=False,
    )
    # same generic "check your e-mail" page as a first-time claimant -- no 302
    # to the existing assertion that would confirm the address holds the badge
    assert r.status_code == 200 and b"Check your e-mail" in r.data


def test_login_next_open_redirect_blocked(app):
    for evil in ("//evil.example", "/\\evil.example", "https://evil.example"):
        c = app.test_client()
        r = c.post(
            f"/admin/login?next={evil}",
            data={"username": "admin", "password": "correct-horse-battery"},
            follow_redirects=False,
        )
        assert r.status_code == 302 and "evil.example" not in r.headers["Location"]
    # a genuine local path is still honoured
    c = app.test_client()
    r = c.post(
        "/admin/login?next=/admin/issuer",
        data={"username": "admin", "password": "correct-horse-battery"},
        follow_redirects=False,
    )
    assert r.headers["Location"].endswith("/admin/issuer")


def test_admin_pages_are_not_cacheable(auth_client):
    assert auth_client.get("/admin/").headers.get("Cache-Control") == "no-store"


def test_csv_award_rejects_bad_addresses(app, auth_client):
    _compose(auth_client, name="Bulk List")
    from io import BytesIO

    blob = (
        b"good@example.com\n"
        b'"inject@example.com\nBcc: evil@example.net"\n'
        b"not-an-email\n"
        b"other@example.com\n"
    )
    r = auth_client.post(
        "/admin/badges/bulk-list/award-csv",
        data={"file": (BytesIO(blob), "list.csv"), "submit": "x"},
        content_type="multipart/form-data", follow_redirects=True,
    )
    assert r.status_code == 200
    with app.app_context():
        held = {a.recipient_email for a in Assertion.query.all()}
    assert held == {"good@example.com", "other@example.com"}


def test_duplicate_active_award_is_blocked(app, auth_client):
    _compose(auth_client, name="Once Only")
    with app.app_context():
        from badgeserver.issuing import AlreadyAwarded, award_badge

        badge = db.session.get(BadgeClass, "once-only")
        award_badge(badge, "dup@example.com", send_email=False)
        # even bypassing the pre-check, the partial unique index stops a 2nd
        import pytest

        with pytest.raises(AlreadyAwarded):
            award_badge(badge, "dup@example.com", send_email=False, allow_duplicate=True)
        assert Assertion.query.filter_by(recipient_email="dup@example.com").count() == 1


def test_verify_bounds_baked_png_recursion(app, monkeypatch):
    import badgeserver.verify as V

    calls = []

    def fake_fetch(url, *, max_bytes):
        calls.append(url)
        return b"\x89PNG\r\n\x1a\n" + b"payload", "image/png"

    monkeypatch.setattr(V, "check_url_allowed", lambda u: ["93.184.216.34"])
    monkeypatch.setattr(V, "_fetch", fake_fetch)
    monkeypatch.setattr(V, "read_baked_from_bytes", lambda b: "https://loop.test/next.png")

    with app.app_context():
        r = V.verify("https://loop.test/start.png")

    assert r.verdict == "invalid"
    assert "nested images" in (r.error or "")
    assert len(calls) <= V._MAX_PNG_DEPTH + 1


def test_verify_fetch_budget_unit():
    import pytest

    import badgeserver.verify as V

    b = V._Budget()
    for _ in range(V._MAX_FETCHES):
        b.spend_fetch()
    with pytest.raises(V.VerifyError):
        b.spend_fetch()


def test_pinned_adapter_connects_to_screened_ip(app):
    import http.server
    import socketserver
    import threading

    import badgeserver.verify as V

    seen = []

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(self.headers.get("Host"))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, *a):
            pass

    with socketserver.TCPServer(("127.0.0.1", 0), H) as srv:
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        with app.app_context():
            session = V._pinned_session({("example.invalid", port): "127.0.0.1"})
            # "example.invalid" never resolves -- only pinning can reach the server
            resp = session.get(f"http://example.invalid:{port}/x", timeout=5)
        srv.shutdown()

    assert resp.status_code == 200
    assert seen and seen[0].startswith("example.invalid")

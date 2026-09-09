# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Jeroen Baten <jeroen@libreplan.dev>
"""A small self-hosted Open Badges 2.0 issuer."""

from __future__ import annotations

import os

from flask import Flask, render_template
from flask_talisman import Talisman
from werkzeug.middleware.proxy_fix import ProxyFix

from .config import Config
from .extensions import babel, csrf, db, limiter, login_manager

__all__ = ["create_app"]

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_CSP = {
    "default-src": "'self'",
    "img-src": ["'self'", "data:", "blob:"],
    "style-src": "'self'",
    "script-src": "'self'",
    "base-uri": "'self'",
    "form-action": "'self'",
    "frame-ancestors": "'none'",
}


def _resolve_data_dir(override: str | None) -> str:
    data_dir = (
        override
        or os.environ.get("BADGESERVER_DATA_DIR")
        or os.path.join(_REPO_ROOT, "instance")
    )
    return os.path.abspath(data_dir)


def create_app(config_overrides: dict | None = None, *, data_dir: str | None = None) -> Flask:
    resolved = _resolve_data_dir(data_dir)
    os.makedirs(resolved, exist_ok=True)

    app = Flask(__name__, instance_path=resolved)

    config = Config(resolved)
    app.config.from_mapping(config.as_dict())
    if config_overrides:
        app.config.update(config_overrides)

    if not app.config.get("TESTING"):
        config.validate()

    os.makedirs(app.config["UPLOAD_DIR"], exist_ok=True)

    hops = int(app.config.get("PROXY_FIX_HOPS", 1))
    if hops > 0:
        app.wsgi_app = ProxyFix(
            app.wsgi_app, x_for=hops, x_proto=hops, x_host=hops, x_port=hops
        )

    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    from .i18n import remember_locale, select_locale

    babel.init_app(app, locale_selector=select_locale)
    app.before_request(remember_locale)

    Talisman(
        app,
        force_https=False,
        strict_transport_security=True,
        session_cookie_secure=app.config["SESSION_COOKIE_SECURE"],
        frame_options="DENY",
        referrer_policy="same-origin",
        content_security_policy=_CSP,
    )

    from .models import AdminUser, OidcUser

    @login_manager.user_loader
    def _load_user(user_id: str):
        oidc_user = OidcUser.from_session_id(user_id)
        if oidc_user is not None:
            return oidc_user
        try:
            return db.session.get(AdminUser, int(user_id))
        except (TypeError, ValueError):
            return None

    from .admin import bp as admin_bp
    from .claim_views import bp as claim_bp
    from .public import bp as public_bp
    from .verify_views import bp as verify_bp

    app.register_blueprint(public_bp)
    app.register_blueprint(admin_bp, url_prefix="/admin")
    app.register_blueprint(verify_bp)
    app.register_blueprint(claim_bp)

    from . import cli

    cli.register(app)

    @app.errorhandler(404)
    def _not_found(err):  # noqa: ANN001
        return render_template("404.html"), 404

    @app.errorhandler(500)
    def _server_error(err):  # noqa: ANN001
        return render_template("500.html"), 500

    @app.context_processor
    def _inject_globals():
        from flask import url_for
        from flask_babel import get_locale

        from .i18n import languages, switch_url
        from .version import app_version

        def badge_image_url(badge):
            """Badge image URL with a cache-busting version from the file mtime."""
            path = os.path.join(app.config["UPLOAD_DIR"], badge.image_path or "")
            try:
                version = int(os.path.getmtime(path))
            except OSError:
                version = 0
            return url_for("public.badge_image", slug=badge.slug, v=version)

        return {
            "site_title": app.config["SITE_TITLE"],
            "oidc_enabled": bool(app.config.get("OIDC_ISSUER") and app.config.get("OIDC_CLIENT_ID")),
            "badge_image_url": badge_image_url,
            "languages": languages(),
            "current_locale": str(get_locale() or app.config["BABEL_DEFAULT_LOCALE"]),
            "switch_url": switch_url,
            "app_version": app_version(),
        }

    return app

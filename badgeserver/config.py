# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Jeroen Baten <jeroen@libreplan.dev>
"""Configuration, loaded from the process environment.

Every value has a safe default except ``SECRET_KEY`` and ``EXTERNAL_URL``,
which are mandatory in a non-testing run (see :func:`Config.validate`).
"""

from __future__ import annotations

import os


def _str(name: str, default: str = "") -> str:
    """Environment value, with an unset OR empty variable falling back to *default*.

    An empty string matters: process managers (and ``badgectl``) often pass
    ``KEY=`` for values the operator left blank in the config file.
    """
    raw = os.environ.get(name)
    return raw if raw not in (None, "") else default


def _bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    return int(raw)


class Config:
    """Application configuration derived from environment variables."""

    def __init__(self, data_dir: str) -> None:
        self.DATA_DIR = data_dir
        self.UPLOAD_DIR = os.path.join(data_dir, "uploads")

        self.SECRET_KEY = _str("SECRET_KEY")
        # Public origin the badges are served from. Examples:
        #   http://badges.example.lan:4000   (direct access, no reverse proxy)
        #   https://badges.example.org       (behind a TLS-terminating proxy)
        self.EXTERNAL_URL = _str("EXTERNAL_URL").rstrip("/")
        _https = self.EXTERNAL_URL.startswith("https://")

        self.SQLALCHEMY_DATABASE_URI = _str(
            "DATABASE_URL", f"sqlite:///{os.path.join(data_dir, 'badges.sqlite')}"
        )
        self.SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True}

        # These default to the EXTERNAL_URL scheme, so a plain-HTTP deployment
        # works with no reverse proxy. Override either one explicitly if needed.
        self.PREFERRED_URL_SCHEME = _str(
            "PREFERRED_URL_SCHEME", "https" if _https else "http"
        )
        self.SESSION_COOKIE_SECURE = _bool("SESSION_COOKIE_SECURE", _https)
        self.SESSION_COOKIE_HTTPONLY = True
        self.SESSION_COOKIE_SAMESITE = "Lax"

        # Trusted reverse-proxy hops. 0 = no proxy (X-Forwarded-* is ignored, so
        # it cannot be spoofed). Set to 1 when running behind one nginx/apache.
        self.PROXY_FIX_HOPS = _int("PROXY_FIX_HOPS", 0)

        self.RATELIMIT_STORAGE_URI = _str("RATELIMIT_STORAGE_URI", "memory://")
        self.RATELIMIT_LOGIN = _str("RATELIMIT_LOGIN", "5 per minute; 30 per hour")
        self.RATELIMIT_VERIFY = _str("RATELIMIT_VERIFY", "12 per minute; 80 per hour")
        self.RATELIMIT_CLAIM = _str("RATELIMIT_CLAIM", "4 per minute; 15 per hour; 40 per day")

        # Self-service badges: visitors may claim badges flagged as such.
        self.SELF_SERVICE_ENABLED = _bool("SELF_SERVICE_ENABLED", True)
        self.CLAIM_EXPIRY_HOURS = _int("CLAIM_EXPIRY_HOURS", 24)

        self.MAX_CONTENT_LENGTH = _int("MAX_UPLOAD_BYTES", 3 * 1024 * 1024)
        self.BADGE_IMAGE_SIZE = _int("BADGE_IMAGE_SIZE", 512)
        self.CSV_AWARD_MAX_ROWS = _int("CSV_AWARD_MAX_ROWS", 200)

        # E-mail / SMTP
        self.MAIL_ENABLED = _bool("MAIL_ENABLED", False)
        self.SMTP_HOST = _str("SMTP_HOST")
        self.SMTP_PORT = _int("SMTP_PORT", 587)
        self.SMTP_SECURITY = _str("SMTP_SECURITY", "starttls").strip().lower()
        self.SMTP_USERNAME = _str("SMTP_USERNAME")
        self.SMTP_PASSWORD = _str("SMTP_PASSWORD")
        self.SMTP_TIMEOUT = _int("SMTP_TIMEOUT", 15)
        self.MAIL_FROM = _str("MAIL_FROM")
        self.MAIL_REPLY_TO = _str("MAIL_REPLY_TO")

        self.SITE_TITLE = _str("SITE_TITLE", "Open Badges")
        # Header logo: a filename in the static/ directory, or an absolute
        # http(s) URL. Defaults to the bundled project logo. Operators who
        # rebrand the server drop their logo in static/ and set this.
        self.SITE_LOGO = _str("SITE_LOGO", "project-logo.png")

        # Internationalisation
        self.LANGUAGES = [
            code.strip()
            for code in _str("LANGUAGES", "en,es,de,fr,nl").split(",")
            if code.strip()
        ]
        self.BABEL_DEFAULT_LOCALE = _str("BABEL_DEFAULT_LOCALE", "en")
        self.BABEL_DEFAULT_TIMEZONE = "UTC"

    def as_dict(self) -> dict:
        return {k: v for k, v in vars(self).items() if k.isupper()}

    def validate(self) -> None:
        missing = [k for k in ("SECRET_KEY", "EXTERNAL_URL") if not getattr(self, k)]
        if missing:
            raise RuntimeError(
                "Missing required configuration: "
                + ", ".join(missing)
                + ". Set them in the environment (see deploy/badges.env.example)."
            )
        if not self.EXTERNAL_URL.startswith(("http://", "https://")):
            raise RuntimeError("EXTERNAL_URL must be an absolute http(s) URL.")
        if self.SESSION_COOKIE_SECURE and self.EXTERNAL_URL.startswith("http://"):
            raise RuntimeError(
                "SESSION_COOKIE_SECURE is on but EXTERNAL_URL is http:// -- the "
                "session cookie would never come back and sign-in would always "
                "fail with a CSRF error. Remove the SESSION_COOKIE_SECURE line "
                "from badges.env (it defaults correctly from the URL scheme), or "
                "serve over https."
            )
        if self.SMTP_SECURITY not in {"none", "starttls", "ssl"}:
            raise RuntimeError("SMTP_SECURITY must be one of: none, starttls, ssl.")

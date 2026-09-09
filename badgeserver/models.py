# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Jeroen Baten <jeroen@libreplan.dev>
"""Database models.

The public JSON never exposes ``Assertion.recipient_email``; only the salted
SHA-256 :meth:`Assertion.identity_hash` is published.
"""

from __future__ import annotations

import hashlib
import re
import secrets
import uuid as uuidlib
from datetime import datetime, timedelta, timezone

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from .extensions import db


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_uuid() -> str:
    return str(uuidlib.uuid4())


def new_salt() -> str:
    return uuidlib.uuid4().hex


def new_token() -> str:
    return secrets.token_urlsafe(32)


_SLUG_RE = re.compile(r"[^a-z0-9]+")


def slugify(value: str) -> str:
    value = _SLUG_RE.sub("-", (value or "").strip().lower()).strip("-")
    return value or "item"


class AdminUser(db.Model, UserMixin):
    __tablename__ = "admin_user"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_on = db.Column(db.DateTime, nullable=False, default=_utcnow)

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password, method="pbkdf2:sha256")

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def get_id(self) -> str:  # noqa: D401 - flask-login contract
        return str(self.id)


class OidcPending(db.Model):
    """A pending OIDC authorization: ties the PKCE verifier + nonce to the
    random ``state`` that travels in the browser redirect, so the verifier
    never leaves the server (the Flask session cookie is signed but not
    encrypted, which would leak the PKCE secret). Consumed on callback."""

    __tablename__ = "oidc_pending"

    state = db.Column(db.String(64), primary_key=True)
    verifier = db.Column(db.String(128), nullable=False)
    nonce = db.Column(db.String(64), nullable=False)
    next_path = db.Column(db.String(255), nullable=False, default="")
    organization_id = db.Column(db.String(64), nullable=False, default="")
    created_on = db.Column(db.DateTime, nullable=False, default=_utcnow)


class OidcUser(UserMixin):
    """A transient, non-persisted admin identity established by a validated
    OIDC ID token. flask-login reloads it from the ``oidc:<subject>`` session
    id via the user-loader; nothing is stored in the database."""

    _PREFIX = "oidc:"

    def __init__(self, subject: str, name: str = "") -> None:
        self.subject = subject
        self.name = name

    def get_id(self) -> str:
        return f"{self._PREFIX}{self.subject}"

    @property
    def username(self) -> str:
        return self.name or self.subject

    @classmethod
    def from_session_id(cls, user_id: str) -> "OidcUser | None":
        if not user_id.startswith(cls._PREFIX):
            return None
        return cls(user_id[len(cls._PREFIX):])


class Issuer(db.Model):
    __tablename__ = "issuer"

    slug = db.Column(db.String(64), primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    url = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False, default="")
    image_path = db.Column(db.String(255))
    created_on = db.Column(db.DateTime, nullable=False, default=_utcnow)

    badges = db.relationship("BadgeClass", back_populates="issuer", lazy="dynamic")


class BadgeClass(db.Model):
    __tablename__ = "badge_class"

    #: shapes available when composing a badge from a logo + title
    ART_SHAPES = ("octagon", "circle", "hexagon", "shield", "crest")
    ART_BG_DEFAULT = "#2b6cb0"
    ART_ACCENT_DEFAULT = "#b0872b"
    ART_LOGO_SCALE_RANGE = (40, 200)
    ART_BORDER_WIDTH_RANGE = (0, 30)
    ART_LOGO_OFFSET_RANGE = (-20, 20)
    ART_TITLE_OFFSET_RANGE = (-20, 20)

    slug = db.Column(db.String(64), primary_key=True)
    issuer_slug = db.Column(db.String(64), db.ForeignKey("issuer.slug"), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False, default="")
    image_path = db.Column(db.String(255), nullable=False)
    criteria_narrative = db.Column(db.Text, nullable=False, default="")
    criteria_url = db.Column(db.String(255), nullable=False, default="")
    tags = db.Column(db.String(512), nullable=False, default="")
    created_on = db.Column(db.DateTime, nullable=False, default=_utcnow)
    archived = db.Column(db.Boolean, nullable=False, default=False)

    # Set when the badge image was composed from a logo (see badgeart.py).
    logo_path = db.Column(db.String(255))
    art_shape = db.Column(db.String(16), nullable=False, default="octagon")
    art_bg = db.Column(db.String(7), nullable=False, default="")
    art_accent = db.Column(db.String(7), nullable=False, default="")
    art_logo_scale = db.Column(db.Integer, nullable=False, default=100)
    art_border_width = db.Column(db.Integer, nullable=False, default=8)
    art_logo_offset = db.Column(db.Integer, nullable=False, default=0)
    art_title_offset = db.Column(db.Integer, nullable=False, default=0)

    # When true, any visitor may claim this badge for their own e-mail address.
    self_service = db.Column(db.Boolean, nullable=False, default=False)

    issuer = db.relationship("Issuer", back_populates="badges")
    assertions = db.relationship(
        "Assertion", back_populates="badge", lazy="dynamic", cascade="all, delete-orphan"
    )

    @property
    def composed(self) -> bool:
        return bool(self.logo_path)

    @property
    def tag_list(self) -> list[str]:
        return [t.strip() for t in self.tags.split(",") if t.strip()]

    @staticmethod
    def normalise_tags(raw: str) -> str:
        seen: list[str] = []
        for part in (raw or "").replace(";", ",").split(","):
            part = part.strip()
            if part and part.lower() not in {s.lower() for s in seen}:
                seen.append(part)
        return ", ".join(seen)


class Assertion(db.Model):
    __tablename__ = "assertion"
    __table_args__ = (
        # At most one *active* (non-revoked) assertion per badge + recipient.
        # Partial index -> a revoked assertion does not block re-awarding.
        # SQLite-scoped, like the ALTER-based migration in cli.py.
        db.Index(
            "uq_assertion_active_recipient",
            "badge_slug",
            "recipient_email",
            unique=True,
            sqlite_where=db.text("revoked = 0"),
        ),
    )

    uuid = db.Column(db.String(36), primary_key=True, default=new_uuid)
    badge_slug = db.Column(
        db.String(64), db.ForeignKey("badge_class.slug"), nullable=False, index=True
    )
    recipient_email = db.Column(db.String(255), nullable=False, index=True)
    salt = db.Column(db.String(64), nullable=False, default=new_salt)
    issued_on = db.Column(db.DateTime, nullable=False, default=_utcnow)
    evidence_url = db.Column(db.String(255), nullable=False, default="")
    narrative = db.Column(db.Text, nullable=False, default="")

    revoked = db.Column(db.Boolean, nullable=False, default=False)
    revocation_reason = db.Column(db.Text, nullable=False, default="")

    baked_png_path = db.Column(db.String(255))
    created_on = db.Column(db.DateTime, nullable=False, default=_utcnow)

    email_sent = db.Column(db.Boolean, nullable=False, default=False)
    email_sent_at = db.Column(db.DateTime)
    email_error = db.Column(db.Text, nullable=False, default="")

    badge = db.relationship("BadgeClass", back_populates="assertions")

    def identity_hash(self) -> str:
        digest = hashlib.sha256(
            (self.recipient_email + self.salt).encode("utf-8")
        ).hexdigest()
        return f"sha256${digest}"

    @property
    def masked_recipient(self) -> str:
        local, sep, domain = self.recipient_email.partition("@")
        if not sep:
            return "***"
        shown = local[0] if local else ""
        return f"{shown}{'*' * max(3, len(local) - 1)}@{domain}"

    def issued_on_utc(self) -> datetime:
        dt = self.issued_on
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)


class BadgeClaim(db.Model):
    """A pending self-service claim, awaiting e-mail confirmation."""

    __tablename__ = "badge_claim"

    token = db.Column(db.String(64), primary_key=True, default=new_token)
    badge_slug = db.Column(
        db.String(64), db.ForeignKey("badge_class.slug"), nullable=False, index=True
    )
    email = db.Column(db.String(255), nullable=False, index=True)
    created_on = db.Column(db.DateTime, nullable=False, default=_utcnow)
    expires_on = db.Column(db.DateTime, nullable=False)
    confirmed_on = db.Column(db.DateTime)
    assertion_uuid = db.Column(db.String(36))

    badge = db.relationship("BadgeClass")

    @staticmethod
    def make(badge_slug: str, email: str, hours: int) -> "BadgeClaim":
        return BadgeClaim(
            token=new_token(),
            badge_slug=badge_slug,
            email=email.strip(),
            expires_on=_utcnow() + timedelta(hours=hours),
        )

    @property
    def expired(self) -> bool:
        dt = self.expires_on
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return _utcnow() > dt

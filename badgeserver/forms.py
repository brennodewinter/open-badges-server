# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Jeroen Baten <jeroen@libreplan.dev>
"""Flask-WTF forms. CSRF protection is applied globally via ``CSRFProtect``.

Labels and messages use ``lazy_gettext`` because forms are built at import
time, before any request has established a locale.
"""

from __future__ import annotations

from flask_babel import lazy_gettext as _l
from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed, FileField, FileRequired
from wtforms import (
    BooleanField,
    DateField,
    IntegerRangeField,
    PasswordField,
    RadioField,
    SelectField,
    StringField,
    SubmitField,
    TextAreaField,
)
from wtforms.validators import (
    URL,
    DataRequired,
    Email,
    EqualTo,
    Length,
    NumberRange,
    Optional,
    Regexp,
)
from wtforms.widgets import RangeInput

from .models import BadgeClass

_IMAGE_EXT = ["png", "jpg", "jpeg", "webp", "gif"]
_LOGO_EXT = [*_IMAGE_EXT, "svg"]
_HEX_COLOUR = Regexp(
    r"^#(?:[0-9A-Fa-f]{3}|[0-9A-Fa-f]{6})$", message=_l("Use a hex colour like #2b6cb0.")
)
_IMAGES_ONLY = _l("Images only.")


class LoginForm(FlaskForm):
    username = StringField(_l("Username"), validators=[DataRequired(), Length(max=64)])
    password = PasswordField(_l("Password"), validators=[DataRequired()])
    submit = SubmitField(_l("Sign in"))


class ChangePasswordForm(FlaskForm):
    current_password = PasswordField(_l("Current password"), validators=[DataRequired()])
    new_password = PasswordField(
        _l("New password"), validators=[DataRequired(), Length(min=10, max=255)]
    )
    confirm = PasswordField(
        _l("Repeat new password"),
        validators=[DataRequired(), EqualTo("new_password", _l("Passwords do not match."))],
    )
    submit = SubmitField(_l("Change password"))


class IssuerForm(FlaskForm):
    slug = StringField(_l("Slug"), validators=[Optional(), Length(max=64)])
    name = StringField(_l("Name"), validators=[DataRequired(), Length(max=255)])
    # require_tld=False so a self-hosted deployment can list a LAN or
    # loopback address (e.g. http://localhost:1428) as the issuer website.
    url = StringField(
        _l("Website URL"),
        validators=[DataRequired(), URL(require_tld=False), Length(max=255)],
    )
    email = StringField(_l("Contact e-mail"), validators=[DataRequired(), Email(), Length(max=255)])
    description = TextAreaField(_l("Description"), validators=[Optional(), Length(max=4000)])
    image = FileField(_l("Logo (optional)"), validators=[FileAllowed(_IMAGE_EXT, _IMAGES_ONLY)])
    submit = SubmitField(_l("Save issuer"))


class BadgeClassForm(FlaskForm):
    slug = StringField(_l("Slug"), validators=[Optional(), Length(max=64)])
    name = StringField(_l("Name"), validators=[DataRequired(), Length(max=255)])
    description = TextAreaField(
        _l("Description"), validators=[DataRequired(), Length(max=4000)]
    )
    criteria_narrative = TextAreaField(
        _l("Criteria (what it is awarded for)"), validators=[Optional(), Length(max=4000)]
    )
    criteria_url = StringField(
        _l("Criteria URL (optional)"),
        validators=[Optional(), URL(require_tld=False), Length(max=255)],
    )
    tags = StringField(_l("Tags (comma separated)"), validators=[Optional(), Length(max=512)])
    self_service = BooleanField(_l("Let anyone claim this badge"))

    art_mode = RadioField(
        _l("Badge image"),
        choices=[
            ("upload", _l("Upload a finished image")),
            ("compose", _l("Compose from a logo")),
        ],
        default="upload",
    )
    image = FileField(
        _l("Finished badge image"), validators=[FileAllowed(_LOGO_EXT, _IMAGES_ONLY)]
    )
    logo = FileField(_l("Logo"), validators=[FileAllowed(_LOGO_EXT, _IMAGES_ONLY)])
    art_shape = SelectField(
        _l("Shape"),
        choices=[(s, s.title()) for s in BadgeClass.ART_SHAPES],
        default="octagon",
    )
    art_bg = StringField(
        _l("Background colour"), default=BadgeClass.ART_BG_DEFAULT,
        validators=[Optional(), _HEX_COLOUR],
    )
    art_accent = StringField(
        _l("Ring colour"), default=BadgeClass.ART_ACCENT_DEFAULT,
        validators=[Optional(), _HEX_COLOUR],
    )
    art_logo_scale = IntegerRangeField(
        _l("Logo size"), default=100, widget=RangeInput(step=5),
        validators=[Optional(), NumberRange(*BadgeClass.ART_LOGO_SCALE_RANGE)],
    )
    art_border_width = IntegerRangeField(
        _l("Border width"), default=8, widget=RangeInput(step=1),
        validators=[Optional(), NumberRange(*BadgeClass.ART_BORDER_WIDTH_RANGE)],
    )
    art_logo_offset = IntegerRangeField(
        _l("Logo position"), default=0, widget=RangeInput(step=1),
        validators=[Optional(), NumberRange(*BadgeClass.ART_LOGO_OFFSET_RANGE)],
    )
    art_title_offset = IntegerRangeField(
        _l("Title position"), default=0, widget=RangeInput(step=1),
        validators=[Optional(), NumberRange(*BadgeClass.ART_TITLE_OFFSET_RANGE)],
    )

    submit = SubmitField(_l("Save badge"))


class NewBadgeClassForm(BadgeClassForm):
    """Same fields; on creation the view requires an image or a logo per mode."""


class AwardForm(FlaskForm):
    recipient_email = StringField(
        _l("Recipient e-mail"), validators=[DataRequired(), Email(), Length(max=255)]
    )
    issued_on = DateField(_l("Issued on"), validators=[Optional()])
    evidence_url = StringField(
        _l("Evidence URL (optional)"),
        validators=[Optional(), URL(require_tld=False), Length(max=255)],
    )
    narrative = TextAreaField(_l("Note (optional)"), validators=[Optional(), Length(max=4000)])
    send_email = BooleanField(_l("Send an e-mail notification"), default=True)
    submit = SubmitField(_l("Award badge"))


class AwardCsvForm(FlaskForm):
    file = FileField(
        _l("CSV file"),
        validators=[FileRequired(_l("Choose a CSV file.")), FileAllowed(["csv", "txt"], _l("CSV only."))],
    )
    send_email = BooleanField(_l("Send an e-mail notification to each recipient"), default=True)
    submit = SubmitField(_l("Award to all rows"))


class RevokeForm(FlaskForm):
    reason = StringField(_l("Reason"), validators=[DataRequired(), Length(max=255)])
    submit = SubmitField(_l("Revoke"))


class ConfirmForm(FlaskForm):
    """A bare form carrying only the CSRF token, for one-click POST actions."""

    submit = SubmitField(_l("Confirm"))


class ClaimForm(FlaskForm):
    email = StringField(
        _l("Your e-mail address"), validators=[DataRequired(), Email(), Length(max=255)]
    )
    submit = SubmitField(_l("Claim this badge"))


class VerifyForm(FlaskForm):
    source = TextAreaField(
        _l("Badge URL, assertion JSON, or signed badge token"),
        validators=[DataRequired(), Length(max=20000)],
    )
    recipient = StringField(
        _l("Recipient e-mail (optional)"), validators=[Optional(), Email(), Length(max=255)]
    )
    submit = SubmitField(_l("Verify"))

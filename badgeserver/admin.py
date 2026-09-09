# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Jeroen Baten <jeroen@libreplan.dev>
"""Authenticated admin views."""

from __future__ import annotations

import csv as csvmod
import io
import os
import shutil
from datetime import datetime, time, timedelta, timezone
from urllib.parse import urlsplit

from flask import (
    Blueprint,
    Response,
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_babel import gettext as _
from flask_login import current_user, login_required, login_user, logout_user

from .extensions import db, limiter
from . import oidc
from .forms import (
    AwardCsvForm,
    AwardForm,
    BadgeClassForm,
    ChangePasswordForm,
    ConfirmForm,
    IssuerForm,
    LoginForm,
    NewBadgeClassForm,
    RevokeForm,
)
from . import images
from .badgeart import compose_badge
from .images import ImageError, save_square_png
from .issuing import AlreadyAwarded, award_badge, resend_email
from .mail import mail_configured
from .models import AdminUser, Assertion, BadgeClass, Issuer, OidcPending, OidcUser, slugify
from .openbadges import assertion_id as assertion_public_id

bp = Blueprint("admin", __name__)


@bp.before_request
def _require_login():
    if request.endpoint in {
        "admin.login",
        "admin.static",
        "admin.oidc_start",
        "admin.oidc_callback",
    }:
        return None
    if not current_user.is_authenticated:
        return current_app.login_manager.unauthorized()
    return None


@bp.after_request
def _no_store(response):
    """Admin pages carry recipient e-mails etc. -- never cache them."""
    response.headers.setdefault("Cache-Control", "no-store")
    return response


# --- helpers --------------------------------------------------------------


def _unique_slug(model, desired: str, *, current: str | None = None) -> str:
    base = slugify(desired)
    candidate = base
    n = 2
    while candidate != current and db.session.get(model, candidate) is not None:
        candidate = f"{base}-{n}"
        n += 1
    return candidate


def _sole_issuer() -> Issuer | None:
    return Issuer.query.order_by(Issuer.created_on).first()


def _upload_dir() -> str:
    return current_app.config["UPLOAD_DIR"]


def _image_size() -> int:
    return current_app.config["BADGE_IMAGE_SIZE"]


def _write_upload(data: bytes, filename: str) -> str:
    with open(os.path.join(_upload_dir(), filename), "wb") as fh:
        fh.write(data)
    return filename


def _store_image(file_storage, filename: str) -> str:
    raw = file_storage.read()
    if not raw:
        raise ImageError(_("The uploaded file is empty."))
    save_square_png(raw, os.path.join(_upload_dir(), filename), size=_image_size())
    return filename


def _as_utc_datetime(d) -> datetime | None:
    if not d:
        return None
    return datetime.combine(d, time(12, 0), tzinfo=timezone.utc)


def _safe_redirect_target(target: str) -> str | None:
    """A post-login ``next`` value, only if it is a local same-site path."""
    if not target:
        return None
    # Browsers treat backslashes in a URL as slashes; normalise before checking.
    probe = target.replace("\\", "/")
    parts = urlsplit(probe)
    if parts.scheme or parts.netloc:  # absolute or protocol-relative
        return None
    if not probe.startswith("/") or probe.startswith("//"):
        return None
    return target


# --- auth ----------------------------------------------------------------


@bp.route("/login", methods=["GET", "POST"])
@limiter.limit(lambda: current_app.config["RATELIMIT_LOGIN"], methods=["POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("admin.dashboard"))
    form = LoginForm()
    if form.validate_on_submit():
        user = AdminUser.query.filter_by(username=form.username.data.strip()).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            current_app.logger.info("Admin %s signed in", user.username)
            nxt = _safe_redirect_target(request.args.get("next", ""))
            if nxt:
                return redirect(nxt)
            return redirect(url_for("admin.dashboard"))
        flash(_("Incorrect username or password."), "error")
    return render_template("admin/login.html", form=form)


@bp.post("/logout")
@login_required
def logout():
    logout_user()
    flash(_("Signed out."), "ok")
    return redirect(url_for("public.index"))


# --- OIDC single sign-on (opt-in) ----------------------------------------


def _purge_expired_oidc() -> None:
    cutoff = datetime.now(timezone.utc) - _OIDC_TTL
    OidcPending.query.filter(OidcPending.created_on < cutoff).delete(
        synchronize_session=False
    )


# ponytail: a 10-minute ceiling on completing an OIDC redirect. Long enough for
# a user to authenticate at the IdP, short enough that abandoned flows don't
# accumulate. Upgrade path: a periodic cleanup job if SSO volume ever warrants.
_OIDC_TTL = timedelta(minutes=10)


@bp.get("/oidc")
def oidc_start():
    if not oidc.configured(current_app):
        abort(404)
    nxt = _safe_redirect_target(request.args.get("next", "")) or "/admin/"
    organization_id = (request.args.get("organization_id") or "").strip()
    state = oidc.new_token()
    nonce = oidc.new_token()
    verifier, challenge = oidc.pkce_pair()
    _purge_expired_oidc()
    db.session.add(
        OidcPending(
            state=state,
            verifier=verifier,
            nonce=nonce,
            next_path=nxt,
            organization_id=organization_id[:64],
        )
    )
    db.session.commit()
    redirect_uri = url_for("admin.oidc_callback", _external=True)
    try:
        doc = oidc.discover(current_app)
        target = oidc.authorization_url(
            current_app,
            doc,
            redirect_uri=redirect_uri,
            state=state,
            nonce=nonce,
            challenge=challenge,
        )
    except oidc.OidcError as exc:
        flash(str(exc), "error")
        return redirect(url_for("admin.login"))
    return redirect(target)


@bp.get("/oidc/callback")
def oidc_callback():
    # The IdP returns the user here with ?code=...&state=... (or ?error=...).
    state = request.args.get("state", "")
    pending = db.session.get(OidcPending, state) if state else None
    if pending is None:
        flash(_("The sign-in link is expired or invalid."), "error")
        return redirect(url_for("admin.login"))
    nxt = pending.next_path or "/admin/"
    # Consume the pending row before doing anything else so a replay is useless.
    db.session.delete(pending)
    db.session.commit()
    if request.args.get("error"):
        flash(_("The identity-provider refused the sign-in."), "error")
        return redirect(url_for("admin.login"))
    code = request.args.get("code")
    if not code:
        flash(_("The sign-in came back without a code."), "error")
        return redirect(url_for("admin.login"))
    redirect_uri = url_for("admin.oidc_callback", _external=True)
    try:
        doc = oidc.discover(current_app)
        tokens = oidc.exchange_code(
            current_app, doc, code=code, redirect_uri=redirect_uri, verifier=pending.verifier
        )
        claims = oidc.validate_id_token(
            current_app, doc, tokens["id_token"], expected_nonce=pending.nonce
        )
    except oidc.OidcError as exc:
        flash(str(exc), "error")
        return redirect(url_for("admin.login"))
    subject = str(claims.get("sub") or "")
    if not subject:
        flash(_("The identity-provider gave no subject."), "error")
        return redirect(url_for("admin.login"))
    name = str(claims.get("name") or claims.get("preferred_username") or "")
    login_user(OidcUser(subject, name))
    current_app.logger.info("OIDC admin %s signed in", subject)
    return redirect(nxt)


# --- dashboard ---------------------------------------------------------


@bp.get("/")
def dashboard():
    stats = {
        "badges": BadgeClass.query.count(),
        "active_badges": BadgeClass.query.filter_by(archived=False).count(),
        "assertions": Assertion.query.filter_by(revoked=False).count(),
        "revoked": Assertion.query.filter_by(revoked=True).count(),
    }
    recent = Assertion.query.order_by(Assertion.created_on.desc()).limit(10).all()
    return render_template(
        "admin/dashboard.html",
        stats=stats,
        recent=recent,
        issuer=_sole_issuer(),
        mail_ready=mail_configured(),
    )


# --- issuer ----------------------------------------------------------


@bp.route("/issuer", methods=["GET", "POST"])
def issuer():
    obj = _sole_issuer()
    form = IssuerForm(obj=obj)
    if form.validate_on_submit():
        try:
            if obj is None:
                slug = _unique_slug(Issuer, form.slug.data or form.name.data)
                obj = Issuer(slug=slug)
                db.session.add(obj)
            obj.name = form.name.data.strip()
            obj.url = form.url.data.strip()
            obj.email = form.email.data.strip()
            obj.description = (form.description.data or "").strip()
            if form.image.data:
                obj.image_path = _store_image(form.image.data, f"issuer-{obj.slug}.png")
            db.session.commit()
            flash(_("Issuer saved."), "ok")
            return redirect(url_for("admin.issuer"))
        except ImageError as exc:
            db.session.rollback()
            flash(str(exc), "error")
    return render_template("admin/issuer.html", form=form, issuer=obj)


# --- badge classes -------------------------------------------------


@bp.get("/badges")
def badges():
    items = BadgeClass.query.order_by(BadgeClass.archived, BadgeClass.name).all()
    return render_template("admin/badges.html", badges=items)


@bp.route("/badges/new", methods=["GET", "POST"])
def badge_new():
    if _sole_issuer() is None:
        flash(_("Create the issuer profile first."), "error")
        return redirect(url_for("admin.issuer"))

    ref = (request.values.get("copy") or "").strip()
    source = db.session.get(BadgeClass, ref) if ref else None
    if ref and source is None and request.method == "GET":
        flash(_("No badge “%(slug)s” to copy from.", slug=ref), "error")

    form = NewBadgeClassForm()
    if request.method == "GET" and source is not None:
        _prefill_from_badge(form, source, name=f"{source.name}-copy")

    if form.validate_on_submit():
        try:
            slug = _unique_slug(BadgeClass, form.slug.data or form.name.data)
            badge = BadgeClass(slug=slug, issuer_slug=_sole_issuer().slug)
            copied = source is not None and _copy_badge_art(source, badge)
            _apply_badge_form(badge, form, image_required=not copied)
            db.session.add(badge)
            db.session.commit()
            flash(_("Badge “%(name)s” created.", name=badge.name), "ok")
            return redirect(url_for("admin.badges"))
        except ImageError as exc:
            db.session.rollback()
            flash(str(exc), "error")
    return render_template("admin/badge_form.html", form=form, badge=None, source=source)


def _prefill_from_badge(form: BadgeClassForm, badge: BadgeClass, *, name: str) -> None:
    """Populate a blank badge form from an existing badge (the 'copy' action)."""
    form.name.data = name
    form.description.data = badge.description
    form.criteria_narrative.data = badge.criteria_narrative
    form.criteria_url.data = badge.criteria_url
    form.tags.data = badge.tags
    form.self_service.data = badge.self_service
    form.art_mode.data = "compose" if badge.composed else "upload"
    form.art_shape.data = badge.art_shape or "octagon"
    form.art_bg.data = badge.art_bg or BadgeClass.ART_BG_DEFAULT
    form.art_accent.data = badge.art_accent or BadgeClass.ART_ACCENT_DEFAULT
    form.art_logo_scale.data = badge.art_logo_scale
    form.art_border_width.data = badge.art_border_width
    form.art_logo_offset.data = badge.art_logo_offset
    form.art_title_offset.data = badge.art_title_offset


def _copy_badge_art(source: BadgeClass, badge: BadgeClass) -> bool:
    """Copy *source*'s stored logo/image files to *badge*'s filenames.

    Returns True if the new badge now has usable art, so the form does not
    have to require an upload.
    """
    up = _upload_dir()
    copied = False
    for rel, dest in (
        (source.logo_path, f"logo-{badge.slug}.png"),
        (source.image_path, f"badge-{badge.slug}.png"),
    ):
        if not rel:
            continue
        src = os.path.join(up, rel)
        if not os.path.exists(src):
            continue
        try:
            shutil.copyfile(src, os.path.join(up, dest))
        except OSError:
            continue
        if dest.startswith("logo-"):
            badge.logo_path = dest
        else:
            badge.image_path = dest
        copied = True
    return copied


@bp.route("/badges/<slug>/edit", methods=["GET", "POST"])
def badge_edit(slug: str):
    badge = db.session.get(BadgeClass, slug) or abort(404)
    form = BadgeClassForm(obj=badge)
    if request.method == "GET":
        form.tags.data = badge.tags
        form.art_mode.data = "compose" if badge.composed else "upload"
        form.art_bg.data = badge.art_bg or BadgeClass.ART_BG_DEFAULT
        form.art_accent.data = badge.art_accent or BadgeClass.ART_ACCENT_DEFAULT
        form.art_logo_scale.data = badge.art_logo_scale
        form.art_border_width.data = badge.art_border_width
        form.art_logo_offset.data = badge.art_logo_offset
        form.art_title_offset.data = badge.art_title_offset
    if form.validate_on_submit():
        try:
            _apply_badge_form(badge, form, image_required=False)
            db.session.commit()
            flash(_("Badge updated."), "ok")
            return redirect(url_for("admin.badges"))
        except ImageError as exc:
            db.session.rollback()
            flash(str(exc), "error")
    return render_template("admin/badge_form.html", form=form, badge=badge, source=None)


def _apply_badge_form(badge: BadgeClass, form: BadgeClassForm, *, image_required: bool) -> None:
    badge.name = form.name.data.strip()
    badge.description = form.description.data.strip()
    badge.criteria_narrative = (form.criteria_narrative.data or "").strip()
    badge.criteria_url = (form.criteria_url.data or "").strip()
    badge.tags = BadgeClass.normalise_tags(form.tags.data or "")
    badge.self_service = bool(form.self_service.data)

    if form.art_mode.data == "compose":
        _apply_compose(badge, form)
    else:
        if form.image.data:
            badge.image_path = _store_image(form.image.data, f"badge-{badge.slug}.png")
        elif image_required and not badge.image_path:
            raise ImageError(_("A badge image is required."))
        badge.logo_path = None
        badge.art_bg = badge.art_accent = ""


def _apply_compose(badge: BadgeClass, form: BadgeClassForm) -> None:
    size = _image_size()
    if form.logo.data:
        png = images.rasterize_to_png(form.logo.data.read(), size)
        badge.logo_path = _write_upload(png, f"logo-{badge.slug}.png")
    if not badge.logo_path:
        raise ImageError(_("Upload a logo to compose a badge."))

    badge.art_shape = (
        form.art_shape.data if form.art_shape.data in BadgeClass.ART_SHAPES else "octagon"
    )
    badge.art_bg = (form.art_bg.data or BadgeClass.ART_BG_DEFAULT).strip()
    badge.art_accent = (form.art_accent.data or BadgeClass.ART_ACCENT_DEFAULT).strip()
    badge.art_logo_scale = _clamp(
        form.art_logo_scale.data, BadgeClass.ART_LOGO_SCALE_RANGE, 100
    )
    badge.art_border_width = _clamp(
        form.art_border_width.data, BadgeClass.ART_BORDER_WIDTH_RANGE, 8
    )
    badge.art_logo_offset = _clamp(
        form.art_logo_offset.data, BadgeClass.ART_LOGO_OFFSET_RANGE, 0
    )
    badge.art_title_offset = _clamp(
        form.art_title_offset.data, BadgeClass.ART_TITLE_OFFSET_RANGE, 0
    )

    with open(os.path.join(_upload_dir(), badge.logo_path), "rb") as fh:
        logo_png = fh.read()
    compose_badge(
        logo_png,
        badge.name,
        shape=badge.art_shape,
        bg=badge.art_bg,
        accent=badge.art_accent,
        size=size,
        dest_path=os.path.join(_upload_dir(), f"badge-{badge.slug}.png"),
        logo_scale=badge.art_logo_scale / 100,
        border_width=badge.art_border_width,
        logo_offset=badge.art_logo_offset,
        title_offset=badge.art_title_offset,
    )
    badge.image_path = f"badge-{badge.slug}.png"


def _clamp(value, bounds: tuple[int, int], default: int) -> int:
    lo, hi = bounds
    try:
        return max(lo, min(hi, int(value)))
    except (TypeError, ValueError):
        return default


def _placeholder_logo() -> bytes:
    from io import BytesIO

    from PIL import Image, ImageDraw

    img = Image.new("RGBA", (240, 240), (0, 0, 0, 0))
    ImageDraw.Draw(img).rounded_rectangle(
        [24, 24, 216, 216], radius=28, fill=(255, 255, 255, 90)
    )
    buf = BytesIO()
    img.save(buf, "PNG")
    return buf.getvalue()


@bp.post("/badges/preview")
def badge_preview():
    """Render a composed badge for the live form preview. Saves nothing."""
    from io import BytesIO

    from .badgeart import render_badge

    data = request.form
    scale = _clamp(data.get("art_logo_scale"), BadgeClass.ART_LOGO_SCALE_RANGE, 100)
    border = _clamp(data.get("art_border_width"), BadgeClass.ART_BORDER_WIDTH_RANGE, 8)
    logo_off = _clamp(data.get("art_logo_offset"), BadgeClass.ART_LOGO_OFFSET_RANGE, 0)
    title_off = _clamp(data.get("art_title_offset"), BadgeClass.ART_TITLE_OFFSET_RANGE, 0)

    logo_png = None
    upload = request.files.get("logo")
    if upload and upload.filename:
        try:
            logo_png = images.rasterize_to_png(upload.read(), 320)
        except ImageError:
            logo_png = None
    if logo_png is None:
        # the badge being edited, or the one being copied from
        ref = (data.get("slug") or data.get("copy") or "").strip()
        badge = db.session.get(BadgeClass, ref) if ref else None
        if badge and badge.logo_path:
            path = os.path.join(_upload_dir(), badge.logo_path)
            if os.path.exists(path):
                with open(path, "rb") as fh:
                    logo_png = fh.read()
    if logo_png is None:
        logo_png = _placeholder_logo()

    try:
        image = render_badge(
            logo_png,
            data.get("name", ""),
            shape=data.get("art_shape", "octagon"),
            bg=data.get("art_bg") or BadgeClass.ART_BG_DEFAULT,
            accent=data.get("art_accent") or BadgeClass.ART_ACCENT_DEFAULT,
            size=320,
            logo_scale=scale / 100,
            border_width=border,
            logo_offset=logo_off,
            title_offset=title_off,
        )
    except Exception:  # noqa: BLE001 - preview must never 500
        return Response("preview unavailable", status=422, mimetype="text/plain")

    buf = BytesIO()
    image.save(buf, "PNG")
    resp = Response(buf.getvalue(), mimetype="image/png")
    resp.headers["Cache-Control"] = "no-store"
    return resp


@bp.post("/badges/<slug>/archive")
def badge_archive(slug: str):
    badge = db.session.get(BadgeClass, slug) or abort(404)
    badge.archived = not badge.archived
    db.session.commit()
    flash((_("Badge archived.") if badge.archived else _("Badge un-archived.")), "ok")
    return redirect(url_for("admin.badges"))


# --- awarding --------------------------------------------------------


@bp.route("/badges/<slug>/award", methods=["GET", "POST"])
def award(slug: str):
    badge = db.session.get(BadgeClass, slug) or abort(404)
    form = AwardForm()
    if form.validate_on_submit():
        try:
            result = award_badge(
                badge,
                form.recipient_email.data,
                issued_on=_as_utc_datetime(form.issued_on.data),
                evidence_url=form.evidence_url.data or "",
                narrative=form.narrative.data or "",
                send_email=form.send_email.data,
            )
        except AlreadyAwarded as exc:
            flash(
                _(
                    "That recipient already holds this badge (assertion %(id)s).",
                    id=exc.assertion.uuid,
                ),
                "error",
            )
            return redirect(url_for("admin.award", slug=slug))
        msg = _("Badge awarded to %(email)s.", email=result.assertion.recipient_email)
        category = "ok"
        if result.email_attempted and result.email_ok:
            msg += " " + _("Notification e-mail sent.")
        elif result.email_attempted:
            msg += " " + _(
                "Notification e-mail failed: %(error)s", error=result.email_error
            )
            category = "error"
        flash(msg, category)
        return redirect(url_for("admin.assertion_detail", uuid=result.assertion.uuid))
    return render_template(
        "admin/award.html", form=form, badge=badge, mail_ready=mail_configured()
    )


@bp.route("/badges/<slug>/award-csv", methods=["GET", "POST"])
def award_csv(slug: str):
    badge = db.session.get(BadgeClass, slug) or abort(404)
    form = AwardCsvForm()
    results: list[dict] = []
    if form.validate_on_submit():
        raw = form.file.data.read().decode("utf-8-sig", errors="replace")
        emails, skipped = _extract_emails(raw)
        cap = current_app.config["CSV_AWARD_MAX_ROWS"]
        if skipped:
            flash(
                _("Skipped %(n)d row(s) with an unreadable e-mail address.", n=skipped),
                "error",
            )
        if len(emails) > cap:
            flash(
                _(
                    "CSV has %(count)d addresses; the limit is %(cap)d.",
                    count=len(emails),
                    cap=cap,
                ),
                "error",
            )
        else:
            for email in emails:
                results.append(_award_one_csv_row(badge, email, form.send_email.data))
            ok = sum(1 for r in results if r["status"] == "awarded")
            flash(
                _(
                    "Processed %(rows)d rows: %(ok)d awarded.",
                    rows=len(results),
                    ok=ok,
                ),
                "ok",
            )
    return render_template(
        "admin/award_csv.html",
        form=form,
        badge=badge,
        results=results,
        mail_ready=mail_configured(),
    )


def _extract_emails(text: str) -> tuple[list[str], int]:
    """Return ``(valid_addresses, skipped_count)`` from a CSV / plain-text blob.

    The first cell of each row that contains ``@`` is treated as the candidate
    address and validated with ``email_validator``; anything that fails to
    parse (including a cell with an embedded newline) is counted as skipped.
    """
    from email_validator import EmailNotValidError, validate_email

    out: list[str] = []
    skipped = 0
    seen: set[str] = set()
    for row in csvmod.reader(io.StringIO(text)):
        for cell in row:
            cell = cell.strip()
            if "@" not in cell:
                continue
            try:
                result = validate_email(cell, check_deliverability=False)
                # .normalized on email-validator >= 2.0, .email on 1.x
                normalized = getattr(result, "normalized", None) or result.email
            except EmailNotValidError:
                skipped += 1
            else:
                if normalized.lower() not in seen:
                    seen.add(normalized.lower())
                    out.append(normalized)
            break
    return out, skipped


def _award_one_csv_row(badge: BadgeClass, email: str, send_email: bool) -> dict:
    try:
        result = award_badge(badge, email, send_email=send_email)
    except AlreadyAwarded:
        return {"email": email, "status": "skipped", "detail": _("already holds this badge")}
    except Exception as exc:  # noqa: BLE001
        db.session.rollback()
        return {"email": email, "status": "error", "detail": f"{type(exc).__name__}: {exc}"}
    detail = ""
    if result.email_attempted and not result.email_ok:
        detail = _("awarded, e-mail failed: %(error)s", error=result.email_error)
    elif result.email_attempted:
        detail = _("awarded, e-mail sent")
    else:
        detail = _("awarded")
    return {"email": email, "status": "awarded", "detail": detail, "uuid": result.assertion.uuid}


# --- assertions ------------------------------------------------------


@bp.get("/assertions")
def assertions():
    q = Assertion.query
    badge_slug = request.args.get("badge", "").strip()
    email = request.args.get("email", "").strip()
    status = request.args.get("status", "").strip()
    if badge_slug:
        q = q.filter_by(badge_slug=badge_slug)
    if email:
        q = q.filter(Assertion.recipient_email.ilike(f"%{email}%"))
    if status == "revoked":
        q = q.filter_by(revoked=True)
    elif status == "active":
        q = q.filter_by(revoked=False)
    items = q.order_by(Assertion.created_on.desc()).limit(500).all()
    return render_template(
        "admin/assertions.html",
        items=items,
        all_badges=BadgeClass.query.order_by(BadgeClass.name).all(),
        filters={"badge": badge_slug, "email": email, "status": status},
    )


@bp.get("/assertions/<uuid>")
def assertion_detail(uuid: str):
    assertion = db.session.get(Assertion, uuid) or abort(404)
    json_url = assertion_public_id(assertion.uuid)
    return render_template(
        "admin/assertion_detail.html",
        assertion=assertion,
        badge=assertion.badge,
        json_url=json_url,
        page_url=json_url.removesuffix(".json"),
        revoke_form=RevokeForm(),
        confirm_form=ConfirmForm(),
        mail_ready=mail_configured(),
    )


@bp.post("/assertions/<uuid>/revoke")
def assertion_revoke(uuid: str):
    assertion = db.session.get(Assertion, uuid) or abort(404)
    form = RevokeForm()
    if form.validate_on_submit():
        assertion.revoked = True
        assertion.revocation_reason = form.reason.data.strip()
        db.session.commit()
        flash(_("Assertion revoked."), "ok")
    else:
        flash(_("A reason is required to revoke."), "error")
    return redirect(url_for("admin.assertion_detail", uuid=uuid))


@bp.post("/assertions/<uuid>/unrevoke")
def assertion_unrevoke(uuid: str):
    assertion = db.session.get(Assertion, uuid) or abort(404)
    assertion.revoked = False
    assertion.revocation_reason = ""
    db.session.commit()
    flash(_("Assertion re-instated."), "ok")
    return redirect(url_for("admin.assertion_detail", uuid=uuid))


@bp.post("/assertions/<uuid>/resend-email")
def assertion_resend(uuid: str):
    assertion = db.session.get(Assertion, uuid) or abort(404)
    if not mail_configured():
        flash(_("SMTP is not configured."), "error")
    else:
        try:
            resend_email(assertion)
            flash(_("Notification e-mail re-sent."), "ok")
        except Exception as exc:  # noqa: BLE001
            assertion.email_error = f"{type(exc).__name__}: {exc}"
            db.session.commit()
            flash(_("Re-send failed: %(error)s", error=assertion.email_error), "error")
    return redirect(url_for("admin.assertion_detail", uuid=uuid))


# --- account --------------------------------------------------------


@bp.route("/change-password", methods=["GET", "POST"])
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if not current_user.check_password(form.current_password.data):
            flash(_("Current password is incorrect."), "error")
        else:
            current_user.set_password(form.new_password.data)
            db.session.commit()
            flash(_("Password changed."), "ok")
            return redirect(url_for("admin.dashboard"))
    return render_template("admin/change_password.html", form=form)

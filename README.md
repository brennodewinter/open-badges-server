<img src="badgeserver/static/project-logo.png" alt="LibrePlan Open Badges Server" width="400">

# badgeserver

A small self-hosted **Open Badges 2.0** issuer.

## Always start with "why?"

I needed to "scratch an itch". I wanted a simple open badges server and
all I could find was, well, not what I hoped I would find.
So I vibe coded this in a couple of days and deployed it on https://badges.libreplan.dev.
I'm happy now, and hopefully you too.

If you like it, consider a donation to the LibrePlan project at https://libreplan.dev.

## What does it do?

- Issues badges with **hosted verification** — the assertion JSON URL is the proof.
- One **local admin** account (username + password). No external identity provider.
- Single **SQLite** database plus an uploads directory.
- Server-rendered Flask app under **gunicorn on port 4000**. A reverse proxy is
  optional: serve plain HTTP directly on the LAN, or put nginx/apache in front
  for TLS.
- Emails recipients (optional) when a badge is awarded.

Licence: **AGPL-3.0-or-later** (see `LICENSE`). © Jeroen Baten.

## Important docs

- Install: [`Docs/INSTALL.md`](Docs/INSTALL.md)
- Docker: [`Docs/docker.md`](Docs/docker.md)
- Running it (backup, upgrade, troubleshooting): [`Docs/operations.md`](Docs/operations.md)
- Design notes: [`Docs/badges-server-v2-build-plan-v1.md`](Docs/badges-server-v2-build-plan-v1.md)

## What it serves

| URL | Content |
| --- | --- |
| `/` | public browse page (issuer + active badges) |
| `/b/<slug>` , `/b/<slug>.json` | badge class (human page / `BadgeClass` JSON) |
| `/a/<uuid>` , `/a/<uuid>.json` | assertion (human page / `Assertion` JSON — the hosted proof) |
| `/a/<uuid>/badge.png` | the badge image with the assertion URL baked in |
| `/a/<uuid>/qr.png` | QR code linking to the assertion page |
| `/issuer/<slug>.json` | `Issuer` / `Profile` JSON |
| `/admin` | login-protected administration |
| `/healthz` | health check for the proxy |

## Install

Debian 13, all dependencies from `apt`. Full walk-through in
[`Docs/INSTALL.md`](Docs/INSTALL.md); scripted in
[`contrib/setup.sh`](contrib/setup.sh). In short:

```sh
# the service user must be able to read the checkout: keep it out of a private
# /home and somewhere world-traversable such as /opt
sudo rsync -a --delete ./ /opt/badgeserver/ && cd /opt/badgeserver

sudo apt install python3-flask python3-flask-sqlalchemy python3-flask-login \
  python3-flaskext.wtf python3-wtforms python3-email-validator \
  python3-flask-talisman python3-flask-limiter python3-pil python3-qrcode \
  python3-gunicorn
sudo adduser --system --group --home /var/lib/badgeserver --no-create-home badges

sudo install -o root -g badges -m 0640 deploy/badges.env.example /var/lib/badgeserver/badges.env
sudoedit /var/lib/badgeserver/badges.env      # SECRET_KEY, EXTERNAL_URL, BIND, SMTP_*

sudo ./deploy/badgectl init-db
sudo ./deploy/badgectl create-admin admin
# --url is the issuing organisation's homepage, not this server; see INSTALL.md.
sudo ./deploy/badgectl set-issuer --slug main --name "LibrePlan Badges" \
  --url https://libreplan.dev --email jeroen@libreplan.dev

# The `sed` step pins the checkout path into the service unit — redo it if you
# move the checkout.
sudo sed "s#__REPO__#$PWD#" deploy/badgeserver.service \
  | sudo tee /etc/systemd/system/badgeserver.service > /dev/null

sudo systemctl daemon-reload && sudo systemctl enable --now badgeserver
curl -s localhost:4000/healthz
```

## Docker

```sh
cp deploy/badges.env.example badges.env      # then edit: SECRET_KEY, EXTERNAL_URL, SMTP_*
docker compose up -d --build
docker compose exec badgeserver flask create-admin admin
docker compose exec badgeserver flask set-issuer --name "LibrePlan Badges" \
  --url https://libreplan.dev --email jeroen@libreplan.dev
curl -s localhost:4000/healthz
```

The image installs the same apt packages as a bare-metal install; the SQLite
database and uploads live in the `data` volume. Details, reverse-proxy and
backup notes in [`Docs/docker.md`](Docs/docker.md).

## Local development

```sh
export SECRET_KEY=dev-only EXTERNAL_URL=http://localhost:4000 MAIL_ENABLED=false
python3 -m flask --app wsgi.py init-db
python3 -m flask --app wsgi.py create-admin admin
python3 -m flask --app wsgi.py run --port 4000
```

`SESSION_COOKIE_SECURE` defaults to false for an `http://` `EXTERNAL_URL`, so
login works over plain HTTP. Data goes to `./instance/` in this mode.

## Single sign-on (optional)

The admin area uses a local username/password login by default. To let
administrators sign in via an external identity provider instead, set
`OIDC_ISSUER` and `OIDC_CLIENT_ID` in `badges.env` (see
`deploy/badges.env.example`). The server then offers an
Authorization Code + PKCE (S256) flow at `/admin/oidc`; the local login
remains available as a fallback.

When badge administration is delegated to a parent application (e.g.
OciServe), set `OIDC_AUTHORIZATION_URL` to the endpoint that authorises the
user for a given organization — the access token is sent as a Bearer header
and a 200/204 response grants access.

## Tests

```sh
sudo apt install python3-pytest
python3 -m pytest -q
```

# Onboarding to Knuckles

Welcome. This guide gets you from "I've never seen this repo" to "I'm
running Knuckles locally and have a consuming app talking to it" in
about 30 minutes. It also covers the deploy story and the day-2
operations you'll inherit.

If you only need to integrate an app *against* an already-running
Knuckles instance, jump straight to **[Part C — Integrate a consuming
app](#part-c--integrate-a-consuming-app)**.

---

## Table of contents

- [What Knuckles is (in one paragraph)](#what-knuckles-is-in-one-paragraph)
- [Mental model in five bullets](#mental-model-in-five-bullets)
- [Repo layout cheat-sheet](#repo-layout-cheat-sheet)
- [Part A — Run Knuckles locally](#part-a--run-knuckles-locally)
- [Part B — Hello-world the four sign-in flows](#part-b--hello-world-the-four-sign-in-flows)
- [Part C — Integrate a consuming app](#part-c--integrate-a-consuming-app)
- [Part D — Deploy to production](#part-d--deploy-to-production)
- [Part E — Operating Knuckles](#part-e--operating-knuckles)
- [API reference (full surface)](#api-reference-full-surface)
- [Troubleshooting catalogue](#troubleshooting-catalogue)
- [Where to read the source](#where-to-read-the-source)

---

## What Knuckles is (in one paragraph)

Knuckles is a small, single-purpose identity service. It owns user
accounts and four sign-in ceremonies (magic-link, Google, Apple,
WebAuthn passkey), and after a successful ceremony it issues an
RS256-signed JWT access token plus a rotating opaque refresh token.
Consuming apps register as `app_clients`, hold a `client_id` +
`client_secret`, and validate Knuckles' tokens locally against the
public JWKS endpoint — they never call Knuckles to validate a token,
only to mint or rotate one. Knuckles never knows about anything beyond
identity (no music services, no product data, no analytics — see
`CLAUDE.md` and `DECISIONS.md` #001 for the load-bearing scope rule).

## Mental model in five bullets

1. **Knuckles signs, apps verify.** Knuckles holds a private RSA key.
   Every consuming app fetches `/.well-known/jwks.json` once and
   verifies tokens locally with the public key. (`DECISIONS.md` #002)
2. **Every app is an `app_client` row.** A `client_id` + a hashed
   `client_secret` + a list of allowed origins. The `client_id`
   becomes the JWT `aud`. (`DECISIONS.md` #003)
3. **Refresh tokens rotate one-shot.** Every `/v1/token/refresh` call
   invalidates the old token and issues a new one. A second
   presentation of an already-used token revokes every refresh token
   for that user. (`DECISIONS.md` #004 + #008)
4. **Ceremony state lives in signed JWTs, not Redis.** OAuth `state`
   and WebAuthn challenges are HS256 JWTs minted with
   `KNUCKLES_STATE_SECRET`. Knuckles is stateless across the browser
   round trip. (`DECISIONS.md` #005)
5. **Tokens at rest are hashes.** Magic-link tokens, refresh tokens,
   and client secrets are stored only as SHA-256 digests; the
   plaintext exists for one moment in flight. (`DECISIONS.md` #006)

## Repo layout cheat-sheet

```
knuckles/
├── app.py                # Flask app factory; CORS + error handlers + JWKS route
├── wsgi.py               # gunicorn entry point
├── core/                 # cross-cutting infra (config, db, jwt, logging, decorators)
├── data/
│   ├── models/auth.py    # every ORM table Knuckles owns
│   └── repositories/auth.py  # every SQL query Knuckles runs
├── services/             # one module per ceremony + tokens.py + email.py
├── api/v1/               # thin route handlers — validate, call service, jsonify
└── migrations/           # Alembic
tests/                    # mirrors knuckles/ exactly
scripts/                  # start.sh (entrypoint) and register_app_client.py (admin CLI)
```

The import hierarchy (enforced by convention, see `CLAUDE.md` rule 8):

```
api/  →  services/  →  data/  →  core/
```

Routes never touch the DB directly; services never touch HTTP.

---

## Part A — Run Knuckles locally

### Prerequisites

- Python 3.12+
- A local PostgreSQL instance (Docker is fine; SQLite is only used
  for tests)
- `openssl` for generating an RS256 keypair

### One-time setup

```bash
# 1. Clone and create a venv
git clone <repo> knuckles && cd knuckles
python3.12 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# 2. Create a Postgres database
createdb knuckles
# (or via psql)
#   CREATE USER knuckles WITH PASSWORD 'knuckles';
#   CREATE DATABASE knuckles OWNER knuckles;

# 3. Generate an RS256 signing key (PKCS#8 PEM, base64-encoded)
openssl genpkey -algorithm RSA -out /tmp/knuckles_private.pem \
    -pkeyopt rsa_keygen_bits:2048
KNUCKLES_JWT_PRIVATE_KEY=$(base64 < /tmp/knuckles_private.pem | tr -d '\n')

# 4. Generate a state secret
KNUCKLES_STATE_SECRET=$(python -c "import secrets; print(secrets.token_urlsafe(48))")

# 5. Copy the env template and fill in the two secrets above
cp .env.example .env
# Paste KNUCKLES_JWT_PRIVATE_KEY and KNUCKLES_STATE_SECRET into .env
```

### Boot the service

```bash
# Run pending migrations (also done automatically in production)
python -m alembic -c knuckles/alembic.ini upgrade head

# Start the dev server on :5001
flask --app knuckles.app run --port 5001 --debug

# In another terminal, sanity-check
curl http://localhost:5001/health
# => {"status":"ok"}

curl http://localhost:5001/.well-known/jwks.json
# => {"keys":[{"kty":"RSA",...,"kid":"knuckles-2026-04",...}]}
```

### Register your first consuming app-client

The service comes with no app_clients. Add one with the admin script:

```bash
python scripts/register_app_client.py \
    --client-id local-dev \
    --app-name "Local Dev App" \
    --allowed-origin http://localhost:3000

# Output:
#   Registered app_client.
#     client_id:     local-dev
#     client_secret: <plaintext — copy this once, it cannot be recovered>
```

Save both values somewhere safe — the secret is hashed at rest and
only ever printed at creation time.

### Run the test suite

```bash
pytest --cov=knuckles --cov-fail-under=80
```

Tests use an in-memory SQLite database (no Postgres needed) and a
freshly-minted RSA key per session, so the suite is hermetic.

---

## Part B — Hello-world the four sign-in flows

All examples below assume:

- Knuckles is running on `http://localhost:5001`
- The `local-dev` app-client from Part A is registered
- You have `client_id=local-dev` and `client_secret=<your-secret>` exported

```bash
export CID=local-dev
export CSECRET=<your-secret>
```

### B.1 — Magic-link

Request a link (returns 202 regardless of whether the email exists, to
avoid leaking account existence):

```bash
curl -X POST http://localhost:5001/v1/auth/magic-link/start \
    -H "Content-Type: application/json" \
    -H "X-Client-Id: $CID" \
    -H "X-Client-Secret: $CSECRET" \
    -d '{"email":"you@example.com",
         "redirect_url":"http://localhost:3000/auth/magic-link"}'
```

If `RESEND_API_KEY` is unset (the local default), the
`ConsoleEmailSender` prints the magic-link URL to the Knuckles process
log. Copy the `token=...` value from the URL and verify it:

```bash
curl -X POST http://localhost:5001/v1/auth/magic-link/verify \
    -H "Content-Type: application/json" \
    -H "X-Client-Id: $CID" \
    -H "X-Client-Secret: $CSECRET" \
    -d '{"token":"<token-from-link>"}'
```

You get back a `TokenPair`:

```json
{
  "data": {
    "access_token": "<RS256 JWT>",
    "access_token_expires_at": "2026-04-26T13:00:00+00:00",
    "refresh_token": "<opaque>",
    "refresh_token_expires_at": "2026-05-26T12:00:00+00:00",
    "token_type": "Bearer"
  }
}
```

### B.2 — Google OAuth

Pre-register `http://localhost:3000/auth/google/callback` in your
Google Cloud Console OAuth client, then set
`GOOGLE_OAUTH_CLIENT_ID` / `GOOGLE_OAUTH_CLIENT_SECRET` in `.env` and
restart Knuckles.

```bash
# Step 1 — get the Google consent URL + state JWT
curl -X POST http://localhost:5001/v1/auth/google/start \
    -H "Content-Type: application/json" \
    -H "X-Client-Id: $CID" -H "X-Client-Secret: $CSECRET" \
    -d '{"redirect_url":"http://localhost:3000/auth/google/callback"}'

# Step 2 — your frontend redirects the user to authorize_url, Google
# redirects back to redirect_url with ?code=...&state=...
# Your frontend posts that pair to /v1/auth/google/complete:
curl -X POST http://localhost:5001/v1/auth/google/complete \
    -H "Content-Type: application/json" \
    -H "X-Client-Id: $CID" -H "X-Client-Secret: $CSECRET" \
    -d '{"code":"<google-code>","state":"<state-from-step-1>"}'
```

### B.3 — Apple Sign-In

Same shape as Google but with two Apple-specific quirks:

- The state JWT is bound to the calling `app_client_id` and the
  `redirect_uri`, so you can't pivot a leaked state.
- Apple POSTs the `user` payload (with the user's name) **only on the
  first sign-in for a given Apple ID**. Pass it through verbatim if
  present.

```bash
# Step 1
curl -X POST http://localhost:5001/v1/auth/apple/start \
    -H "Content-Type: application/json" \
    -H "X-Client-Id: $CID" -H "X-Client-Secret: $CSECRET" \
    -d '{"redirect_url":"http://localhost:3000/auth/apple/callback"}'

# Step 2 — Apple POSTs back to your redirect_url with code, state,
# and (first time) a user JSON object. Forward all three:
curl -X POST http://localhost:5001/v1/auth/apple/complete \
    -H "Content-Type: application/json" \
    -H "X-Client-Id: $CID" -H "X-Client-Secret: $CSECRET" \
    -d '{"code":"<apple-code>","state":"<state>",
         "user":{"name":{"firstName":"Ada","lastName":"Lovelace"}}}'
```

### B.4 — WebAuthn passkey

Two ceremonies, two halves each. Registration assumes the user is
already signed in (bearer token). Sign-in is anonymous — the passkey
*is* the proof of identity.

**Registration** (signed-in user enrolls a new passkey):

```bash
# Browser calls /register/begin with a bearer access token
curl -X POST http://localhost:5001/v1/auth/passkey/register/begin \
    -H "Authorization: Bearer <access-token>"

# Returns: { data: { options: <PublicKeyCredentialCreationOptions>, state: <jwt> } }
# Frontend hands `options` to navigator.credentials.create(),
# then POSTs the resulting credential + state back:

curl -X POST http://localhost:5001/v1/auth/passkey/register/complete \
    -H "Authorization: Bearer <access-token>" \
    -H "Content-Type: application/json" \
    -d '{"credential":{...},"state":"...","name":"My MacBook Air"}'
```

**Sign-in** (no user yet — discoverable credential flow):

```bash
curl -X POST http://localhost:5001/v1/auth/passkey/sign-in/begin \
    -H "X-Client-Id: $CID" -H "X-Client-Secret: $CSECRET"

# Frontend hands `options` to navigator.credentials.get(),
# then POSTs the assertion back:

curl -X POST http://localhost:5001/v1/auth/passkey/sign-in/complete \
    -H "X-Client-Id: $CID" -H "X-Client-Secret: $CSECRET" \
    -H "Content-Type: application/json" \
    -d '{"credential":{...},"state":"..."}'
```

For local development set:

```
WEBAUTHN_RP_ID=localhost
WEBAUTHN_RP_NAME=Local Dev
WEBAUTHN_ORIGIN=http://localhost:3000
```

---

## Part C — Integrate a consuming app

### Step 1 — Get credentials

The Knuckles operator runs `scripts/register_app_client.py` for your
app and hands you `client_id` + `client_secret` out of band. The
secret never leaves your backend — never put it in a frontend bundle.

### Step 2 — Validate Knuckles tokens locally (no extra calls)

The whole point of the JWKS pattern is that your app verifies access
tokens with the cached public key. Boot-time pseudocode:

```python
import jwt, requests
KNUCKLES = "https://auth.example.com"
JWKS = jwt.PyJWKClient(f"{KNUCKLES}/.well-known/jwks.json")

def verify(token: str) -> dict:
    signing_key = JWKS.get_signing_key_from_jwt(token).key
    return jwt.decode(
        token,
        signing_key,
        algorithms=["RS256"],
        issuer=KNUCKLES,
        audience="my-app-client-id",   # <- your own client_id
    )
```

`PyJWKClient` caches keys; the first request fetches `/.well-known/jwks.json`,
subsequent requests use the in-memory cache. Persist the JWKS to disk
if you want graceful degradation when Knuckles is briefly unreachable.

### Step 3 — Drive a sign-in ceremony from your frontend

Your frontend chooses a method, calls `/v1/auth/<method>/start`
(server-to-server with your client headers, **never directly from the
browser** — the secret would leak), forwards the user through the
provider, then calls `/v1/auth/<method>/complete`. The response body
is identical across every method:

```json
{
  "data": {
    "access_token": "...",
    "access_token_expires_at": "...",
    "refresh_token": "...",
    "refresh_token_expires_at": "...",
    "token_type": "Bearer"
  }
}
```

Store the access token in an HTTP-only same-site cookie (or the
equivalent for native clients). Store the refresh token *server-side*,
keyed by your own session — refresh always goes through your backend
so the secret stays out of the browser.

### Step 4 — Refresh transparently

```http
POST /v1/token/refresh
X-Client-Id: my-app-client-id
X-Client-Secret: <secret>
Content-Type: application/json

{ "refresh_token": "<the one you stored>" }
```

The response contains a *new* refresh token. Always store the new one
— the old one is now consumed and presenting it again triggers
revocation of every refresh token for that user.

### Step 5 — Logout

```http
POST /v1/logout
X-Client-Id: my-app-client-id
X-Client-Secret: <secret>
Content-Type: application/json

{ "refresh_token": "<current>" }
```

Idempotent — unknown or already-used tokens succeed silently.

### Step 6 — Read the user profile

```http
GET /v1/me
Authorization: Bearer <access token>
X-Client-Id: my-app-client-id
X-Client-Secret: <secret>
```

Both pieces of auth are required: the bearer says *which user*, the
client headers say *which app is asking*.

---

## Part D — Deploy to production

### Container image

The repo ships a single-stage `Dockerfile` that runs as a non-root
user on `python:3.12-slim`, installs Knuckles, and uses
`scripts/start.sh` as `CMD`. The script runs `alembic upgrade head`
and then `exec`s gunicorn — migrations and boot are coupled
intentionally (see `DECISIONS.md` #011).

### Railway (the production target Knuckles is shipped on)

`railway.toml` declares `Dockerfile` as the builder, sets a
`/health` healthcheck with a 30-second timeout, and configures
`ON_FAILURE` restart with up to 5 retries. Set the env vars below in
the Railway service's variables tab. There's nothing else to do — the
container CMD does the rest.

### Required environment variables

| Variable | Description |
|---|---|
| `DATABASE_URL` | Postgres connection string |
| `KNUCKLES_BASE_URL` | Public origin (e.g. `https://auth.example.com`) — published as JWT `iss` |
| `KNUCKLES_JWT_PRIVATE_KEY` | Base64-encoded PKCS#8 PEM of the RS256 private key |
| `KNUCKLES_JWT_KEY_ID` | Stable `kid` published on the JWKS |
| `KNUCKLES_STATE_SECRET` | HS256 secret for ceremony-state JWTs |

### Identity-path optional env vars

Empty values disable that ceremony silently — set the relevant ones
for the methods you want enabled.

| Path | Vars |
|---|---|
| Magic-link | `RESEND_API_KEY`, `RESEND_FROM_EMAIL` |
| Google | `GOOGLE_OAUTH_CLIENT_ID`, `GOOGLE_OAUTH_CLIENT_SECRET` |
| Apple | `APPLE_OAUTH_CLIENT_ID`, `APPLE_OAUTH_TEAM_ID`, `APPLE_OAUTH_KEY_ID`, `APPLE_OAUTH_PRIVATE_KEY` |
| Passkey | `WEBAUTHN_RP_ID`, `WEBAUTHN_RP_NAME`, `WEBAUTHN_ORIGIN` |

Tunable lifetimes (sane defaults baked in):

- `KNUCKLES_ACCESS_TOKEN_TTL_SECONDS` (default 3600 = 1h)
- `KNUCKLES_REFRESH_TOKEN_TTL_SECONDS` (default 2592000 = 30d)
- `MAGIC_LINK_TTL_SECONDS` (default 900 = 15m)

Behavioral toggles:

- `KNUCKLES_STRICT_CORS` (default `false`) — when `true`, only echo
  `Access-Control-Allow-Origin` for origins registered in some
  app-client. See Decision #013.

### Gunicorn knobs (set as env)

- `PORT` (default 5001)
- `WEB_CONCURRENCY` (worker count, default 2)
- `GUNICORN_TIMEOUT` (default 30)

### First production deploy checklist

- [ ] Provision Postgres and set `DATABASE_URL`
- [ ] Generate a fresh RS256 keypair; load the base64 PEM into
      `KNUCKLES_JWT_PRIVATE_KEY` and pick a `kid` like
      `knuckles-2026-04` for `KNUCKLES_JWT_KEY_ID`
- [ ] Generate `KNUCKLES_STATE_SECRET` with
      `python -c "import secrets; print(secrets.token_urlsafe(48))"`
- [ ] Configure each identity path you intend to enable (skip the
      others — empty values are a feature)
- [ ] Deploy. The container runs migrations on boot.
- [ ] Verify `GET /health` returns `200` and `GET /.well-known/jwks.json`
      returns the public key under your chosen `kid`.
- [ ] `railway run python scripts/register_app_client.py …` to create
      production `app_clients` rows; share credentials with each app
      operator out-of-band.

---

## Part E — Operating Knuckles

### Key rotation

Documented in `DECISIONS.md` #002 — the lifecycle is:

1. Generate a new RS256 keypair, give it a new `kid`
   (e.g. `knuckles-2026-10`).
2. Extend `get_jwks` (in `knuckles/core/jwt.py`) to publish *both*
   public keys.
3. Switch `KNUCKLES_JWT_PRIVATE_KEY` and `KNUCKLES_JWT_KEY_ID` to the
   new key. From this point new tokens are signed with the new key.
4. Wait `KNUCKLES_ACCESS_TOKEN_TTL_SECONDS` (1h by default) so every
   token signed with the old key has expired.
5. Drop the old key from `get_jwks`.

Refresh tokens are unaffected — they're opaque random strings, not
JWTs.

### Rotating an app-client secret

```sql
UPDATE app_clients
SET client_secret_hash = encode(digest('<new-secret>', 'sha256'), 'hex')
WHERE client_id = '<id>';
```

Notify the app operator out-of-band, redeploy that app's environment.
No user sessions are invalidated; the new secret simply replaces the
old one for future server-to-server calls.

### Refresh-token reuse incident

If a refresh token is presented twice after consumption, Knuckles
silently revokes every refresh token for the affected user and
returns `REFRESH_TOKEN_REUSED`. The user must re-authenticate
everywhere. To investigate:

```sql
-- All refresh tokens for a user, newest first
SELECT id, app_client_id, used_at, expires_at, created_at
FROM refresh_tokens
WHERE user_id = '<uuid>'
ORDER BY created_at DESC;
```

### Cleaning up expired magic-link rows

`scripts/cleanup_magic_links.py` deletes magic-link rows whose
`expires_at` is older than the cutoff (default 24 hours). Wire it to
a Railway scheduled task or any cron:

```bash
# Nightly at 3am UTC
python scripts/cleanup_magic_links.py --older-than-hours 24
```

Idempotent — running it twice in a row deletes nothing the second time.

### Adding a new consuming app

Same script as local dev:

```bash
railway run python scripts/register_app_client.py \
    --client-id <id> \
    --app-name "<Name>" \
    --allowed-origin https://app.example.com \
    --allowed-origin https://staging.example.com
```

Hand the `client_id` + plaintext secret to the app operator over a
secure channel.

---

## API reference (full surface)

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/health` | none | Healthcheck for load balancer |
| GET | `/.well-known/jwks.json` | none | Public keys for token verification |
| GET | `/.well-known/openid-configuration` | none | OIDC discovery (issuer + jwks_uri) |
| GET | `/v1/auth/jwks` | none | Alias of the JWKS path |
| POST | `/v1/auth/magic-link/start` | client | Send a one-time email link (per-email rate-limited) |
| POST | `/v1/auth/magic-link/verify` | client | Redeem a magic-link token |
| POST | `/v1/auth/google/start` | client | Get Google consent URL + state |
| POST | `/v1/auth/google/complete` | client | Finish Google ceremony |
| POST | `/v1/auth/apple/start` | client | Get Apple consent URL + state |
| POST | `/v1/auth/apple/complete` | client | Finish Apple ceremony |
| POST | `/v1/auth/passkey/register/begin` | bearer | Start passkey enrollment |
| POST | `/v1/auth/passkey/register/complete` | bearer | Finish passkey enrollment |
| GET | `/v1/auth/passkey` | bearer | List the user's registered passkeys |
| DELETE | `/v1/auth/passkey/<credential_id>` | bearer | Delete one of the user's passkeys |
| POST | `/v1/auth/passkey/sign-in/begin` | client | Start discoverable-credential sign-in |
| POST | `/v1/auth/passkey/sign-in/complete` | client | Finish passkey sign-in |
| POST | `/v1/token/refresh` | client | Rotate a refresh token |
| POST | `/v1/logout` | client | Revoke the presented refresh token |
| POST | `/v1/logout/all` | client + bearer | Revoke every refresh token for the user |
| GET | `/v1/me` | client + bearer | Current-user profile |

The expired-magic-link cleanup is the script
``scripts/cleanup_magic_links.py`` (run from cron / Railway scheduled
task), not an HTTP endpoint.

Auth column legend:
- **client** = `X-Client-Id` + `X-Client-Secret` headers
- **bearer** = `Authorization: Bearer <access token>`
- **none** = unauthenticated

> **Note:** `CLAUDE.md`'s "API Surface" section lists slightly different
> path names (e.g. `/v1/auth/magic-link/request` vs the actual
> `/v1/auth/magic-link/start`, `/v1/auth/passkey/auth/begin` vs
> `/v1/auth/passkey/sign-in/begin`, and `/v1/auth/token/refresh` vs
> `/v1/token/refresh`). The table above reflects what is actually
> registered in `knuckles/api/v1/`. Reconcile `CLAUDE.md` to match before
> publishing this doc externally.

### Standard response shapes

Success:
```json
{ "data": { ... }, "meta": { ... } }
```

Error (every error code is a constant in `knuckles/core/exceptions.py`):
```json
{ "error": { "code": "TOKEN_EXPIRED", "message": "..." } }
```

Error code vocabulary: `INVALID_TOKEN`, `TOKEN_EXPIRED`,
`INVALID_CLIENT`, `INVALID_GRANT`, `USER_NOT_FOUND`,
`MAGIC_LINK_INVALID`, `MAGIC_LINK_EXPIRED`, `MAGIC_LINK_ALREADY_USED`,
`GOOGLE_AUTH_FAILED`, `APPLE_AUTH_FAILED`, `PASSKEY_AUTH_FAILED`,
`PASSKEY_REGISTRATION_FAILED`, `EMAIL_DELIVERY_FAILED`,
`REFRESH_TOKEN_INVALID`, `REFRESH_TOKEN_EXPIRED`,
`REFRESH_TOKEN_REUSED`, `VALIDATION_ERROR`, `UNAUTHORIZED`,
`FORBIDDEN`, `INTERNAL_SERVER_ERROR`.

---

## Troubleshooting catalogue

**Knuckles fails at boot with a Pydantic validation error.**
Required env var is missing. The error message names it. The hard
requirements are `DATABASE_URL`, `KNUCKLES_JWT_PRIVATE_KEY`,
`KNUCKLES_JWT_KEY_ID`, `KNUCKLES_STATE_SECRET`.

**`KNUCKLES_JWT_PRIVATE_KEY must be an RSA private key in PEM format.`**
You pasted the raw PEM instead of the base64-wrapped PEM, or you
copied a key that isn't PKCS#8. Regenerate with the `openssl` command
from Part A and `base64 -i` it before pasting.

**Magic-link emails go to the console, not Resend.**
`RESEND_API_KEY` is unset, so `get_default_sender()` returns
`ConsoleEmailSender`. This is intentional for local dev. Set the key
to switch to real delivery.

**Apple sign-in fails with `APPLE_AUTH_FAILED` on `_verify_id_token`.**
Either the `APPLE_OAUTH_PRIVATE_KEY` is malformed (must be the
contents of the `.p8` file, including the `-----BEGIN PRIVATE KEY-----`
lines) or the configured `APPLE_OAUTH_CLIENT_ID` / `TEAM_ID` / `KEY_ID`
don't match the `.p8` file you uploaded to Apple.

**WebAuthn registration fails with origin mismatch.**
Your frontend origin doesn't match `WEBAUTHN_ORIGIN`. The string must
include scheme and host with no trailing slash
(`http://localhost:3000`, not `http://localhost:3000/`).

**`/v1/token/refresh` returns `REFRESH_TOKEN_REUSED` unexpectedly.**
Two clients are sharing one refresh token (e.g. browser and a mobile
app), or you forgot to swap in the rotated token from the previous
refresh response. Always store the new refresh token from the most
recent rotation.

**`/v1/me` returns `UNAUTHORIZED` even with a valid bearer token.**
You forgot the `X-Client-Id` + `X-Client-Secret` headers. `/v1/me`
requires both: the bearer says *which user*, the client headers say
*which app is asking*.

---

## Where to read the source

When you need to understand a behavior, the order is usually:

1. **Route handler** in `knuckles/api/v1/<area>.py` — confirms the
   wire shape, headers, and which service it calls.
2. **Service module** in `knuckles/services/<area>.py` — the actual
   logic.
3. **Repository** in `knuckles/data/repositories/auth.py` — every
   SQL query Knuckles runs, in one file.
4. **Models** in `knuckles/data/models/auth.py` — the schema.
5. **Decision log** in `DECISIONS.md` — the *why* behind the shape.
   Almost every non-obvious choice is recorded here.

The hard rules are in `CLAUDE.md`. Read it before adding any feature
— in particular the "Knuckles never handles music service OAuth" rule
and the import-hierarchy table.

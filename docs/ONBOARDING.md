---
title: Setup Guide
layout: default
nav_order: 4
description: "Step-by-step setup for your own Knuckles deployment. Beginner-friendly. Every command, every env var, every gotcha."
---

# Setup Guide
{: .no_toc }

The full walkthrough for running Knuckles. Unlike the
[Quickstart](quickstart.html), this page assumes you want to
understand what you're doing and end up with a real deployable setup
— with Google Sign-In, Apple Sign-In, real magic-link emails, and
optionally passkeys.

If a step seems obvious, skip it. If it doesn't, every step has a
"why this is here" line.

<details open markdown="block">
<summary>Table of contents</summary>

1. TOC
{:toc}

</details>

---

## Mental model: what you're about to set up

```
[ users' browsers ]
        ↓
[ your app's website ]      ← your code, your domain
        ↓
[ your app's backend ]      ← your code, your servers
        ↓
[ Knuckles service ]        ← what we're setting up here
   ↓        ↓        ↓
[ DB ]   [ Resend ]   [ Google / Apple ]
```

You're going to run **one new service** (Knuckles) that handles every
sign-in ceremony. Your app's backend will talk to it for sign-ins
and verify the tokens it issues.

**Knuckles needs:**
- A Postgres database (its own — no shared schema with your app).
- A pair of secrets: an RSA key (for signing tokens) and a state
  secret (for ceremony state).
- Optionally: API credentials for the providers you want enabled
  (Resend for emails, Google + Apple for OAuth).

**Knuckles does NOT need:**
- Redis, Memcached, or any cache.
- A worker queue.
- Cloud storage.
- Any other service besides Postgres and the providers above.

---

## Part 1 — Generate the two required secrets

These two secrets are required no matter what. Generate them once,
keep them safe, and use the same values in dev and prod (or different
ones — your call, but don't lose them).

### 1.1 The RSA signing key

This is the private key Knuckles uses to sign JWT access tokens. The
matching public key is published at `/.well-known/jwks.json` so your
app can verify tokens locally.

```bash
openssl genpkey -algorithm RSA -out knuckles_private.pem \
    -pkeyopt rsa_keygen_bits:2048
```

You need to base64-encode the file so it fits in a single environment
variable:

```bash
base64 < knuckles_private.pem | tr -d '\n'
```

Copy the resulting string — that's the value for
`KNUCKLES_JWT_PRIVATE_KEY`.

{: .warning }
**Treat this like a password.** Anyone with this key can mint
tokens that look like Knuckles minted them. Keep it in a secrets
manager (Railway / Render / Fly all have one), never in source
control.

You also need a **key id** (`kid`) — a stable label that goes on every
token, so future-you can rotate keys safely. Pick something like
`knuckles-2026-04` (year-month is a nice convention). That's the
value for `KNUCKLES_JWT_KEY_ID`.

### 1.2 The state secret

A 48-byte random string used to sign **ceremony-state JWTs** —
short-lived tokens that carry context across an OAuth round-trip.

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(48))"
```

That's the value for `KNUCKLES_STATE_SECRET`.

---

## Part 2 — Set up your database

Knuckles needs its own Postgres database. Don't share with your
app's database — keep identity separate.

### 2.1 Create the database

```bash
# If running Postgres locally:
createdb knuckles

# If using a managed Postgres (Railway, Neon, Supabase, RDS):
# Just create a database called `knuckles` from their dashboard
# and copy the connection URL.
```

The `DATABASE_URL` env var should look like:

```
postgresql://username:password@host:5432/knuckles
```

### 2.2 Run migrations

Migrations create the tables Knuckles needs. From a checkout of the
repo:

```bash
DATABASE_URL=postgresql://... \
    python -m alembic -c knuckles/alembic.ini upgrade head
```

You should see Alembic apply migrations one at a time, ending in
`head`.

{: .tip }
You don't need to do this manually in production — the Knuckles
container runs migrations automatically on every boot via
`scripts/start.sh`. Migrations are reversible and idempotent.

---

## Part 3 — Pick which sign-in methods you want

Each method is independent. Enable the ones you want; leave the
others disabled (Knuckles silently skips a method if its env vars
aren't set).

### 3.1 Magic-link emails (recommended for everyone)

You'll need a [Resend](https://resend.com) account (free tier is
plenty for getting started). After signing up:

1. Verify a domain you own (e.g. `mail.your-app.com`).
2. Create an API key from the dashboard.
3. Set:
   ```
   RESEND_API_KEY=re_xxxxxxxxxxxx
   RESEND_FROM_EMAIL=login@mail.your-app.com
   ```

Until you set these, magic links print to the Knuckles process log
instead of being emailed (great for local dev).

### 3.2 Sign in with Google

1. Go to [console.cloud.google.com](https://console.cloud.google.com).
2. Create a project (or pick one you already have).
3. Navigate to **APIs & Services → Credentials**.
4. Click **Create Credentials → OAuth client ID**.
5. Pick **Web application**.
6. Under **Authorized redirect URIs**, add **every place** your app
   will receive the Google callback. For most setups that's:
   - `http://localhost:3000/auth/google/callback` (local dev)
   - `https://staging.your-app.com/auth/google/callback`
   - `https://your-app.com/auth/google/callback`
7. Save. Google shows you a Client ID and a Client Secret.
8. Set:
   ```
   GOOGLE_OAUTH_CLIENT_ID=xxxxxxxxxxxx.apps.googleusercontent.com
   GOOGLE_OAUTH_CLIENT_SECRET=GOCSPX-xxxxxxxxx
   ```

{: .note }
**The redirect URI goes on YOUR app, not on Knuckles.** Knuckles
hands the user back to your app, your app forwards the result to
Knuckles. You'll see why in the [Integration guide](INTEGRATION.html).

### 3.3 Sign in with Apple

Apple is more involved. You need an Apple Developer account ($99/yr).

1. In your Apple Developer account, register an **App ID** with
   "Sign In with Apple" capability enabled.
2. Register a **Services ID** (this becomes your `client_id`).
3. Add your callback URLs to the Services ID:
   - `https://your-app.com/auth/apple/callback`
   - (etc. for staging / dev)
4. Create a **Sign in with Apple key** — Apple gives you a `.p8` file
   to download. Note the **Key ID** and your **Team ID** from the
   developer portal.
5. Set:
   ```
   APPLE_OAUTH_CLIENT_ID=com.your-app.signin     # the Services ID
   APPLE_OAUTH_TEAM_ID=ABCDE12345
   APPLE_OAUTH_KEY_ID=XYZ123ABC4
   APPLE_OAUTH_PRIVATE_KEY=$(cat AuthKey_XYZ123ABC4.p8)
   ```

{: .warning }
Apple's redirect URLs **must be HTTPS** — they don't accept
`http://localhost`. If you want to test locally, use a tunnel like
[ngrok](https://ngrok.com) and add the tunnel URL to the Services
ID.

### 3.4 Passkeys (WebAuthn)

No third-party setup needed — passkeys are entirely between the user's
browser and your domain. You just tell Knuckles:

```
WEBAUTHN_RP_ID=your-app.com
WEBAUTHN_RP_NAME=Your App
WEBAUTHN_ORIGIN=https://your-app.com
```

For local dev:

```
WEBAUTHN_RP_ID=localhost
WEBAUTHN_RP_NAME=Local Dev
WEBAUTHN_ORIGIN=http://localhost:3000
```

`RP_ID` is the **domain** users register passkeys against. It must
exactly match the host your frontend runs on. Subdomains are allowed
(`app.your-domain.com` registered against `your-domain.com` works),
but cross-domain doesn't (`other-app.com` won't work).

---

## Part 4 — Run Knuckles locally

You should now have all your env vars. Put them in a `.env` file at
the repo root:

```bash
# Required
DATABASE_URL=postgresql://...
KNUCKLES_BASE_URL=http://localhost:5001
KNUCKLES_JWT_PRIVATE_KEY=<long-base64-string>
KNUCKLES_JWT_KEY_ID=knuckles-2026-04
KNUCKLES_STATE_SECRET=<48-char-random-string>

# Magic-link (optional)
RESEND_API_KEY=re_xxxxxxxxxxxx
RESEND_FROM_EMAIL=login@mail.your-app.com

# Google (optional)
GOOGLE_OAUTH_CLIENT_ID=xxx.apps.googleusercontent.com
GOOGLE_OAUTH_CLIENT_SECRET=GOCSPX-xxx

# Apple (optional)
APPLE_OAUTH_CLIENT_ID=com.your-app.signin
APPLE_OAUTH_TEAM_ID=ABCDE12345
APPLE_OAUTH_KEY_ID=XYZ123ABC4
APPLE_OAUTH_PRIVATE_KEY=...

# Passkeys (optional)
WEBAUTHN_RP_ID=localhost
WEBAUTHN_RP_NAME=Local Dev
WEBAUTHN_ORIGIN=http://localhost:3000
```

Then:

```bash
# 1. Install
pip install -e ".[dev]"

# 2. Migrate
python -m alembic -c knuckles/alembic.ini upgrade head

# 3. Start
flask --app knuckles.app run --port 5001 --debug
```

Sanity check:

```bash
curl http://localhost:5001/health
curl http://localhost:5001/.well-known/jwks.json
curl http://localhost:5001/.well-known/openid-configuration
```

The first returns `{"status":"ok"}`. The second returns your public
key. The third returns OIDC discovery metadata.

---

## Part 5 — Register your first app

For each app that uses Knuckles, you create an `app_client` row.
This holds the app's `client_id`, hashed `client_secret`, and the
list of origins it's allowed to redirect users to.

```bash
python scripts/register_app_client.py \
    --client-id my-app \
    --app-name "My App" \
    --allowed-origin http://localhost:3000 \
    --allowed-origin https://staging.my-app.com \
    --allowed-origin https://my-app.com
```

The output:

```
Registered app_client.
  client_id:     my-app
  client_secret: kn_xxxxxxxxxxxxxxxxxxxxxxxx
```

{: .important }
**Copy the secret immediately.** Knuckles stores only a SHA-256
hash of it. There's no recovery — if you lose it, you'll need to
register a new client.

Hand the `client_id` and `client_secret` to whoever's running the
app (likely yourself). The secret goes in the **app's backend
environment** — never in the frontend bundle.

### What's an "allowed origin"?

When a user signs in, Knuckles redirects them back to a URL on your
app (e.g. `https://my-app.com/auth/google/callback`). The
`--allowed-origin` flags whitelist which URL prefixes are acceptable.
Knuckles refuses to redirect anywhere not in this list — that's what
prevents phishers from registering a fake `client_id` and stealing
sign-in flows.

Add an origin for **every place** your app runs: production, staging,
each dev's machine. Origins are scheme + host + port — e.g.
`http://localhost:3000`, `https://app.example.com`. Paths don't
matter; only the origin part does.

---

## Part 6 — Test the four sign-in methods

Set these in your shell so the curl commands stay short:

```bash
export KNUCKLES=http://localhost:5001
export CID=my-app
export CSECRET=kn_xxxxxxxxxxxxxxxxxxxxxxxx
```

### 6.1 Magic-link

```bash
# Request a link
curl -X POST $KNUCKLES/v1/auth/magic-link/start \
    -H "Content-Type: application/json" \
    -H "X-Client-Id: $CID" -H "X-Client-Secret: $CSECRET" \
    -d '{"email":"you@example.com",
         "redirect_url":"http://localhost:3000/auth/verify"}'
```

Look in the Knuckles terminal for the magic link (or your inbox if
Resend is configured). Then redeem the token:

```bash
curl -X POST $KNUCKLES/v1/auth/magic-link/verify \
    -H "Content-Type: application/json" \
    -H "X-Client-Id: $CID" -H "X-Client-Secret: $CSECRET" \
    -d '{"token":"<token-from-link>"}'
```

You get back a token pair. ✅ Magic-link works.

### 6.2 Google

```bash
# Step 1 — get the Google consent URL
curl -X POST $KNUCKLES/v1/auth/google/start \
    -H "Content-Type: application/json" \
    -H "X-Client-Id: $CID" -H "X-Client-Secret: $CSECRET" \
    -d '{"redirect_url":"http://localhost:3000/auth/google/callback"}'
```

The response includes `authorize_url`. Open it in your browser. After
you approve, Google redirects to your `redirect_url` with a `code`
and a `state` in the query string. Pass them to:

```bash
curl -X POST $KNUCKLES/v1/auth/google/complete \
    -H "Content-Type: application/json" \
    -H "X-Client-Id: $CID" -H "X-Client-Secret: $CSECRET" \
    -d '{"code":"<from-url>","state":"<from-url>"}'
```

Token pair. ✅ Google works.

### 6.3 Apple

Same shape as Google with `/v1/auth/apple/start` and
`/v1/auth/apple/complete`. Apple's first-ever sign-in for a given
Apple ID also includes a `user` payload (the user's name) — pass it
through if present:

```bash
curl -X POST $KNUCKLES/v1/auth/apple/complete \
    -H "Content-Type: application/json" \
    -H "X-Client-Id: $CID" -H "X-Client-Secret: $CSECRET" \
    -d '{"code":"...","state":"...",
         "user":{"name":{"firstName":"Ada","lastName":"Lovelace"}}}'
```

### 6.4 Passkeys

Passkeys can't be tested with `curl` alone — they require a real
browser (the user's device performs the cryptography). The
end-to-end test for passkeys is to wire them into your app, see the
[TypeScript walkthrough](typescript.html) for a concrete example.

---

## Part 7 — Deploy to production

Knuckles ships with a single-stage Dockerfile and a `railway.toml`,
so the production target it's been most thoroughly tested against is
[Railway](https://railway.app). The same Dockerfile works on Render,
Fly, your own Docker host — anywhere that runs containers.

### 7.1 Provision Postgres

Most platforms have a "Add Postgres" button. Click it; copy the
`DATABASE_URL` it gives you.

### 7.2 Set every env var

| Variable | Required? | Notes |
|---|---|---|
| `DATABASE_URL` | yes | From your Postgres provider |
| `KNUCKLES_BASE_URL` | yes | The public URL of this service (e.g. `https://auth.your-app.com`) |
| `KNUCKLES_JWT_PRIVATE_KEY` | yes | Base64-encoded PEM from Part 1.1 |
| `KNUCKLES_JWT_KEY_ID` | yes | Stable `kid` from Part 1.1 |
| `KNUCKLES_STATE_SECRET` | yes | From Part 1.2 |
| `RESEND_API_KEY` | for magic-link | |
| `RESEND_FROM_EMAIL` | for magic-link | |
| `GOOGLE_OAUTH_CLIENT_ID` | for Google | |
| `GOOGLE_OAUTH_CLIENT_SECRET` | for Google | |
| `APPLE_OAUTH_CLIENT_ID` | for Apple | |
| `APPLE_OAUTH_TEAM_ID` | for Apple | |
| `APPLE_OAUTH_KEY_ID` | for Apple | |
| `APPLE_OAUTH_PRIVATE_KEY` | for Apple | |
| `WEBAUTHN_RP_ID` | for passkeys | |
| `WEBAUTHN_RP_NAME` | for passkeys | |
| `WEBAUTHN_ORIGIN` | for passkeys | |

Tunables (sensible defaults shipped):

| Variable | Default | What it does |
|---|---|---|
| `KNUCKLES_ACCESS_TOKEN_TTL_SECONDS` | 3600 (1h) | Access-token lifetime |
| `KNUCKLES_REFRESH_TOKEN_TTL_SECONDS` | 2592000 (30d) | Refresh-token lifetime |
| `MAGIC_LINK_TTL_SECONDS` | 900 (15m) | How long magic links stay valid |
| `KNUCKLES_STRICT_CORS` | `false` | When `true`, only echo CORS for registered origins |
| `PORT` | 5001 | Listening port |
| `WEB_CONCURRENCY` | 2 | Gunicorn workers |
| `GUNICORN_TIMEOUT` | 30 | Per-request timeout (seconds) |

### 7.3 Deploy

Push to the platform of your choice. The container's `CMD` runs
`scripts/start.sh`, which:

1. Runs `alembic upgrade head` (applies migrations).
2. Boots gunicorn binding to `$PORT`.

The platform's healthcheck should hit `GET /health` with a 30-second
timeout. `railway.toml` already configures this.

### 7.4 Verify it's up

```bash
curl https://auth.your-app.com/health
curl https://auth.your-app.com/.well-known/jwks.json
curl https://auth.your-app.com/.well-known/openid-configuration
```

If all three respond, you're done.

### 7.5 Register your production app-client

```bash
# Run the script against the deployed service. On Railway:
railway run python scripts/register_app_client.py \
    --client-id my-app \
    --app-name "My App" \
    --allowed-origin https://my-app.com \
    --allowed-origin https://staging.my-app.com
```

Hand the credentials to whoever runs the app.

---

## Part 8 — Day-2 operations

### Adding a new app

Same script as Part 5 / 7.5, run against your production Knuckles.

### Rotating an app's secret

```sql
UPDATE app_clients
SET client_secret_hash = encode(digest('<new-secret>', 'sha256'), 'hex')
WHERE client_id = '<id>';
```

Notify the app's operator out of band so they can update their env
var. No user sessions are invalidated.

### Rotating Knuckles' signing key

This needs care because in-flight access tokens are still signed by
the old key. The lifecycle:

1. Generate a fresh RSA keypair with a new `kid`.
2. Edit `knuckles/core/jwt.py:get_published_public_keys()` to publish
   **both** the old and new public keys.
3. Switch `KNUCKLES_JWT_PRIVATE_KEY` and `KNUCKLES_JWT_KEY_ID` to the
   new key. From this point new tokens are signed with the new key.
4. Wait at least `KNUCKLES_ACCESS_TOKEN_TTL_SECONDS` (1h by default)
   so old tokens have expired.
5. Drop the old key from `get_published_public_keys()`.

Refresh tokens are unaffected — they're opaque random strings, not
JWTs.

### Cleaning up expired magic-link rows

`scripts/cleanup_magic_links.py` deletes magic-link rows whose
`expires_at` is older than the cutoff. Wire it to a nightly cron:

```bash
# Once a day at 3am UTC
python scripts/cleanup_magic_links.py --older-than-hours 24
```

Idempotent — running twice in a row is fine.

### A user reports "I can't sign in / I'm signed out"

Check the most recent refresh-token activity for that user:

```sql
SELECT id, app_client_id, used_at, expires_at, created_at
FROM refresh_tokens
WHERE user_id = (SELECT id FROM users WHERE email = 'them@example.com')
ORDER BY created_at DESC
LIMIT 5;
```

If you see a row with `used_at` set but a sibling row created **after**
it, that's a refresh-token reuse — Knuckles auto-revokes everything for
that user, and the user must sign in again. This is working as
designed; it usually means a leaked token.

---

## Troubleshooting

**Knuckles fails at boot with a Pydantic validation error.**
A required env var is missing or malformed. The error names which
one. The hard requirements are `DATABASE_URL`, `KNUCKLES_JWT_PRIVATE_KEY`,
`KNUCKLES_JWT_KEY_ID`, `KNUCKLES_STATE_SECRET`.

**`KNUCKLES_JWT_PRIVATE_KEY must be an RSA private key in PEM format.`**
Either you pasted the raw PEM instead of the base64-wrapped version,
or the key isn't PKCS#8. Regenerate with the openssl command in
Part 1.1 and base64-encode it.

**Magic-link emails go to the console, not the user's inbox.**
`RESEND_API_KEY` is unset. This is intentional for local dev. Set
the key to switch to real delivery.

**Apple sign-in fails with `APPLE_AUTH_FAILED`.**
Either your `APPLE_OAUTH_PRIVATE_KEY` is malformed (must be the
literal contents of the `.p8` file, including
`-----BEGIN PRIVATE KEY-----` lines) or the configured
`APPLE_OAUTH_CLIENT_ID` / `TEAM_ID` / `KEY_ID` don't match the key
file you uploaded to Apple.

**WebAuthn registration fails with origin mismatch.**
Your frontend origin doesn't match `WEBAUTHN_ORIGIN` exactly. The
string must include scheme and host with no trailing slash:
`http://localhost:3000`, NOT `http://localhost:3000/`.

**`/v1/token/refresh` returns `REFRESH_TOKEN_REUSED`.**
Two clients (or two browser tabs) tried to use the same refresh
token, OR the app forgot to swap in the rotated token from the
previous response. Always store the **new** refresh token from each
refresh response.

**`/v1/me` returns `UNAUTHORIZED` even with a valid bearer token.**
You forgot the `X-Client-Id` + `X-Client-Secret` headers. `/v1/me`
needs both: bearer says *which user*, client headers say *which app
is asking*.

For a longer list of beginner gotchas, see the [FAQ](faq.html).

---

## Where to go next

- **Wire up an app to use Knuckles.** → [Integration overview](INTEGRATION.html)
- **Common patterns (protect routes, log out, refresh tokens).** →
  [Recipes](recipes.html)
- **Full HTTP API reference.** → [API reference](api/)

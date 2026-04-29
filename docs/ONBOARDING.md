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

You'll create a **Google Cloud project**, configure an **OAuth
consent screen**, and create an **OAuth client ID**. Plan ~15
minutes if it's your first time. Free, no card required.

#### Step 1 — Create a Google Cloud project

1. Open <https://console.cloud.google.com>. Sign in with the Google
   account you want to own this project (it can be your personal
   account; Workspace is not required).
2. In the **top-left**, click the **project picker** (it currently
   shows "Select a project" or the name of an existing project).
3. In the modal, click **New Project** (top right).
4. Name it whatever you like (e.g. "My App Auth"). Leave organization
   as "No organization" if you don't have a Workspace. Click
   **Create**.
5. Wait ~10 seconds for the project to provision, then make sure it's
   selected in the project picker (top-left should now show your
   project name).

#### Step 2 — Configure the OAuth consent screen

This is the screen Google shows users *during* sign-in ("My App wants
to access your name and email"). You **must** configure it before
you can create credentials.

1. In the left sidebar, navigate to **APIs & Services → OAuth consent
   screen**. (If you don't see "APIs & Services", click the hamburger
   menu **☰** in the top left.)
2. Pick a **User Type:**
   - **External** — anyone with a Google account can sign in. Pick
     this. (Internal is only available if you have a Google Workspace
     organization.)
3. Click **Create**.
4. Fill in **OAuth consent screen** fields:
   - **App name:** what users see during sign-in (e.g. "My App").
   - **User support email:** your email.
   - **App logo:** optional.
   - **Application home page** / **privacy policy** / **terms of
     service:** optional during testing, **required before
     publishing**.
   - **Authorized domains:** add the bare domains you'll redirect
     from (e.g. `your-app.com`). For localhost-only dev, leave empty
     — Google allows `localhost` automatically.
   - **Developer contact:** your email again.
   - Click **Save and Continue**.
5. **Scopes** screen: click **Add or Remove Scopes** and add three:
   - `.../auth/userinfo.email`
   - `.../auth/userinfo.profile`
   - `openid`
   - Click **Update**, then **Save and Continue**.
6. **Test users** screen: while your app is in "Testing" mode (the
   default), only emails listed here can sign in. Add your own email
   plus any teammates. Click **Save and Continue**.
7. **Summary** screen: review and click **Back to Dashboard**.

{: .note }
**Testing vs. Production:** Your app starts in "Testing" status —
limited to 100 test users you've explicitly added. To let any Google
user sign in, click **Publish App** on the consent screen page. For
basic scopes (email, profile, openid) publishing is instant and does
not require Google verification. For sensitive scopes (Drive, Gmail,
etc.) it requires manual review by Google — but Knuckles only uses
the basic scopes, so publishing is one click.

#### Step 3 — Create the OAuth client

1. Sidebar: **APIs & Services → Credentials**.
2. Click **+ Create Credentials** (top of page) → **OAuth client ID**.
3. **Application type:** select **Web application**.
4. **Name:** internal label only (e.g. "My App – Web"). Users never
   see this.
5. **Authorized JavaScript origins:** leave blank. Knuckles doesn't
   need them — all calls go server-to-server.
6. **Authorized redirect URIs:** click **+ Add URI** for each place
   your app will receive Google's callback. **Add every environment
   you have:**
   - `http://localhost:3000/auth/google/callback` (local dev — http
     is allowed for localhost)
   - `https://staging.your-app.com/auth/google/callback`
   - `https://your-app.com/auth/google/callback`
7. Click **Create**.

A modal pops up with your **Client ID** and **Client Secret.**
**Copy both right now** — you'll see the Client ID again later, but
copying both is convenient. Click **OK**.

#### Step 4 — Set the env vars

```
GOOGLE_OAUTH_CLIENT_ID=xxxxxxxxxxxx.apps.googleusercontent.com
GOOGLE_OAUTH_CLIENT_SECRET=GOCSPX-xxxxxxxxx
```

{: .note }
**The redirect URI goes on YOUR app, not on Knuckles.** Knuckles
hands the user back to your app, your app forwards the result to
Knuckles. You'll see why in the [Integration guide](INTEGRATION.html).

#### Common Google errors

| Error | Cause | Fix |
|---|---|---|
| `redirect_uri_mismatch` | The `redirect_url` you sent to Knuckles doesn't exactly match what's listed in the OAuth client. | Check trailing slashes (`/auth/google/callback` ≠ `/auth/google/callback/`), http vs https, port numbers, the host. Add the exact string to **Authorized redirect URIs** and wait ~5 minutes for Google to propagate. |
| `invalid_client` | Wrong Client ID, wrong Client Secret, or the credential was deleted. | Re-copy from the Credentials page. The Client Secret is masked — click **Reset Client Secret** if you've lost it. |
| `access_denied` (user-facing) | Your app is in "Testing" status and the user's email isn't in the test-users list. | Add their email under **OAuth consent screen → Test users**, OR click **Publish App**. |
| `disallowed_useragent` | Some embedded browsers (Facebook in-app browser, old WebViews) are blocked by Google. | Open the sign-in flow in the system browser, not the in-app one. |
| Sign-in works in dev but breaks in prod | Production redirect URI not added to the OAuth client. | Add `https://your-app.com/auth/google/callback` and wait ~5 min. |

### 3.3 Sign in with Apple

Sign in with Apple is the most painful provider to set up. Plan
**~30–45 minutes** the first time. Two reasons it's harder than
Google:

1. **It costs money.** Apple Developer Program is $99/year. No free
   tier. You need a paid membership before you can configure
   anything below.
2. **Multiple distinct concepts.** You'll juggle four things —
   **Team ID**, **App ID**, **Services ID**, and a **Sign in with
   Apple key** — that all live in different places and refer to each
   other in non-obvious ways. Don't worry, the steps below are in
   the right order.

{: .warning }
**Apple does not allow `http://localhost` redirect URIs.** Even for
local dev. Either skip Apple while developing locally and only test
in staging, or use a tunnel like [ngrok](https://ngrok.com) (free
tier is fine) so you have an HTTPS URL pointed at your dev machine,
and add that tunnel URL to the Services ID.

#### Step 0 — Make sure you're enrolled

If you haven't already, enroll at
<https://developer.apple.com/programs/enroll/>. Individual enrollment
takes a day or two for Apple to verify; organization enrollment can
take up to a week. **Skip the rest of this section until you're
enrolled** — none of the screens below are accessible otherwise.

#### Step 1 — Find your Team ID (you already have one)

1. Sign in at <https://developer.apple.com/account>.
2. Look at the **top-right corner** under your name. You'll see a
   10-character alphanumeric string like `ABCDE12345`. **That's your
   Team ID.** Copy it down.

You'll also see it under **Membership Details** in the left sidebar
if you can't find it elsewhere.

#### Step 2 — Create an App ID

This represents the underlying "app" entity at Apple, even though
yours might be a web app. You need it before the Services ID will
work.

1. Go to <https://developer.apple.com/account/resources/identifiers/list>.
   (Or sidebar: **Certificates, Identifiers & Profiles → Identifiers**.)
2. Click the **blue + button** next to "Identifiers" at the top.
3. Select **App IDs** → click **Continue**.
4. Select **App** → click **Continue**.
5. Fill in:
   - **Description:** internal label (e.g. "My App"). Users never
     see this.
   - **Bundle ID:** select **Explicit** and enter a reverse-domain
     identifier like `com.your-app`. This is permanent — pick
     carefully.
6. Scroll the **Capabilities** list, find **Sign In with Apple**, and
   **check the box.** (Click **Edit** next to it if you want a
   non-default config; the default is fine for most apps.)
7. Click **Continue** → review → click **Register**.

#### Step 3 — Create a Services ID (this becomes your `client_id`)

A Services ID represents the *web-side* identity. The bundle ID
above is for native apps; the Services ID is what Knuckles uses.

1. Back to **Identifiers**, click the **blue + button** again.
2. Select **Services IDs** → click **Continue**.
3. Fill in:
   - **Description:** internal label (e.g. "My App Sign In").
   - **Identifier:** another reverse-domain string like
     `com.your-app.signin`. This will be your
     `APPLE_OAUTH_CLIENT_ID` env var. Different from the App ID
     above. Permanent.
4. Click **Continue** → **Register**.
5. Now click on the Services ID you just created from the list to
   open its settings.
6. Check **Sign In with Apple** to enable it.
7. Click the **Configure** button next to "Sign In with Apple."
8. In the modal:
   - **Primary App ID:** select the App ID you made in Step 2.
   - **Domains and Subdomains:** add the bare hostnames where your
     callback URLs will live, *without* `https://` and *without*
     paths. E.g. `your-app.com`, `staging.your-app.com`,
     `tunnel-abc123.ngrok-free.app`.
   - **Return URLs:** add the **full callback URLs**, including
     `https://` and the path. E.g.
     `https://your-app.com/auth/apple/callback`.
   - Click **Next** → **Done**.
9. Click **Continue** → **Save**.

{: .note }
**Domain verification.** Apple requires you serve a verification
file at `https://your-domain.com/.well-known/apple-developer-domain-association.txt`.
After saving the Services ID, you'll see a **Download** button on the
domains modal. Download that file, drop it at that exact path on
your web server, then click **Verify** in the Apple modal. Repeat
for each domain. Verification often takes a few minutes to propagate.

#### Step 4 — Create a Sign in with Apple key (`.p8` file)

This is the **private key** Apple uses to confirm your server's
identity. You can only download it ONCE.

1. Sidebar: **Certificates, Identifiers & Profiles → Keys.**
2. Click the **blue + button** next to "Keys."
3. **Key Name:** internal label (e.g. "My App – Sign In Key").
4. Check **Sign In with Apple.**
5. Click **Configure** next to it. **Primary App ID:** select the
   App ID from Step 2. Click **Save.**
6. Click **Continue** → review → click **Register**.
7. **Download the `.p8` file NOW.** This is your only chance —
   Apple never lets you download it again. Store it somewhere safe
   (1Password, your secrets manager, encrypted disk).
8. Note the **Key ID** shown on this page (10 characters,
   alphanumeric, e.g. `XYZ123ABC4`). Copy it.

#### Step 5 — Set the env vars

```bash
APPLE_OAUTH_CLIENT_ID=com.your-app.signin       # the Services ID identifier
APPLE_OAUTH_TEAM_ID=ABCDE12345                  # from Step 1
APPLE_OAUTH_KEY_ID=XYZ123ABC4                   # from Step 4
APPLE_OAUTH_PRIVATE_KEY=$(cat AuthKey_XYZ123ABC4.p8)
```

The `APPLE_OAUTH_PRIVATE_KEY` value is the **literal contents of the
`.p8` file**, including the `-----BEGIN PRIVATE KEY-----` and
`-----END PRIVATE KEY-----` lines. The `$(cat ...)` shell expansion
above does this for you when you set the env var locally; for
production deploys, copy-paste the file's text into your platform's
secrets manager.

{: .important }
**Apple's `client_secret` is a JWT that expires every 6 months.**
Knuckles auto-mints this client_secret JWT internally on every
request, signed with your `.p8` key. So as long as your `.p8` key
itself isn't revoked, you don't have to rotate `client_secret`s by
hand. (This is different from Google, where the Client Secret is a
permanent string until you reset it.)

#### Common Apple errors

| Error | Cause | Fix |
|---|---|---|
| `invalid_client` (during `/v1/auth/apple/complete`) | One of `APPLE_OAUTH_CLIENT_ID`, `TEAM_ID`, or `KEY_ID` doesn't match the `.p8` key file you uploaded. | Re-check all three values against the Apple Developer portal — they're in three different places (Services ID page, top-right of any page, Keys page respectively). |
| `invalid_grant` (after time passes) | Apple's auth code expired, or the client_secret JWT Knuckles minted has clock skew. | Make sure the Knuckles host's clock is correct. If it's been weeks, your .p8 key may have been revoked — check **Keys** page in the developer portal. |
| Domain verification keeps failing | The `.well-known/apple-developer-domain-association.txt` file isn't being served correctly. | The file must be at *exactly* that path, served as `text/plain`, with the exact contents Apple gave you (no BOM, no extra whitespace). Some platforms (Vercel, Netlify) need explicit routing rules to allow `.well-known/`. |
| Apple sign-in works the first time but fails on subsequent attempts with no `user` payload | This is by design — Apple sends the user's name only on the FIRST EVER sign-in for a given Apple ID. | Don't depend on `user` being present. If it's there, save it; if it's not, fall back to whatever you have. Knuckles handles this correctly internally. |
| User sees "Email Sharing Preference" with a relay address like `abc123@privaterelay.appleid.com` | Apple lets users hide their real email and use a relay. | Treat the relay address as the canonical email. It's stable across sign-ins. Apple forwards email sent to it. |
| Sign-in works in dev but not in prod | Production return URL not added to the Services ID, or the production domain isn't verified. | Add the prod URL under **Sign In with Apple → Configure → Return URLs**, and make sure the prod domain is verified (download + serve the verification file there too). |

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

---
title: Quickstart
layout: default
nav_order: 3
description: "From git clone to a real signed-in user, in five minutes."
---

# Quickstart
{: .no_toc }

Five minutes from cloning the repo to seeing a real user signed in
with a magic-link. We'll skip every optional step here — there's a
[Setup Guide](ONBOARDING.html) for the full story.

<details open markdown="block">
<summary>Table of contents</summary>

1. TOC
{:toc}

</details>

---

## What you need before you start

- **Python 3.12 or newer.** Run `python3 --version` to check.
- **Postgres running locally.** The easiest way is Docker:
  `docker run -p 5432:5432 -e POSTGRES_PASSWORD=local postgres:16`
- **`openssl` on your shell path.** It's already installed on macOS
  and most Linux distros.

That's it. No paid accounts, no Google Cloud setup, no email service
— we'll use the **console email sender**, which prints magic-link
URLs to your terminal so you can sign in to yourself.

---

## Step 1 — Clone and install (1 min)

```bash
git clone https://github.com/gsooter/knuckles.git
cd knuckles

python3.12 -m venv .venv
source .venv/bin/activate

pip install -e ".[dev]"
```

This installs Knuckles in editable mode plus the dev tools (pytest,
ruff, etc.).

---

## Step 2 — Make a database (30 sec)

If you used the Docker command above, just run:

```bash
createdb -h localhost -U postgres knuckles
# (password: local)
```

If you have Postgres installed natively, `createdb knuckles` is enough.

---

## Step 3 — Generate the secrets Knuckles needs (1 min)

Knuckles needs two secrets at startup: an **RSA signing key** (for
JWTs) and a **state secret** (for ceremony state). Generate both:

```bash
# RSA private key (used to sign access tokens)
openssl genpkey -algorithm RSA -out /tmp/knuckles_private.pem \
    -pkeyopt rsa_keygen_bits:2048

# Base64-encode it for the env var
KNUCKLES_JWT_PRIVATE_KEY=$(base64 < /tmp/knuckles_private.pem | tr -d '\n')

# Random state secret
KNUCKLES_STATE_SECRET=$(python -c "import secrets; print(secrets.token_urlsafe(48))")
```

Now write a `.env` file at the repo root:

```bash
cat > .env <<EOF
DATABASE_URL=postgresql://postgres:local@localhost:5432/knuckles
KNUCKLES_BASE_URL=http://localhost:5001
KNUCKLES_JWT_PRIVATE_KEY=$KNUCKLES_JWT_PRIVATE_KEY
KNUCKLES_JWT_KEY_ID=local-dev-key
KNUCKLES_STATE_SECRET=$KNUCKLES_STATE_SECRET
EOF
```

{: .note }
The `KNUCKLES_JWT_PRIVATE_KEY` value is a long single line of
base64 — that's intentional. It's the entire RSA key, encoded so
it fits in an environment variable.

---

## Step 4 — Run migrations and start the server (30 sec)

```bash
# Set up the database schema
python -m alembic -c knuckles/alembic.ini upgrade head

# Start the dev server on port 5001
flask --app knuckles.app run --port 5001 --debug
```

In a second terminal, sanity-check:

```bash
curl http://localhost:5001/health
# => {"status":"ok"}
```

You're running.

---

## Step 5 — Register an app-client (30 sec)

Knuckles needs to know which apps are allowed to call it. Create one:

```bash
python scripts/register_app_client.py \
    --client-id local-dev \
    --app-name "Local Dev App" \
    --allowed-origin http://localhost:3000
```

The output looks like:

```
Registered app_client.
  client_id:     local-dev
  client_secret: kn_xxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

**Copy the secret right now.** Knuckles only stores a hash of it and
will not show it again. For this quickstart, save it to a shell
variable:

```bash
export CID=local-dev
export CSECRET=kn_xxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

---

## Step 6 — Sign yourself in with a magic link (1 min)

Ask Knuckles to send a magic link to your email:

```bash
curl -X POST http://localhost:5001/v1/auth/magic-link/start \
    -H "Content-Type: application/json" \
    -H "X-Client-Id: $CID" \
    -H "X-Client-Secret: $CSECRET" \
    -d '{
      "email": "you@example.com",
      "redirect_url": "http://localhost:3000/auth/verify"
    }'
```

The response is `{"data":{"status":"sent"}}` — but since you don't
have Resend configured, **the magic link is printed in the Flask
terminal output instead.** Look at the terminal running the server,
you'll see something like:

```
[ConsoleEmailSender] To: you@example.com
[ConsoleEmailSender] Subject: Sign in to Local Dev App
[ConsoleEmailSender] Magic link: http://localhost:3000/auth/verify?token=abc123def...
```

Copy the `token=...` value from the URL. Now redeem it:

```bash
curl -X POST http://localhost:5001/v1/auth/magic-link/verify \
    -H "Content-Type: application/json" \
    -H "X-Client-Id: $CID" \
    -H "X-Client-Secret: $CSECRET" \
    -d '{"token": "abc123def..."}'
```

The response is your sign-in success — an access token plus a refresh
token:

```json
{
  "data": {
    "access_token": "eyJhbGciOiJSUzI1NiIs...",
    "access_token_expires_at": "2026-04-26T13:00:00+00:00",
    "refresh_token": "rt_xxxxxxxxxxxxxxxxxxxxxxxx",
    "refresh_token_expires_at": "2026-05-26T12:00:00+00:00",
    "token_type": "Bearer"
  }
}
```

🎉 **You signed in a real user.** That JWT is a real signed access
token your app can verify against `/.well-known/jwks.json`.

---

## Step 7 — Look at what just happened

Take a moment to see the data:

```bash
# View the user that got created
psql knuckles -c "SELECT id, email, created_at FROM users;"

# View the active refresh token
psql knuckles -c "SELECT id, user_id, expires_at FROM refresh_tokens;"

# Decode the access token (the middle part is base64 JSON)
echo '<your-access-token>' | cut -d. -f2 | base64 -d | python -m json.tool
```

The decoded token will look like:

```json
{
  "sub": "uuid-of-the-user",
  "iss": "http://localhost:5001",
  "aud": "local-dev",
  "exp": 1714102800,
  "iat": 1714099200,
  "email": "you@example.com",
  "scopes": ["openid", "email", "profile"]
}
```

That's the payload your app will read on every request to know who
the user is.

---

## What's next

Now that you have Knuckles running and a user signed in, you have
three natural directions:

- **Add it to a real app.** → [Integration overview](INTEGRATION.html)
  → pick [Python](python.html) or [TypeScript](typescript.html).
- **Set up the other sign-in methods (Google, Apple, passkey).** →
  [Setup Guide](ONBOARDING.html). Each one is a section.
- **Deploy this somewhere.** → [Setup Guide](ONBOARDING.html) (Part 7 covers deploy).

If something didn't work, the [FAQ](faq.html) covers the common
quickstart pitfalls.

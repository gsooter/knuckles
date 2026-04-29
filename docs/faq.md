---
title: FAQ
layout: default
nav_order: 7
description: "Questions beginners actually ask about running and integrating Knuckles."
---

# FAQ
{: .no_toc }

Real questions from people setting Knuckles up for the first time.
If yours isn't here, [open an issue](https://github.com/gsooter/knuckles/issues) — we'll add it.

<details open markdown="block">
<summary>Table of contents</summary>

1. TOC
{:toc}

</details>

---

## Conceptual

### Why do I need a separate auth service at all? Can't I just do this in my app?

You can. Many apps do. Knuckles is for the case where:

- You don't want to learn OAuth, WebAuthn, JWT signing, password
  hashing, refresh-token rotation, JWKS, and the rest.
- You want sane security defaults out of the box.
- You might add a second app later and want them to share sign-in.

If you have one small app and don't mind owning the auth code,
something like NextAuth (Node) or Authlib (Python) gives you a
library, not a service. They're solid. Knuckles is the answer for
"give me a service, I just want to point at it."

### How is this different from Auth0 / Clerk / Supabase Auth?

Those are **hosted services** — you give them your users, they store
them, you pay them per user.

Knuckles is **self-hosted** — you run it (one container, one
Postgres). Your data stays with you. You don't pay per user.

Trade-off: you're on the hook for ops. If your Knuckles instance
goes down, sign-ins fail until you fix it. (Existing sessions keep
working — apps verify tokens locally without phoning home.)

### Why JWTs and not session cookies?

Two reasons:
1. **Scaling.** With JWTs, every backend in your fleet can verify the
   token locally — no shared session store, no per-request DB lookup.
2. **Multi-app.** If you have two apps that share users, both can
   verify Knuckles' JWTs without coordinating session state.

If you only have one small monolith and don't expect to scale, plain
session cookies are simpler. Knuckles still works for that case, but
the JWT machinery is overkill.

### What does "rotating refresh token" mean?

Every time you call `/v1/token/refresh`, you get **a new refresh
token in the response**. The old one becomes invalid immediately.

If anyone tries to reuse the old one (because you stored it after a
leak, or because it leaked), Knuckles detects it and **revokes every
refresh token for that user**. The user is signed out everywhere
they had sessions, and has to sign in again.

This is the standard refresh-token-reuse-detection pattern. It's
what protects you from token theft.

### Does Knuckles work for mobile apps?

Yes — same flows, no browser-specific bits except passkeys (and
those work on iOS/Android via system passkey APIs).

The pattern is identical: your mobile app's backend (or a serverless
function it calls) holds the `client_secret`, drives the sign-in
ceremony, and hands the access token back to the mobile client.

---

## Setup

### What's the cheapest way to run this?

Railway and Render both have free tiers that fit Knuckles + a tiny
Postgres. Real cost at low scale is roughly **$5–10/month**. If you
already have a server somewhere, the Docker image runs anywhere —
zero added cost.

### Do I need Resend? Can I use SendGrid / Mailgun / SES?

Right now Knuckles ships with a Resend backend out of the box, plus
a `ConsoleEmailSender` for local dev. Adding another provider is
about 30 lines in `knuckles/services/email.py` — `EmailSender` is a
simple Protocol with one method (`send_magic_link`).

If you'd rather not wire one up, you can also use Resend's free tier
(100 emails/day, plenty for most starting points).

### My app is on Vercel / Cloudflare Workers — can it talk to Knuckles?

Yes. Knuckles is a regular HTTP API. Your app's serverless functions
call it like any other service. The SDKs work in Node-runtime
serverless environments. For edge runtimes (Cloudflare Workers,
Vercel Edge), you'll want to verify tokens with a JWKS-aware library
like [`jose`](https://github.com/panva/jose) — the SDK expects
Node's crypto module.

### Can I host Knuckles at a custom domain like auth.my-app.com?

Yes, and you should. Set `KNUCKLES_BASE_URL=https://auth.my-app.com`
and configure your platform's custom-domain feature to point at
Knuckles. The base URL becomes the JWT `iss` claim, so changing it
later means re-issuing tokens — pick once, stick with it.

### Do I need HTTPS?

In production, yes — same as any web service. Browser security
features (cookies, WebAuthn) refuse non-HTTPS in production
contexts. For local dev, HTTP on `localhost` is fine.

Apple Sign-In is the strictest: even local dev must be HTTPS for
Apple's redirect URLs. Use [ngrok](https://ngrok.com) or
[localtunnel](https://github.com/localtunnel/localtunnel).

---

## Quickstart problems

### `flask: command not found`

You forgot to activate the venv:

```bash
source .venv/bin/activate
```

Or you didn't install in editable mode:

```bash
pip install -e ".[dev]"
```

### `psycopg.OperationalError: connection refused`

Postgres isn't running, or `DATABASE_URL` points at the wrong host
or port. If you used the Docker command from the Quickstart, double
check the container's still up: `docker ps`.

### Magic-link emails aren't being sent

By default they go to the Knuckles **terminal**, not your inbox.
Look at the Flask process output — you'll see lines like
`[ConsoleEmailSender] Magic link: http://...`. To switch to real
email, set `RESEND_API_KEY` and `RESEND_FROM_EMAIL`.

### `KNUCKLES_JWT_PRIVATE_KEY must be an RSA private key in PEM format`

You pasted the raw PEM (with newlines) instead of the base64-encoded
single-line version. Re-run the encoding step:

```bash
base64 < knuckles_private.pem | tr -d '\n'
```

That's the value to paste.

### `INVALID_CLIENT` on every request

Two possibilities:
1. You haven't created an `app_client` row yet — run
   `scripts/register_app_client.py`.
2. You're sending the wrong `X-Client-Id` / `X-Client-Secret`. The
   secret is hashed at rest; if you lost the plaintext, register a
   new client.

### `validation error` for `redirect_url`

Your `redirect_url` doesn't match any registered `--allowed-origin`.
The origin is the scheme + host + port — `http://localhost:3000` is
different from `http://localhost:3001`.

You can list a client's allowed origins:

```sql
SELECT client_id, allowed_origins FROM app_clients;
```

Add an origin by editing the row directly, or just delete and
re-register the client.

---

## Integration

### What's the difference between `client_secret` and `access_token`?

| | `client_secret` | `access_token` |
|---|---|---|
| Identifies | Your **app** | A signed-in **user** |
| Where it lives | Your backend env vars | An HTTP-only cookie |
| Lifetime | Forever (until rotated) | 1 hour |
| Format | Random string | JWT |

Your backend sends both on protected calls — the secret says "this is
My App talking," the bearer says "and this user is signed in."

### Where do I store the access token?

In an **HTTP-only, same-site cookie**. Set by your backend after the
sign-in ceremony.

```python
# Flask
response.set_cookie(
    "access_token",
    pair.access_token,
    httponly=True,
    samesite="Lax",
    secure=True,  # in production
)
```

```ts
// Express
res.cookie('access_token', pair.accessToken, {
  httpOnly: true,
  sameSite: 'lax',
  secure: process.env.NODE_ENV === 'production',
})
```

`httpOnly` means JavaScript can't read it — safer against XSS.
`sameSite: 'lax'` means it's sent on top-level GETs from your domain
but not cross-site requests — safer against CSRF.

### Where do I store the refresh token?

**Server-side**, never in the browser. Store it in a database row
keyed by your own session ID. The browser only ever sees the session
ID.

If you put the refresh token in a cookie, you've handed an attacker
30 days of access if they ever steal the cookie.

### Why does `/v1/me` need TWO kinds of auth?

Because Knuckles wants to know:

1. **Which user?** — from the bearer access token (`sub` claim).
2. **Which app is asking?** — from the client headers (`X-Client-Id`).

That second one is for audit logging and rate limiting. Knuckles
won't let App A use App B's user tokens to learn about users — the
audience claim has to match.

### My access token expired and the user got bounced. What do I do?

Wire up silent refresh — see the [recipe](recipes.html#refresh-the-access-token-silently).
The pattern: catch `TokenError`, call `tokens.refresh(...)` with the
stored refresh token, get a new pair, retry the original request.

The user never sees the round trip.

### Can I extend the access token's lifetime?

Yes — set `KNUCKLES_ACCESS_TOKEN_TTL_SECONDS`. The default is 3600 (1
hour); you can go up to a few hours. **Don't go above 24h** — a
longer lifetime means a longer window where a stolen token works
without refresh.

### What if I don't want refresh tokens at all?

You can ignore them. Just discard the `refresh_token` from each
sign-in response. When the access token expires, the user signs in
again. This is fine for low-traffic admin dashboards where users
don't mind re-authing daily.

For consumer apps, do silent refresh — users will hate signing in
every hour.

### How do I add Knuckles to an app that already has user auth?

Two phases:

1. **Mirror users.** When someone signs in via Knuckles, look up
   their email in your existing `users` table. If a row exists, link
   the Knuckles `user_id` to your user record. If not, create a new
   row.

2. **Migrate flows.** Replace your sign-in routes with the Knuckles
   ceremonies. Existing sessions keep working until they expire; new
   sessions are issued by Knuckles.

You can run both auth systems in parallel for a while — they don't
conflict.

---

## Security

### Is my deployment safe by default?

The defaults are sensible:
- RS256 signing, not HS256.
- Refresh-token rotation with reuse detection.
- Tokens at rest are SHA-256 hashes, not plaintext.
- Magic-link rate-limiting per email.
- Origin validation on every redirect.

The things you have to do yourself:
- Use HTTPS in production.
- Set `KNUCKLES_STRICT_CORS=true` if you don't want strangers' apps
  hitting your Knuckles instance.
- Rotate `KNUCKLES_STATE_SECRET` and your signing key on a schedule
  (every 6 months is a fine cadence).

### What happens if a user's refresh token leaks?

Whoever has the leaked token can call `/v1/token/refresh` once. After
that:
- They get a new refresh token, the old one is invalid.
- The legitimate user, on their next refresh attempt, presents the
  *now-invalid* old token — Knuckles detects the reuse and revokes
  every refresh token for that user.
- Both attacker and legitimate user get signed out. The attacker's
  access token still works for up to 1 hour, but they can't refresh.

That's why short access-token lifetimes matter.

### What if my Knuckles signing key leaks?

Treat as a serious incident:
1. Generate a new keypair with a new `kid` immediately.
2. Add the new public key to JWKS alongside the old one.
3. Switch `KNUCKLES_JWT_PRIVATE_KEY` and `KNUCKLES_JWT_KEY_ID` to
   the new key.
4. **Drop the old key from JWKS.** This is the bit that invalidates
   every token signed by the leaked key.
5. Force-log-out all users (revoke every refresh token):
   ```sql
   UPDATE refresh_tokens SET used_at = now() WHERE used_at IS NULL;
   ```

After this, every user signs in again. Painful but contains the
damage.

### Can I add multi-factor auth?

Not yet, but passkeys are MFA-equivalent (something you have +
biometric/PIN). For TOTP / SMS / email-based MFA, that would be a
feature request — open an issue.

---

## Operations

### Is there a UI for managing app-clients?

No, by design. The `app_clients` table is small (one row per app),
and the script `scripts/register_app_client.py` covers
register-and-rotate. If you want a UI, building one over that
script is straightforward — but it's not in the scope of Knuckles
itself.

### How do I monitor Knuckles?

Three things to watch:
1. **Healthcheck**: `GET /health` returns 200.
2. **JWKS reachable**: `GET /.well-known/jwks.json` returns 200 with
   non-empty `keys[]`.
3. **Audit log warnings**: search for `refresh_token_reused` in your
   logs — those are real security signals.

### Knuckles is on fire, what do I do first?

Same as any web service:
1. Check the platform dashboard — is it OOM? Restarting?
2. Check `DATABASE_URL` — is Postgres up?
3. Check the most recent deploy — roll back if you can.

For sign-in outages specifically: existing tokens still work for up
to 1 hour because apps verify locally. You have time to fix things
without users noticing.

### Can I migrate to a different identity provider later?

Yes, but it's a project. The migration shape:
1. Stand up the new provider.
2. Add a "link" page to your app where users sign in with both old
   and new — this writes a mapping.
3. Once enough users have linked, switch primary auth to the new
   provider.
4. Decommission Knuckles.

The user's `sub` will change (different provider, different ID).
Plan for that — most apps key everything off email anyway, which
stays stable.

---

## Anything else?

- **Code questions** → read the source. Knuckles is small (~3000
  lines) and Python-readable.
- **Bug reports** → [GitHub Issues](https://github.com/gsooter/knuckles/issues).
- **Contributing** → PRs welcome. See `CLAUDE.md` for the codebase
  conventions before sending one.

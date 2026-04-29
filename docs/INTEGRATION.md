---
title: Integration
layout: default
nav_order: 5
has_children: true
description: "Add Knuckles to your existing app. Pick a language and follow along."
---

# Integration
{: .no_toc }

You have Knuckles running. Now you want your app to use it. This
page is the overview — read it once, then jump to your language.

<details open markdown="block">
<summary>Table of contents</summary>

1. TOC
{:toc}

</details>

---

## What you're about to do

Three pieces:

1. **Drive a sign-in ceremony.** Your app starts a sign-in flow,
   sends the user through Google / Apple / passkey / magic-link, and
   gets a `(access_token, refresh_token)` pair back from Knuckles.
2. **Verify access tokens on every request.** Your app reads the
   bearer token from each incoming request and checks it locally
   against Knuckles' public key. No network call per request.
3. **Refresh + log out.** When the access token expires, your app
   trades the refresh token for a new pair. When the user logs out,
   your app revokes the refresh token.

That's the whole shape. Each language SDK packages all three.

---

## What's an "SDK"?

If you've never seen the term: an **SDK** is "a library you install
that wraps an API." Instead of writing curl-equivalents in your code,
you call functions like `knuckles.google.start(...)` and the SDK
handles the HTTP, the JSON shapes, the error codes, the JWT
verification, and the JWKS caching.

Knuckles ships two SDKs:

| Stack | Package | Install |
|---|---|---|
| Python | `knuckles-client` | `pip install knuckles-client` |
| Node / TypeScript | `@knuckles/client` | `npm install @knuckles/client` |

Both are open source — sources at
[`packages/knuckles-client-py/`](https://github.com/gsooter/knuckles/tree/main/packages/knuckles-client-py)
and
[`packages/knuckles-client-ts/`](https://github.com/gsooter/knuckles/tree/main/packages/knuckles-client-ts).

If your backend is in something else (Go, Ruby, Rust, etc.), you
can hand-roll a client against the [OpenAPI spec](api/) — it's a
standard `application/json` REST API.

---

## The four sign-in methods, in shape

All four ceremonies have the same shape: **start, then complete.**

```
                     YOUR APP                   KNUCKLES
                     --------                   --------

[user clicks Sign in with X]
                     ──── start() ────────────►
                     ◄──── { authorize_url } ──

[redirect user to authorize_url]
[user is at provider — Google, Apple, etc.]
[provider redirects user back to your callback]

[your callback gets ?code=...&state=...]
                     ──── complete(code,state) ►
                     ◄──── { tokens } ─────────

[store tokens in your session, user is signed in]
```

Magic-link is slightly different: instead of redirecting through a
provider, Knuckles emails the user a link. They click it, your
callback gets `?token=...`, and you call
`magic_link.verify(token)` instead of `complete(...)`.

Passkey sign-in skips the redirect entirely: the user's device does
the cryptographic handshake right in the page, and your frontend
posts the result to your backend, which calls `passkey.sign_in_complete(...)`.

---

## The trust pattern: secret on the backend, token in the cookie

Knuckles distinguishes two kinds of authentication:

- **Client auth** = `X-Client-Id` + `X-Client-Secret` headers. Proves
  *the app* is allowed to call Knuckles. **The secret never leaves
  your backend.** All Knuckles calls go through your server, never
  directly from the browser.
- **Bearer auth** = `Authorization: Bearer <access-token>`. Proves
  *the user* is signed in. The token is given to your frontend
  inside an HTTP-only same-site cookie.

When a request hits your backend with both, your backend reads:
- *Which user?* from the bearer token (verify the JWT).
- *Authorize the call to Knuckles?* with the client headers from your
  env vars.

Some endpoints (like `/v1/me`) need **both**.

---

## Where to verify tokens

```
[ user clicks something ]
        ↓
[ your backend gets a request with Authorization: Bearer ... ]
        ↓
[ your backend verifies the JWT locally    ← THIS IS NEW
  using the cached public key from JWKS ]
        ↓
[ your backend serves the request, knowing it's Alice ]
```

**Locally** is the important word. Your backend fetches Knuckles'
public key once on startup (or first request), caches it forever, and
verifies signatures with that cached key. Verifying a token is just
a few microseconds of CPU — no network involved.

If Knuckles is down, your app keeps verifying tokens just fine. New
sign-ins won't work, but existing sessions are unaffected.

The SDK handles all of this in `verify_access_token()` /
`verifyAccessToken()` — you don't have to write the JWKS fetching or
caching yourself.

---

## Cookie storage 101

You'll store two things in the browser:

1. **Access token** (1h). Goes in an **HTTP-only**, **same-site**
   cookie so your JavaScript can't read it (which means a malicious
   script injected into your page also can't steal it).
2. **Refresh token** (30d). **Don't put this in the browser.** Store
   it server-side in your own session table, keyed by the access
   token's `sub` or by your own session ID. The browser only ever
   sees a session cookie that points at your server-side row.

When the access token expires:
- The browser sends the now-expired access token.
- Your backend's middleware sees it's expired, looks up the
  server-side refresh token, calls `client.refresh(refresh_token)`,
  gets a new pair, sets the new access token cookie, stores the new
  refresh token, and retries the request.

This is the **"silent refresh"** pattern. The user never sees an
auth prompt — their session just keeps working.

---

## Error handling, in three buckets

Every Knuckles error surfaces as a typed exception:

| What happened | Exception | How to detect | What your app should do |
|---|---|---|---|
| Refresh token was already used | `KnucklesAuthError` | `exc.code == "REFRESH_TOKEN_REUSED"` | Sign the user out everywhere. Surface "you've been signed out for security reasons." |
| Refresh token's 30 days elapsed | `KnucklesAuthError` | `exc.code == "REFRESH_TOKEN_EXPIRED"` | Send the user back to the sign-in page. |
| Access token is invalid / expired | `KnucklesTokenError` | catch by class | Try a refresh. If that also fails, send to sign-in. |
| User typed magic-link email too fast | `KnucklesRateLimitError` | catch by class | Show "try again in a minute." |
| Bad input (caller's fault) | `KnucklesValidationError` | catch by class | Treat as a bug. Don't surface to the user. |
| Knuckles unreachable | `KnucklesNetworkError` | catch by class | Retry with backoff. Fail closed for protected resources. |

Refresh-token reuse and expiry both come back as `KnucklesAuthError`
— you switch on `exc.code` (Python) or `err.code` (TS) to tell them
apart. The full code vocabulary lives in
`knuckles/core/exceptions.py` (e.g., `INVALID_CLIENT`,
`MAGIC_LINK_EXPIRED`, `PASSKEY_AUTH_FAILED`).

The SDKs raise these with the same names and the same shape across
Python and TypeScript.

---

## Pick your language

- 🐍 **[Python integration walkthrough](python.html)** — full
  Flask example with route protection, sign-in callbacks, and
  silent refresh.
- 🟦 **[TypeScript integration walkthrough](typescript.html)** —
  full Express / Next.js example with the same coverage.

Both walkthroughs use the same pattern; pick whichever matches your
stack.

---

## Reference examples

If you'd rather read finished code than a walkthrough:

* [`examples/nextjs-app/`](https://github.com/gsooter/knuckles/tree/main/examples/nextjs-app) —
  Next.js (App Router) sign-in page, Google + magic-link callbacks,
  server-side `/me` route.
* [`examples/express-middleware/`](https://github.com/gsooter/knuckles/tree/main/examples/express-middleware) —
  Express middleware that validates Knuckles bearer tokens, ~30 lines.
* [`examples/python-flask/`](https://github.com/gsooter/knuckles/tree/main/examples/python-flask) —
  Same shape as the Express example, for Flask.

---

## Hand-rolling a client (no SDK)

If your backend is in a language without a Knuckles SDK, you can
talk to the HTTP API directly. You'll want to implement:

1. **JWKS fetching + caching.** GET
   `/.well-known/jwks.json`, cache it for an hour or so, refresh on
   `kid` mismatch.
2. **JWT verification.** Use any RS256-capable JWT library. Verify
   `iss` matches your Knuckles base URL, `aud` matches your
   `client_id`, `exp` is in the future.
3. **The seven endpoints you actually need:** `magic-link/start`,
   `magic-link/verify`, `google/start`, `google/complete`,
   `apple/start`, `apple/complete`, `token/refresh`. (Add the
   passkey four if you want passkeys.)

The full schema is in [`docs/openapi.yaml`](api/) — drop it into
[Swagger Editor](https://editor.swagger.io) or generate a client with
[`openapi-generator`](https://openapi-generator.tech).

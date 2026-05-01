---
title: Error reference
layout: default
nav_order: 7
description: "Every error code Knuckles can return — what it means, what your app should do, common causes."
---

# Error reference
{: .no_toc }

Every Knuckles HTTP response that isn't a 2xx carries a structured
error envelope. This page lists every code Knuckles can emit, when
you'll see it, and how to recover.

<details open markdown="block">
<summary>Table of contents</summary>

1. TOC
{:toc}

</details>

---

## Anatomy of a Knuckles error response

Every error response — from a 400 validation failure to a 500
unexpected exception — has the same shape:

```json
{
  "error": {
    "code": "REFRESH_TOKEN_REUSED",
    "message": "Refresh token has already been used."
  },
  "meta": {
    "request_id": "9f8d6b7e-2c3a-4f1e-9b8a-1d2c3e4f5a6b"
  }
}
```

| Field | What it's for |
|---|---|
| `error.code` | Machine-readable. Switch on this to choose recovery behavior. The full vocabulary is below. |
| `error.message` | Human-readable. Safe to log; **do not** show raw to users — translate to your own UI copy. |
| `meta.request_id` | A UUID identifying this exact request. Quote it when reporting an issue — the operator can grep their server logs for it and find the full context. Also returned as the `X-Request-Id` response header on every response (success or failure). |

Every response — including successful ones — also carries `X-Request-Id`
in the response headers. If you set the `X-Request-Id` header on your
request, Knuckles echoes it back instead of generating a new one,
letting you correlate across systems.

---

## Reading errors in the SDK

```python
from knuckles_client.exceptions import KnucklesAuthError

try:
    pair = client.refresh(stored_refresh)
except KnucklesAuthError as exc:
    print(exc.code)         # "REFRESH_TOKEN_REUSED"
    print(exc.message)      # "Refresh token has already been used."
    print(exc.request_id)   # "9f8d6b7e-..."
    print(exc.status_code)  # 401
    log.warning("knuckles failed: %s", exc)  # includes request_id
```

The TypeScript SDK exposes the same fields:

```ts
catch (err) {
  if (err instanceof KnucklesAuthError) {
    console.log(err.code, err.message, err.requestId, err.statusCode)
  }
}
```

---

## How to log errors well

Bad: `log.error("auth failed")` — operator has nothing to go on.

OK: `log.error("auth failed: %s", exc.code)` — operator knows the
class but not the instance.

Good: `log.error("auth failed: %s (request_id=%s)", exc, exc.request_id)`
— operator can grep their Knuckles logs for the request id and find
the matching server-side context. Or just `log.error("%s", exc)` —
the SDK already includes the request id in `str(exc)` since 0.1.1.

---

## Error code vocabulary

Codes are stable contracts — once shipped, a code's meaning does not
change. New codes are additive. If your switch sees an unknown code,
fall through to a generic "auth failed" handler — don't crash.

### Authentication & client identity

| Code | HTTP | When you see it | What to do |
|---|---|---|---|
| `INVALID_CLIENT` | 401 | Wrong / missing `X-Client-Id` or `X-Client-Secret` headers; the headers don't match a registered `app_clients` row. | Verify your env vars match what Knuckles' admin gave you. Rotate if you suspect leak. |
| `UNAUTHORIZED` | 401 | A bearer-required endpoint was called without an `Authorization: Bearer …` header, OR the bearer was malformed. | Send the access token. |
| `FORBIDDEN` | 403 | The caller is authenticated but not allowed to perform this action — e.g., trying to delete another user's passkey. | Surface as a permission denial; do not retry. |
| `INVALID_TOKEN` | 401 | The bearer access token failed verification (signature, issuer, audience, or expiry). | Try a refresh; if that fails, re-authenticate. |
| `TOKEN_EXPIRED` | 401 | The bearer access token's `exp` claim is in the past. | Refresh the access token via `client.refresh(refresh_token)`. |

### Refresh-token lifecycle

| Code | HTTP | When you see it | What to do |
|---|---|---|---|
| `REFRESH_TOKEN_INVALID` | 401 | The refresh token doesn't match any row in `refresh_tokens`. | Re-authenticate the user. |
| `REFRESH_TOKEN_EXPIRED` | 401 | The refresh token's 30-day window has elapsed. | Re-authenticate the user. |
| `REFRESH_TOKEN_REUSED` | 401 | A refresh token was presented twice. **Knuckles has revoked every refresh token for this user as a security response.** | Sign the user out everywhere they had sessions; show "you've been signed out for security." |
| `INVALID_GRANT` | 400 | The refresh token is structurally valid but was issued for a different `app_client_id`. | Verify the token was issued to your app. |

### Magic-link

| Code | HTTP | When you see it | What to do |
|---|---|---|---|
| `MAGIC_LINK_INVALID` | 400 | Token in the URL doesn't match any active magic-link row. | Treat as a bad/old link — show "ask for a new sign-in link." |
| `MAGIC_LINK_EXPIRED` | 400 | The token was valid but its 15-minute window elapsed. | Same as above — request a fresh link. |
| `MAGIC_LINK_ALREADY_USED` | 400 | The token already redeemed a session. | Same — request a fresh link. |
| `EMAIL_DELIVERY_FAILED` | 502 | Resend rejected the send (unverified domain, malformed `from`, suspended account, etc.). | The error message contains Resend's reason. Most often: domain not verified in Resend, or `RESEND_FROM_EMAIL` doesn't match a verified domain. |
| `RATE_LIMITED` | 429 | Per-email magic-link rate limit hit (default 5/hour/email). | Surface a friendly "try again in a few minutes" message; do not retry automatically. |

### OAuth (Google + Apple)

The OAuth services compress a lot of distinct failure modes onto two
codes. The `error.message` field carries the actual upstream reason
where one is available.

| Code | HTTP | When you see it | What to do |
|---|---|---|---|
| `GOOGLE_AUTH_FAILED` | 400 / 502 | Anything that broke during the Google flow. The message names the specific cause: state expired/forged, network failure to Google, Google rejected the code (with Google's `error` and `error_description` propagated), missing `sub`/`email` claim, unverified email. | Read `error.message`. State problems → ask the user to start over. `invalid_grant` → the code was reused or expired; ask the user to start over. Network failures → retry once with backoff. Unverified email → tell the user Google says their email isn't verified. |
| `APPLE_AUTH_FAILED` | 400 / 502 | Same shape for Apple: state failure, network failure, Apple rejected the code, id_token verification failed, missing user payload. | Same triage as above. Check the `error.message` for Apple's `error` / `error_description`. |

### Passkey (WebAuthn)

| Code | HTTP | When you see it | What to do |
|---|---|---|---|
| `PASSKEY_REGISTRATION_FAILED` | 400 / 404 | The credential the browser returned didn't validate against the challenge state, or the user was missing. | Treat as user error — ask them to try registering again. The `error.message` carries the underlying validation detail. |
| `PASSKEY_AUTH_FAILED` | 400 / 404 | The presented credential doesn't match a registered passkey, or the assertion didn't validate. | Surface as "we don't recognize this passkey." Don't retry the same credential. |

### Validation

| Code | HTTP | When you see it | What to do |
|---|---|---|---|
| `VALIDATION_ERROR` | 422 | A required field was missing, malformed, or violated a business rule (bad email, redirect URL not in app-client's `allowed_origins`, etc.). | This is a bug in your integration. Read the message, fix the call site, do not show to end users. |

### User lookup

| Code | HTTP | When you see it | What to do |
|---|---|---|---|
| `USER_NOT_FOUND` | 404 | A user-scoped operation referenced an id that doesn't exist (or was deleted). | Treat as deleted/unknown. Don't retry. |

### Server / fallthrough

| Code | HTTP | When you see it | What to do |
|---|---|---|---|
| `INTERNAL_SERVER_ERROR` | 500 | Knuckles hit an unhandled exception. **The customer-side message is intentionally opaque** ("An unexpected error occurred."). | The full stack trace is in the operator's logs, keyed by the `request_id`. **Quote the request_id when reporting** and the operator can pin down the exact failure. |
| `UNPARSEABLE_RESPONSE` | (n/a — SDK only) | Knuckles returned a non-JSON body where the SDK expected JSON. Typically a load-balancer / proxy intercept (e.g., a 502 page from the platform's edge before reaching Knuckles). | Treat as transient — retry with backoff. If it persists, Knuckles itself may be down. |

---

## When errors don't fit the pattern

A few situations where the customer-facing surface looks slightly
different:

### `RATE_LIMITED` includes a `Retry-After` header

In addition to the JSON body, rate-limited responses carry a
`Retry-After: <seconds>` HTTP header. Honor it; the rate-limit
window is per-email per-hour by default.

### `INTERNAL_SERVER_ERROR` is intentionally opaque

We don't surface the underlying exception details to the consuming
app — a stack trace can leak schema names, file paths, environment
hints. The full trace is logged server-side, keyed by `request_id`.
This is the one place where the `request_id` is essential, not
just helpful.

### Network errors never come from Knuckles

If your SDK raises `KnucklesNetworkError`, Knuckles never received
your request — could be DNS, TLS, a hung connection, the platform's
edge timing out. These exceptions don't have a `code` field because
there was no Knuckles response. Retry with backoff.

---

## Where to find errors in the operator's logs

Every error response logs at WARNING (or ERROR for 500s) with the
exact request id. To find a specific failure in your hosting
provider's logs:

```
grep <request_id>           # or use the platform's log search
```

The log line format is:

```
<timestamp> WARNING knuckles.errors <CODE> [<status>] <message> | request_id=... method=... path=... app_client_id=... user_id=...
```

The same `request_id` appears in both the customer's exception
(`exc.request_id`) and the server's log line — that's the load-bearing
piece for cross-system triage.

---

## What changed when

Error envelope shape and code stability are versioned with the SDK:

- **`knuckles-client` 0.1.0** — error envelope without `meta.request_id`.
- **`knuckles-client` 0.1.1** — `meta.request_id` always present;
  `KnucklesAPIError.request_id` exposed; matching server-side log
  correlation via `X-Request-Id` request and response headers.

Both versions interop with both server versions. Upgrading the SDK
unlocks request-id correlation against a server that supports it
(deployed Knuckles >= the day this was published) and is a no-op
against older servers.

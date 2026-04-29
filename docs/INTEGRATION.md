# Integrating with Knuckles

You're building an app that wants Knuckles to handle sign-in. This
guide is your **shortest path from zero to "users can sign in."**

If you want the full architectural background, read
[`docs/ONBOARDING.md`](./ONBOARDING.md). This page is just enough to
ship.

---

## 1. Get registered

Ask the Knuckles operator to run:

```bash
python scripts/register_app_client.py \
    --client-id <your-app-id> \
    --app-name "<Your App Name>" \
    --allowed-origin https://your-app.example.com \
    --allowed-origin https://staging.your-app.example.com \
    --allowed-origin http://localhost:3000
```

Register **every origin** you'll ever pass as a `redirect_url` —
production, staging, local-dev. Knuckles enforces that the redirect
URL's origin matches one of these.

The operator hands you a `client_id` and a `client_secret`. Store the
secret in your **backend** environment. Never ship it in a browser
bundle.

---

## 2. Pick an SDK

| Stack | Package | Where it lives |
|---|---|---|
| Python backend | `knuckles-client` | [`packages/knuckles-client-py/`](../packages/knuckles-client-py/) |
| Node / TypeScript backend | `@knuckles/client` | [`packages/knuckles-client-ts/`](../packages/knuckles-client-ts/) |
| Anything else | Hand-roll against [`docs/openapi.yaml`](./openapi.yaml) | — |

The SDKs handle the three things you'd otherwise get wrong:

1. **JWKS caching** — `verifyAccessToken` does no network call after
   the first verify on a fresh process.
2. **Refresh-token rotation** — every call returns a new refresh
   token; you store the new one. The SDK doesn't hide this from you,
   but it makes the contract obvious.
3. **Error mapping** — typed exceptions per error code, so
   `REFRESH_TOKEN_REUSED` is a class to catch, not a string to
   match.

---

## 3. Wire the four sign-in paths

All four flows produce the same `TokenPair` shape, so your post-sign-in
code is identical regardless of method.

### Magic-link

Frontend collects an email → backend calls
`client.magic_link.start(email=..., redirect_url=".../auth/verify")`.
Knuckles emails the user. The link points at your verify URL with
`?token=<...>`. Your verify route calls
`client.magic_link.verify(token)` and writes the resulting tokens into
HTTP-only cookies (or whatever your session storage is).

### Google / Apple

Frontend hits a backend route → backend calls
`client.google.start(redirect_url="...")` and returns the
`authorize_url` (or 302s the browser there). The provider redirects
back to your callback URL with `code` + `state`. The backend calls
`client.google.complete(code=..., state=...)` and writes the cookies.

### WebAuthn passkey

Sign-in: backend calls `client.passkey.sign_in_begin()` to get
options, the frontend hands them to `navigator.credentials.get()`,
posts the resulting credential back to the backend, which calls
`client.passkey.sign_in_complete(credential=..., state=...)`.

Registration (user is already signed in): backend calls
`client.passkey.register_begin(access_token=...)`; frontend uses
`navigator.credentials.create()`; backend calls
`client.passkey.register_complete(...)`.

---

## 4. Validate tokens on every API call

```python
# Python
claims = knuckles.verify_access_token(token)
user_id = claims["sub"]
```

```ts
// TypeScript
const claims = await knuckles.verifyAccessToken(token)
const userId = claims.sub
```

The SDK fetches Knuckles' JWKS once per process and verifies tokens
locally — no network cost per request. See the
[Express middleware example](../examples/express-middleware/middleware.ts)
or the [Flask middleware example](../examples/python-flask/middleware.py)
for the full pattern.

---

## 5. Handle the failure modes

| Exception | When it fires | What to do |
|---|---|---|
| `KnucklesAuthError` (`code="REFRESH_TOKEN_REUSED"`) | The refresh token was already used. **Every** refresh token for this user has been revoked. | Log the user out of every device; surface "you've been signed out for security." |
| `KnucklesAuthError` (`code="REFRESH_TOKEN_EXPIRED"`) | Refresh token's 30d window elapsed. | Redirect to sign-in. |
| `KnucklesTokenError` | Access-token signature/audience/issuer/expiry failed locally. | Try a refresh; if that also fails, sign out. |
| `KnucklesRateLimitError` | Magic-link `start` hit the per-email throttle. | Show a friendly "try again in a few minutes" message. |
| `KnucklesValidationError` | The SDK or the caller passed bad input. | Treat as a bug — should not reach end users. |
| `KnucklesNetworkError` | Knuckles unreachable. | Retry with backoff; fail closed for protected resources. |

---

## 6. Reference examples

* [`examples/nextjs-app/`](../examples/nextjs-app/) — Next.js (App
  Router) sign-in page, Google + magic-link callbacks, server-side
  `/me` route.
* [`examples/express-middleware/`](../examples/express-middleware/) —
  ~30 line Express middleware that validates Knuckles bearer tokens.
* [`examples/python-flask/`](../examples/python-flask/) — Same shape
  as the Express example, but for Flask.

---

## 7. Get the OpenAPI spec

For tooling that auto-generates clients, validates contracts, or
renders docs UIs:

[`docs/openapi.yaml`](./openapi.yaml) — OpenAPI 3.1, every public
endpoint, every request/response shape, the full error-code
vocabulary as an enum. Drop into Swagger UI / Redoc / Stoplight to
get a hosted reference.

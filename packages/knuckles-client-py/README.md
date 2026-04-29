# knuckles-client

[![PyPI](https://img.shields.io/pypi/v/knuckles-client.svg)](https://pypi.org/project/knuckles-client/)
[![Python versions](https://img.shields.io/pypi/pyversions/knuckles-client.svg)](https://pypi.org/project/knuckles-client/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Type checked](https://img.shields.io/badge/typed-mypy%20strict-blue.svg)](https://mypy.readthedocs.io)

Python SDK for the **[Knuckles](https://github.com/gsooter/knuckles)**
identity service. Knuckles handles user accounts, sign-in ceremonies
(magic-link, Google, Apple, WebAuthn passkey), and JWT issuance for a
fleet of consuming applications. This package is what those
applications import.

> **Why an SDK?** The three things consuming apps get wrong by default
> are: forgetting `audience` verification on JWTs, forgetting to swap
> in the rotated refresh token after a refresh, and treating
> `REFRESH_TOKEN_REUSED` as a generic 401 instead of a "revoke
> everything" signal. The SDK encodes all three correctly so you don't
> have to.

---

## Table of contents

- [Install](#install)
- [Quick start](#quick-start)
- [Concepts in 30 seconds](#concepts-in-30-seconds)
- [The full API](#the-full-api)
- [Token verification, in depth](#token-verification-in-depth)
- [Refresh-token rotation, in depth](#refresh-token-rotation-in-depth)
- [Exception handling](#exception-handling)
- [Configuration reference](#configuration-reference)
- [Recipes](#recipes)
  - [Flask middleware](#flask-middleware)
  - [FastAPI dependency](#fastapi-dependency)
  - [Django middleware](#django-middleware)
- [Versioning policy](#versioning-policy)
- [Compatibility matrix](#compatibility-matrix)
- [Development](#development)

---

## Install

```bash
pip install knuckles-client
```

Supports Python 3.11+. Pure Python — no compiled extensions, no
platform-specific wheels.

## Quick start

```python
from knuckles_client import KnucklesClient

knuckles = KnucklesClient(
    base_url="https://auth.example.com",   # your Knuckles deployment
    client_id="my-app",                     # the client_id you registered
    client_secret="...",                    # NEVER ship this in a browser bundle
)

# 1. Verify an access token locally — JWKS-cached, no network after warmup.
claims = knuckles.verify_access_token(access_token)
user_id = claims["sub"]

# 2. Drive a sign-in ceremony.
auth = knuckles.google.start(redirect_url="https://my-app/auth/google/callback")
# ... your frontend redirects the browser to auth.authorize_url ...
# ... Google redirects back to your callback with ?code=...&state=... ...
pair = knuckles.google.complete(code=code, state=auth.state)

# 3. Hand the user their session — store however you store sessions.
print(pair.access_token)            # short-lived RS256 JWT
print(pair.refresh_token)           # opaque, rotates on every use

# 4. When the access token nears expiry, rotate.
new_pair = knuckles.refresh(pair.refresh_token)
# IMPORTANT: store new_pair.refresh_token. The old one is now consumed.
```

## Concepts in 30 seconds

- **One client per process.** The `KnucklesClient` holds an HTTP
  session (connection pool) and a JWKS cache. Construct it once at
  startup; reuse it everywhere.
- **App-client credentials live on your backend.** The `client_id` is
  public-ish, the `client_secret` is treated like any other server
  secret. Browsers never see the secret.
- **The user's tokens are what you store.** After a successful
  ceremony you get a `TokenPair`. Where you put it (HTTP-only cookie,
  database row, native keychain) is your application's choice.
- **Access tokens are validated locally.** `verify_access_token`
  caches Knuckles' public keys (JWKS) and verifies signatures
  in-process. No per-request network hop to Knuckles.
- **Refresh tokens rotate on every use.** Always store the *new*
  refresh token from a refresh response. Re-presenting a consumed
  refresh token is treated as a security incident — see below.

## The full API

| Method | Returns | Notes |
|---|---|---|
| `client.verify_access_token(token)` | `dict[str, Any]` | Local. Raises `KnucklesTokenError` on any failure. |
| `client.refresh(refresh_token)` | `TokenPair` | Always store the new refresh token from the response. |
| `client.logout(refresh_token)` | `None` | Idempotent; unknown tokens succeed silently. |
| `client.logout_all(access_token=...)` | `int` | Revokes every refresh token for the user. Returns count. |
| `client.me(access_token=...)` | `UserProfile` | Current user's profile from `/v1/me`. |
| `client.fetch_jwks()` | `dict[str, Any]` | Raw JWKS body, mostly for debugging. |
| `client.fetch_openid_configuration()` | `dict[str, Any]` | Partial OIDC discovery doc. |
| `client.magic_link.start(email=, redirect_url=)` | `None` | Sends the email. May raise `KnucklesRateLimitError`. |
| `client.magic_link.verify(token)` | `TokenPair` | Redeems the token from the email. |
| `client.google.start(redirect_url=)` | `CeremonyStart` | Returns `authorize_url` + `state`. |
| `client.google.complete(code=, state=)` | `TokenPair` | Finishes Google ceremony. |
| `client.apple.start(redirect_url=)` | `CeremonyStart` | |
| `client.apple.complete(code=, state=, user=None)` | `TokenPair` | Pass `user` only on first sign-in for that Apple ID. |
| `client.passkey.sign_in_begin()` | `PasskeyChallenge` | Discoverable-credential flow; no bearer needed. |
| `client.passkey.sign_in_complete(credential=, state=)` | `TokenPair` | |
| `client.passkey.register_begin(access_token=)` | `PasskeyChallenge` | User must be signed in. |
| `client.passkey.register_complete(access_token=, credential=, state=, name=None)` | `str` (credential id) | |
| `client.passkey.list(access_token=)` | `list[PasskeyDescriptor]` | |
| `client.passkey.delete(access_token=, credential_id=)` | `None` | Ownership-checked. |

## Token verification, in depth

```python
claims = knuckles.verify_access_token(token)
```

What the SDK does, in order:

1. Fetches `{base_url}/.well-known/jwks.json` once per process and
   caches the public keys in-memory (via `jwt.PyJWKClient`).
2. Parses the JWT header to find its `kid`, looks up the matching
   public key from the cache.
3. Verifies the RS256 signature.
4. Verifies the `iss` claim equals your `base_url`.
5. Verifies the `aud` claim equals your `client_id`.
6. Verifies `iat`, `exp`, `sub` are present and `exp` is in the
   future.
7. Returns the decoded claims dict.

Any failure raises `KnucklesTokenError`. The SDK does *not*
automatically refresh the token — that's a higher-level decision
your app makes (you may want to refresh, or you may want to require
re-authentication).

## Refresh-token rotation, in depth

Knuckles uses one-shot rotating refresh tokens. The contract:

- Every successful refresh returns a *new* refresh token. Store it
  immediately, replacing the old one.
- The old refresh token is now consumed. Presenting it again is the
  signal of a leak — Knuckles revokes every refresh token for the
  user and returns `REFRESH_TOKEN_REUSED`.

Correct usage:

```python
from knuckles_client import KnucklesAuthError

def get_valid_access_token(session) -> str:
    """Return a usable access token, refreshing if needed."""
    try:
        knuckles.verify_access_token(session.access_token)
        return session.access_token
    except KnucklesTokenError:
        pass  # expired or invalid — try a refresh

    try:
        pair = knuckles.refresh(session.refresh_token)
    except KnucklesAuthError as exc:
        if exc.code == "REFRESH_TOKEN_REUSED":
            # SECURITY EVENT — every session for this user has been
            # revoked server-side. Sign them out everywhere.
            session.delete()
            raise SessionRevokedError() from exc
        # Otherwise: refresh expired or invalid — sign out, redirect to login.
        session.delete()
        raise SignInRequiredError() from exc

    session.access_token = pair.access_token
    session.refresh_token = pair.refresh_token   # <-- the rotation
    session.save()
    return pair.access_token
```

## Exception handling

```
KnucklesError                       # base for everything the SDK raises
├── KnucklesNetworkError            # transport failure / non-JSON response
├── KnucklesTokenError              # local JWKS verification failed
└── KnucklesAPIError                # Knuckles returned a typed error
    ├── KnucklesAuthError           # 401 / 403
    ├── KnucklesValidationError     # 422
    └── KnucklesRateLimitError      # 429
```

Every `KnucklesAPIError` carries `.code`, `.message`, `.status_code`.
Codes that warrant special handling:

| Code | What it means | What to do |
|---|---|---|
| `REFRESH_TOKEN_REUSED` | A consumed refresh token was presented again. **Every** refresh token for this user has been revoked. | Sign user out across every device. Force re-authentication. |
| `REFRESH_TOKEN_EXPIRED` | 30-day lifetime elapsed. | Redirect to sign-in. |
| `REFRESH_TOKEN_INVALID` | Token unknown to Knuckles. | Same as expired. |
| `INVALID_CLIENT` | Wrong `client_id`/`client_secret`, or refresh token issued for a different app. | Configuration bug — log loudly. |
| `RATE_LIMITED` | Per-email throttle on magic-link sends. | Surface a friendly retry message. |
| `MAGIC_LINK_*` | Token bad / expired / used. | Show "this link is no longer valid; request a new one." |
| `*_AUTH_FAILED` | Provider-side ceremony failure. | Show a generic "couldn't sign you in with that method" and offer alternatives. |

Other codes are bugs in your integration or in Knuckles itself — log
the full exception (`code`, `message`, `status_code`) and treat as 5xx.

## Configuration reference

```python
KnucklesClient(
    base_url: str,                 # required
    client_id: str,                # required
    client_secret: str,            # required
    timeout: float = 10,           # per-request HTTP timeout, seconds
    session: requests.Session | None = None,  # bring your own pool / proxy / retries
)
```

- **`base_url`** — exact origin Knuckles publishes itself as (also the
  `iss` claim it embeds in tokens). No trailing slash.
- **`client_id`** — used as the JWT `aud` Knuckles embeds. The SDK
  also enforces it on every `verify_access_token` call.
- **`client_secret`** — sent as `X-Client-Secret` on every request
  that needs app-client auth. Keep it server-side.
- **`timeout`** — per-call timeout. Knuckles ceremonies talk to
  Google/Apple over the network, so leaving headroom (10s default) is
  reasonable.
- **`session`** — pass in a pre-built `requests.Session` to add
  retries (`requests.adapters.HTTPAdapter`), proxies, custom CAs,
  observability hooks, etc.

## Recipes

### Flask middleware

```python
from flask import Flask, g, jsonify, request
from knuckles_client import KnucklesClient, KnucklesTokenError

app = Flask(__name__)
knuckles = KnucklesClient(base_url=..., client_id=..., client_secret=...)

@app.before_request
def authenticate():
    if request.endpoint in {"login", "static"}:
        return
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return jsonify({"error": "missing_bearer"}), 401
    try:
        claims = knuckles.verify_access_token(header.split(" ", 1)[1])
    except KnucklesTokenError:
        return jsonify({"error": "invalid_token"}), 401
    g.user_id = claims["sub"]
```

### FastAPI dependency

```python
from fastapi import Depends, FastAPI, Header, HTTPException
from knuckles_client import KnucklesClient, KnucklesTokenError

app = FastAPI()
knuckles = KnucklesClient(base_url=..., client_id=..., client_secret=...)

def current_user(authorization: str = Header(...)) -> str:
    if not authorization.startswith("Bearer "):
        raise HTTPException(401, "missing_bearer")
    try:
        claims = knuckles.verify_access_token(authorization[7:])
    except KnucklesTokenError as exc:
        raise HTTPException(401, str(exc)) from exc
    return claims["sub"]

@app.get("/me")
def me(user_id: str = Depends(current_user)):
    return {"user_id": user_id}
```

### Django middleware

```python
from django.http import JsonResponse
from knuckles_client import KnucklesClient, KnucklesTokenError

knuckles = KnucklesClient(base_url=..., client_id=..., client_secret=...)

class KnucklesAuthMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        header = request.headers.get("Authorization", "")
        if header.startswith("Bearer "):
            try:
                claims = knuckles.verify_access_token(header[7:])
                request.user_id = claims["sub"]
            except KnucklesTokenError:
                return JsonResponse({"error": "invalid_token"}, status=401)
        return self.get_response(request)
```

## Versioning policy

- **0.x is pre-stable.** Read [`CHANGELOG.md`](./CHANGELOG.md) before
  upgrading minor versions; method signatures may change.
- **1.0+ follows strict semver.** Breaking changes require a major
  version bump.
- **Pin in production.** `knuckles-client==0.1.0` in your
  requirements file is the right move at this stage.

## Compatibility matrix

| `knuckles-client` | Knuckles server API | Python |
|---|---|---|
| 0.1.x | v1 (every route registered under `/v1/...` as of 2026-04) | 3.11, 3.12, 3.13 |

If your Knuckles deployment is older than the SDK targets, calls to
new endpoints (e.g. `/v1/auth/passkey` GET) will return 404. Upgrade
the server first.

## Development

The SDK lives in the [Knuckles monorepo](https://github.com/gsooter/knuckles)
under `packages/knuckles-client-py/`.

```bash
# From a Knuckles checkout
cd packages/knuckles-client-py
pip install -e ".[dev]"
pytest
ruff check .
mypy src
```

The test suite mocks Knuckles' HTTP layer with the `responses`
library and the JWKS verifier with a hand-rolled fake. No live
Knuckles instance needed.

## License

MIT — see [`LICENSE`](./LICENSE).

# CLAUDE.md — Knuckles

This file defines non-negotiable rules for every change to Knuckles.
Read it fully before writing any code. When in doubt, check here first.

---

## What Knuckles Is

Knuckles does exactly one thing: **verify identity and issue JWTs**.

Consuming applications (Greenroom is the first) send users here to sign
in, and get back RS256-signed access tokens + rotating refresh tokens.
Apps validate tokens locally against the public JWKS Knuckles publishes
— they never call Knuckles per-request.

---

## The One Hard Rule That Matters Most

**Knuckles never handles music service OAuth.** Not Spotify, not Apple
Music, not Tidal, not any music service that has ever existed or will
ever exist. If you are adding one of these to Knuckles, you are
violating this rule and the change must be rejected at review.

Music-service connections are a **Greenroom** concern:
- Greenroom has its own `music_service_connections` table.
- Greenroom has its own OAuth routes under `api/v1/music/`.
- Greenroom's settings page manages connect/disconnect.
- Knuckles is never involved.

If a user is signed in via Knuckles and also has a Spotify connection
in Greenroom, the relationship between those two records lives
entirely inside Greenroom. Knuckles knows the user id; it does not
know what services that user has connected. Do not build a
`connected_services.py`, a `services.py` route file, or any endpoint
under `/v1/services/*`. They do not exist in Knuckles by design.

The same rule applies to any other product-specific integration a
future consuming app might want. Knuckles stays identity-only forever.

---

## Absolute Rules — Never Violate These

1. **No business logic in route handlers.** Routes validate input and
   call service functions. All logic lives in the service layer.

2. **No raw SQL outside of repository functions.** All database access
   goes through repository modules in `knuckles/data/repositories/`.

3. **Every function has a Google-style docstring and full type hints.**
   No exceptions, including private helpers. See the Docstrings & Type
   Hints section below.

4. **Every public API endpoint has a corresponding pytest test.**
   Tests first — write the failing test before the implementation.

5. **No hardcoded secrets, URLs, or environment-specific values in
   code.** All configuration comes from environment variables via
   `knuckles/core/config.py`.

6. **Conventional Commits for all commit messages.**
   Format: `type(scope): description`
   Types: `feat`, `fix`, `refactor`, `test`, `docs`, `chore`, `perf`
   Examples:
   - `feat(auth): add magic-link verify endpoint`
   - `fix(jwt): reject tokens with wrong issuer`
   - `test(passkey): cover reuse detection on sign count`

7. **No `any` in TypeScript (if/when a web UI ships). No untyped
   Python function signatures.** Fix the type, don't suppress.

8. **Every layer respects the import hierarchy:**

   | Layer | Can import from | Cannot import from |
   |---|---|---|
   | `api/` | `services/`, `core/` | `data/` directly |
   | `services/` | `data/`, `core/` | `api/` |
   | `data/` | `core/` | `services/`, `api/` |

9. **Every migration is reversible.** Always implement `downgrade()`.

10. **Never add a music service.** See the Hard Rule above.

11. **Native-enum columns must pin `values_callable`.** Whenever a
    SQLAlchemy `Enum(...)` column is backed by a PostgreSQL native
    enum (`native_enum=True`), pass
    `values_callable=lambda enum_cls: [e.value for e in enum_cls]`
    so SQLAlchemy sends the member *values* to Postgres rather than
    the member *names*. Without it, a Python enum like
    `OAuthProvider.GOOGLE = "google"` ends up writing `"GOOGLE"` to
    a column whose DB enum type allows only `"google"` — a 500 at
    insert time that slips past unit tests because SQLite ignores
    the native enum constraint.

---

## Architecture

```
knuckles/
├── CLAUDE.md
├── DECISIONS.md
├── README.md
├── pyproject.toml
├── .env.example
├── knuckles/
│   ├── app.py                   # Flask application factory
│   ├── core/
│   │   ├── config.py            # Pydantic Settings
│   │   ├── database.py          # SQLAlchemy engine + session
│   │   ├── exceptions.py        # AppError + error codes
│   │   ├── logging.py           # Structured logging
│   │   ├── jwt.py               # RS256 access tokens + JWKS
│   │   ├── state_jwt.py         # HS256 ceremony-state tokens
│   │   └── auth.py              # require_auth decorator
│   ├── data/
│   │   ├── models/
│   │   │   └── auth.py          # Every Knuckles table lives here
│   │   └── repositories/
│   │       └── auth.py          # Every Knuckles query lives here
│   ├── services/
│   │   ├── magic_link.py
│   │   ├── google_oauth.py
│   │   ├── apple_oauth.py
│   │   ├── passkeys.py
│   │   └── tokens.py            # Access + refresh issuance, rotation
│   ├── api/v1/
│   │   ├── __init__.py          # Blueprint
│   │   └── auth.py              # All /v1/auth/* routes
│   └── migrations/              # Alembic
└── tests/
    ├── core/
    ├── data/
    ├── services/
    └── api/
```

**No `services/connected_services.py`. No `api/v1/services.py`.** The
absence of those files is load-bearing — see the Hard Rule.

---

## API Surface (the complete list)

Every consuming-app call uses `X-Client-Id` + `X-Client-Secret`
headers (the **client** column below). User-context calls additionally
need `Authorization: Bearer <access_token>` (the **bearer** column).

- `GET  /health` — no auth
- `GET  /.well-known/jwks.json` — no auth
- `GET  /.well-known/openid-configuration` — no auth (OIDC discovery)
- `GET  /v1/auth/jwks` — no auth (alias of `/.well-known/jwks.json`)
- `POST /v1/auth/magic-link/start` — client
- `POST /v1/auth/magic-link/verify` — client
- `POST /v1/auth/google/start` — client
- `POST /v1/auth/google/complete` — client
- `POST /v1/auth/apple/start` — client
- `POST /v1/auth/apple/complete` — client
- `POST /v1/auth/passkey/register/begin` — bearer
- `POST /v1/auth/passkey/register/complete` — bearer
- `POST /v1/auth/passkey/sign-in/begin` — client
- `POST /v1/auth/passkey/sign-in/complete` — client
- `GET  /v1/auth/passkey` — bearer (list current user's passkeys)
- `DELETE /v1/auth/passkey/<credential_id>` — bearer (delete one)
- `POST /v1/token/refresh` — client
- `POST /v1/logout` — client (revokes the presented refresh token)
- `POST /v1/logout/all` — client + bearer (revokes every refresh token for the user)
- `GET  /v1/me` — client + bearer

(The expired-magic-link cleanup is `scripts/cleanup_magic_links.py`,
not an HTTP endpoint, so the admin attack surface stays at zero.)

Adding a route outside this list requires an entry in `DECISIONS.md`.

---

## Database Tables Knuckles Owns

- `users` — `id`, `email`, `display_name`, `avatar_url`, `is_active`,
  `created_at`, `updated_at`, `last_seen_at`.
- `user_oauth_providers` — `id`, `user_id`, `provider` (**`google` and
  `apple` only — never `spotify`, `apple_music`, `tidal`, or any other
  music service**), `provider_user_id`, `access_token`, `refresh_token`,
  `token_expires_at`, `scopes`, `raw_profile`, `created_at`,
  `updated_at`.
- `magic_link_tokens` — `id`, `user_id`, `token_hash`, `email`,
  `expires_at`, `used_at`, `created_at`.
- `passkey_credentials` — `id`, `user_id`, `credential_id`,
  `public_key`, `sign_count`, `created_at`.
- `app_clients` — `id`, `app_name`, `client_secret_hash`,
  `allowed_origins`, `created_at`.
- `refresh_tokens` — `id`, `user_id`, `app_client_id`, `token_hash`,
  `expires_at`, `used_at`, `created_at`.

No other tables exist in Knuckles. Ever.

---

## Docstrings & Type Hints

Every Python function must have:
- Full type hints on all parameters and return values.
- A Google-style docstring with `Args`, `Returns`, and `Raises` sections
  (Raises only if applicable).

Applies to public functions, private helpers, class methods, static
methods, and property getters. There are no exempt functions.

```python
def issue_access_token(
    *,
    user_id: uuid.UUID | str,
    app_client_id: str,
    scopes: list[str] | None = None,
    email: str | None = None,
) -> str:
    """Mint an RS256 access token for a given user and consuming app.

    Args:
        user_id: Knuckles ``users.id`` to embed as the ``sub`` claim.
        app_client_id: ``app_clients.client_id`` to embed as ``aud``.
        scopes: Optional list of scope strings.
        email: Optional email address to embed in the token.

    Returns:
        A signed JWT string.
    """
```

---

## Python Standards

- **Formatter:** Black, line length 88
- **Linter:** Ruff
- **Type checker:** mypy in strict mode
- **Test framework:** pytest with pytest-cov
- **Minimum test coverage:** 80% across all Knuckles modules. CI blocks merge if below.
- **Python version:** 3.12+
- **Docstring style:** Google — see above.

---

## Environment Variables

All env vars are defined and validated in `knuckles/core/config.py`.
The app fails loudly at startup if a required variable is missing.

Required at startup:
- `DATABASE_URL`
- `KNUCKLES_JWT_PRIVATE_KEY` (base64-encoded PEM)
- `KNUCKLES_JWT_KEY_ID`
- `KNUCKLES_STATE_SECRET`

Identity-path optional (empty means the path is not enabled):
- `RESEND_API_KEY`, `RESEND_FROM_EMAIL`
- `GOOGLE_OAUTH_CLIENT_ID`, `GOOGLE_OAUTH_CLIENT_SECRET`
- `APPLE_OAUTH_CLIENT_ID`, `APPLE_OAUTH_TEAM_ID`,
  `APPLE_OAUTH_KEY_ID`, `APPLE_OAUTH_PRIVATE_KEY`
- `WEBAUTHN_RP_ID`, `WEBAUTHN_RP_NAME`, `WEBAUTHN_ORIGIN`

**No music-service env vars exist in Knuckles.** If a future PR adds
`SPOTIFY_*`, `TIDAL_*`, `APPLE_MUSIC_*`, reject it.

---

## Testing Standards

```bash
pytest --cov=knuckles --cov-fail-under=80
```

- Tests live in `tests/` mirroring the source structure.
- Mock external HTTP (Google token endpoint, Apple token endpoint,
  Resend) in unit tests; integration tests hit a real
  `knuckles_test` Postgres database.
- Never test implementation details — test behavior and outcomes.
- 80% coverage applies across `services/`, `data/repositories/`,
  `core/`, and `api/`.

---

## API Response Standards

### Success
```json
{ "data": {}, "meta": {} }
```

### Error
```json
{ "error": { "code": "TOKEN_EXPIRED", "message": "..." } }
```

All error codes are constants in `knuckles/core/exceptions.py`. Never
return raw exception messages to the client.

---

## Keeping This File Current

`CLAUDE.md` and `DECISIONS.md` are living documents. Keep them accurate
as Knuckles evolves.

**Update CLAUDE.md when:**
- A new layer, module, or directory is added.
- A new tool, framework, or library becomes a Knuckles standard.
- A rule or convention changes.
- A new environment variable is required.

**Update DECISIONS.md when:**
- A significant architectural choice is made.
- A decision here is reversed or modified (mark the old entry
  `Superseded` and add a new one).

Do not wait until the end of a task to update these files. Update them
at the point the decision is made.

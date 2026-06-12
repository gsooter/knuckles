# Changelog

All notable changes to `knuckles-client` are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## Versioning policy

- **0.x releases are pre-stable.** APIs may change between minor
  versions. Pin to an exact version in production and read this file
  before upgrading.
- **Once 1.0.0 ships,** breaking changes require a major version bump.
  Additions are minor bumps. Bug fixes are patch bumps.
- **Each `knuckles-client` release lists the Knuckles server API
  version it targets.** A new server endpoint may require an SDK
  release; an SDK release that calls a missing endpoint will surface
  as a 404 from the server.

## [Unreleased]

_Nothing yet._

## [0.1.2] — 2026-06-12

### Added

- **Account management** under the new `client.me` sub-client (still
  callable — `client.me(access_token=...)` returns the `UserProfile`
  exactly as before):
  - `me.update_profile(access_token=, display_name=..., avatar_url=...)`
    — `PATCH /v1/me`; only the fields you pass are sent, and an
    explicit `None` clears the field server-side.
  - `me.delete_account(access_token=)` — `DELETE /v1/me`.
  - `me.list_providers(access_token=)` — `GET /v1/me/providers`.
  - `me.unlink_provider(access_token=, provider=)` —
    `DELETE /v1/me/providers/{provider}`.
  - `me.start_email_change(access_token=, new_email=, redirect_url=)`
    — `POST /v1/me/email/start`.
  - `me.verify_email_change(token)` — `POST /v1/me/email/verify`
    (client headers only).
- **Sessions** sub-client: `sessions.list(access_token=)`
  (`GET /v1/sessions`) and `sessions.revoke(access_token=, session_id=)`
  (`DELETE /v1/sessions/{session_id}`).
- **Admin** sub-client, active when the client is constructed with the
  new keyword-only `admin_token=...`. Admin calls authenticate with
  `X-Admin-Token` (app-client headers are not sent):
  `admin.create_app_client`, `admin.list_app_clients`,
  `admin.get_app_client`, `admin.update_app_client`,
  `admin.rotate_secret`, `admin.set_origins`. Calling any admin method
  without `admin_token` raises a clear `RuntimeError`.
- `KnucklesTokenExpiredError` (subclass of `KnucklesTokenError`) —
  raised by `verify_access_token` when the only problem is an expired
  `exp`. The `__cause__` chain to the underlying
  `jwt.ExpiredSignatureError` is part of the contract.
- `KnucklesRateLimitError.retry_after` — whole-second retry hint
  parsed from the `Retry-After` response header (`None` when absent
  or in the unparsed HTTP-date form).
- Keyword-only `jwks_headers` on `KnucklesClient` — extra HTTP headers
  for the JWKS fetch. The `User-Agent` now defaults to
  `knuckles-client-py/<version>` (urllib's stock UA is blocked by
  common WAF rules), and the JWKS fetch carries an explicit 10s
  timeout.

### Compatibility

- Fully backward compatible. `client.me` changed from a bound method
  to a callable sub-client, but `client.me(access_token=...)` behaves
  identically. The new account/session/admin methods return the
  server's `data` payload as plain dicts. Account, session, and admin
  endpoints require a Knuckles server that ships them; older servers
  return 404.

## [0.1.1] — 2026-05-01

### Added

- `KnucklesAPIError.request_id` — every error raised from a Knuckles
  HTTP response now carries the server's `meta.request_id` (with a
  fallback to the `X-Request-Id` response header). The id is also
  appended to `str(exc)` so logging the exception surfaces it
  automatically. Quote it when reporting an issue — the operator can
  grep their server logs for the same id and find the full
  diagnostic context.

### Changed

- `__str__` of `KnucklesAPIError` (and subclasses) now includes the
  request id when available, e.g.
  `GOOGLE_AUTH_FAILED: ... (request_id=abcd-1234)`.

### Compatibility

- Fully backward compatible. `request_id` is optional everywhere and
  defaults to `None` when talking to a pre-0.1.1 Knuckles server.

## [0.1.0] — 2026-04-26

Initial release.

### Added

- `KnucklesClient` with sub-clients for every ceremony:
  `magic_link.start/verify`, `google.start/complete`,
  `apple.start/complete`, `passkey.sign_in_begin/complete`,
  `passkey.register_begin/complete`, `passkey.list/delete`.
- Session helpers: `refresh`, `logout`, `logout_all`, `me`.
- Local JWKS-cached token verification: `verify_access_token`. No
  network call after the first verify on a fresh process.
- Discovery helpers: `fetch_jwks`, `fetch_openid_configuration`.
- Typed exception hierarchy: `KnucklesError`, `KnucklesNetworkError`,
  `KnucklesAPIError` (subclasses `KnucklesAuthError`,
  `KnucklesValidationError`, `KnucklesRateLimitError`),
  `KnucklesTokenError`.
- Typed dataclass response shapes: `TokenPair`, `CeremonyStart`,
  `PasskeyChallenge`, `UserProfile`, `PasskeyDescriptor`.
- `py.typed` marker for downstream type checkers.

### Targets

- **Knuckles server API:** v1 (every endpoint registered under
  `/v1/...` plus `/health`, `/.well-known/jwks.json`,
  `/.well-known/openid-configuration`, `/v1/auth/jwks`).
- **Python:** 3.11, 3.12, 3.13.

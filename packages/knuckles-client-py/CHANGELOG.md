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

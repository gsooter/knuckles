# Changelog

All notable changes to `@knuckles/client` (TypeScript) are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## Versioning policy

- **0.x releases are pre-stable.** APIs may change between minor
  versions. Pin to an exact version in production and read this file
  before upgrading.
- **Once 1.0.0 ships,** breaking changes require a major version bump.
- **Each release lists the Knuckles server API version it targets.**
  An SDK release that calls a missing endpoint will surface as a 404
  from the server.

## [Unreleased]

_Nothing yet._

## [0.1.0] — 2026-04-26

Initial release.

### Added

- `KnucklesClient` with sub-clients for every ceremony:
  `magicLink.start/verify`, `google.start/complete`,
  `apple.start/complete`, `passkey.signInBegin/Complete`,
  `passkey.registerBegin/Complete`, `passkey.list/delete`.
- Session helpers: `refresh`, `logout`, `logoutAll`, `me`.
- Local JWKS-cached token verification: `verifyAccessToken` (uses
  `jose`'s `createRemoteJWKSet`). No network call after the first
  verify on a fresh process.
- Typed exception hierarchy: `KnucklesError`, `KnucklesNetworkError`,
  `KnucklesAPIError` (subclasses `KnucklesAuthError`,
  `KnucklesValidationError`, `KnucklesRateLimitError`),
  `KnucklesTokenError`.
- Typed response shapes: `TokenPair`, `CeremonyStart`,
  `PasskeyChallenge`, `UserProfile`, `PasskeyDescriptor`,
  `AccessTokenClaims`.
- `VERSION` constant exported from the package root.
- Strict TypeScript config (`exactOptionalPropertyTypes`,
  `noUncheckedIndexedAccess`) — types are honest about what may be
  missing.

### Targets

- **Knuckles server API:** v1 (every endpoint registered under
  `/v1/...` plus `/health`, `/.well-known/jwks.json`,
  `/.well-known/openid-configuration`, `/v1/auth/jwks`).
- **Node:** 18+. Also runs in modern browsers, but the
  `clientSecret` must never ship in a browser bundle.

### Known gaps

- **No automated tests yet.** The Python SDK has 24 tests covering
  the same logic; the TypeScript surface is a 1:1 mirror. Tests are
  the first item for v0.2.

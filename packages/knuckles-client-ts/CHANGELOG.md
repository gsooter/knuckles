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

## [0.1.1] — 2026-06-12

### Added

- **Account management** under `client.me`, which is now callable
  *and* a namespace — `client.me({ accessToken })` returns the
  `UserProfile` exactly as before:
  - `me.updateProfile({ accessToken, displayName?, avatarUrl? })` —
    `PATCH /v1/me`; only the fields you pass are sent, and an
    explicit `null` clears the field server-side.
  - `me.deleteAccount({ accessToken })` — `DELETE /v1/me`.
  - `me.listProviders({ accessToken })` — `GET /v1/me/providers`.
  - `me.unlinkProvider({ accessToken, provider })` —
    `DELETE /v1/me/providers/{provider}`.
  - `me.startEmailChange({ accessToken, newEmail, redirectUrl })` —
    `POST /v1/me/email/start`.
  - `me.verifyEmailChange(token)` — `POST /v1/me/email/verify`
    (client headers only).
- **Sessions** sub-client: `sessions.list({ accessToken })`
  (`GET /v1/sessions`) and `sessions.revoke({ accessToken, sessionId })`
  (`DELETE /v1/sessions/{sessionId}`).
- **Admin** sub-client, active when the client is constructed with
  the new `adminToken` option. Admin calls authenticate with
  `X-Admin-Token` (app-client headers are not sent):
  `admin.createAppClient`, `admin.listAppClients`,
  `admin.getAppClient`, `admin.updateAppClient`, `admin.rotateSecret`,
  `admin.setOrigins`. Calling any admin method without `adminToken`
  throws a plain `Error` immediately.
- `KnucklesTokenExpiredError` (subclass of `KnucklesTokenError`) —
  thrown by `verifyAccessToken` when the only problem is an expired
  `exp`. The underlying `jose` `JWTExpired` error is attached as
  `cause` (part of the contract). All token errors now carry their
  `jose` cause.
- `KnucklesRateLimitError.retryAfter` — whole-second retry hint
  parsed from the `Retry-After` response header (`null` when absent
  or in the unparsed HTTP-date form).
- `jwksHeaders` constructor option — extra HTTP headers on the JWKS
  fetch. The `User-Agent` now defaults to
  `knuckles-client-ts/<version>` (Node-side; browsers strip forbidden
  headers), and the JWKS fetch now uses the client's `timeoutMs`.

### Compatibility

- Fully backward compatible. `me` changed from a method to a callable
  property, but `client.me({ accessToken })` behaves identically. The
  new account/session/admin methods return the server's `data`
  payload as plain records. Account, session, and admin endpoints
  require a Knuckles server that ships them; older servers return 404.

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

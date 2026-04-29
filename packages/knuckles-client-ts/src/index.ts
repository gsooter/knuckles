/**
 * Public entry point for `@knuckles/client`.
 *
 * Re-exports the high-level `KnucklesClient` plus every typed shape
 * and exception class. Sub-client classes are exported so callers can
 * type method parameters / inject their own subclasses if they want.
 */

export { KnucklesClient, MagicLinkClient, OAuthClient, PasskeyClient } from './client.js'
export type { KnucklesClientOptions } from './client.js'
export {
  KnucklesAPIError,
  KnucklesAuthError,
  KnucklesError,
  KnucklesNetworkError,
  KnucklesRateLimitError,
  KnucklesTokenError,
  KnucklesValidationError,
} from './errors.js'
export type {
  AccessTokenClaims,
  CeremonyStart,
  PasskeyChallenge,
  PasskeyDescriptor,
  TokenPair,
  UserProfile,
} from './types.js'

/**
 * Hardcoded SDK version. Kept in sync with `package.json` by hand on every
 * release — see `PUBLISHING.md`. Importing JSON at runtime would force every
 * consumer's bundler to ship `package.json`, which is awkward in some
 * setups, so we mirror the constant here instead.
 */
export const VERSION = '0.1.0'

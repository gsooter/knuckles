/**
 * Public entry point for `@knuckles/client`.
 *
 * Re-exports the high-level `KnucklesClient` plus every typed shape
 * and exception class. Sub-client classes are exported so callers can
 * type method parameters / inject their own subclasses if they want.
 */

export {
  AdminClient,
  KnucklesClient,
  MagicLinkClient,
  OAuthClient,
  PasskeyClient,
  SessionsClient,
  VERSION,
} from './client.js'
export type { KnucklesClientOptions, MeClient } from './client.js'
export {
  KnucklesAPIError,
  KnucklesAuthError,
  KnucklesError,
  KnucklesNetworkError,
  KnucklesRateLimitError,
  KnucklesTokenError,
  KnucklesTokenExpiredError,
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

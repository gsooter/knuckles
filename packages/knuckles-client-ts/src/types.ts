/**
 * Public response shapes mirroring the Knuckles API envelope.
 *
 * Every Knuckles success response is `{ data: T }`; every error
 * response is `{ error: { code, message } }`. The SDK unwraps
 * `data` for callers and converts `error` into a typed exception.
 */

export interface TokenPair {
  /** RS256-signed JWT to attach as `Authorization: Bearer`. */
  accessToken: string
  /** Wall-clock UTC expiry of the access token (mirrors the `exp` claim). */
  accessTokenExpiresAt: Date
  /**
   * Opaque rotating refresh token. Always store the latest — re-presenting
   * a consumed token revokes every session for the user.
   */
  refreshToken: string
  /** Wall-clock UTC expiry of the refresh token. */
  refreshTokenExpiresAt: Date
  /** Always `"Bearer"`. */
  tokenType: 'Bearer'
}

export interface CeremonyStart {
  /** URL the browser must navigate to. */
  authorizeUrl: string
  /** Signed state JWT — echo back on the matching `complete` step. */
  state: string
}

export interface PasskeyChallenge {
  /**
   * WebAuthn `PublicKeyCredentialCreation/RequestOptions`. Pass to
   * `navigator.credentials.create()` / `navigator.credentials.get()`
   * after JSON-encoding.
   */
  options: Record<string, unknown>
  /** Signed state JWT to echo on the matching `complete` step. */
  state: string
}

export interface UserProfile {
  /** Knuckles `users.id` (UUID string). */
  id: string
  /** Canonical email. */
  email: string
  /** Optional display name (may be null). */
  displayName: string | null
  /** Optional avatar URL (may be null). */
  avatarUrl: string | null
  /** `aud` claim of the access token used for the call. */
  appClientId: string
}

export interface PasskeyDescriptor {
  /** WebAuthn credential id (base64url). */
  credentialId: string
  /** User-facing label (may be null). */
  name: string | null
  /** Comma-joined transport hints (may be null). */
  transports: string | null
  /** When the credential was registered. */
  createdAt: Date
  /** Last successful assertion (may be null). */
  lastUsedAt: Date | null
}

/** Raw access-token claims from a successful local verification. */
export interface AccessTokenClaims {
  iss: string
  sub: string
  aud: string
  iat: number
  exp: number
  jti?: string
  scope?: string
  email?: string
  [k: string]: unknown
}

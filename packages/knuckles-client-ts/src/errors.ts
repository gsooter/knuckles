/**
 * Exception hierarchy for the Knuckles TypeScript SDK.
 *
 * Every Knuckles error response carries a machine-readable `code`.
 * The SDK promotes the common families to typed classes so callers
 * can `instanceof` instead of pattern-matching strings.
 */

export class KnucklesError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'KnucklesError'
  }
}

export class KnucklesNetworkError extends KnucklesError {
  constructor(message: string) {
    super(message)
    this.name = 'KnucklesNetworkError'
  }
}

export class KnucklesAPIError extends KnucklesError {
  /** Machine-readable `error.code` from the Knuckles response body. */
  readonly code: string
  /** HTTP status from Knuckles. */
  readonly statusCode: number

  constructor(opts: { code: string; message: string; statusCode: number }) {
    super(`${opts.code}: ${opts.message}`)
    this.name = 'KnucklesAPIError'
    this.code = opts.code
    this.statusCode = opts.statusCode
  }
}

/** 401 / 403 from Knuckles — refresh token is invalid, reused, expired, etc. */
export class KnucklesAuthError extends KnucklesAPIError {
  constructor(opts: { code: string; message: string; statusCode: number }) {
    super(opts)
    this.name = 'KnucklesAuthError'
  }
}

/** 422 from Knuckles. */
export class KnucklesValidationError extends KnucklesAPIError {
  constructor(opts: { code: string; message: string; statusCode: number }) {
    super(opts)
    this.name = 'KnucklesValidationError'
  }
}

/** 429 from Knuckles — back off and retry later. */
export class KnucklesRateLimitError extends KnucklesAPIError {
  constructor(opts: { code: string; message: string; statusCode: number }) {
    super(opts)
    this.name = 'KnucklesRateLimitError'
  }
}

/** Local JWKS verification failure (signature, audience, issuer, expiry). */
export class KnucklesTokenError extends KnucklesError {
  constructor(message: string) {
    super(message)
    this.name = 'KnucklesTokenError'
  }
}

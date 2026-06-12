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
  /**
   * Seconds to wait before retrying, parsed from the `Retry-After`
   * response header. `null` when the server didn't send the header
   * (older Knuckles servers) or sent an HTTP-date form the SDK does
   * not parse.
   */
  readonly retryAfter: number | null

  constructor(opts: {
    code: string
    message: string
    statusCode: number
    retryAfter?: number | null
  }) {
    super(opts)
    this.name = 'KnucklesRateLimitError'
    this.retryAfter = opts.retryAfter ?? null
  }
}

/** Local JWKS verification failure (signature, audience, issuer, expiry). */
export class KnucklesTokenError extends KnucklesError {
  constructor(message: string, options?: ErrorOptions) {
    super(message)
    this.name = 'KnucklesTokenError'
    if (options?.cause !== undefined) {
      this.cause = options.cause
    }
  }
}

/**
 * Local verification failure *specifically because the token expired*.
 *
 * Subclass of {@link KnucklesTokenError}, so existing
 * `instanceof KnucklesTokenError` checks keep working. Catch this
 * class when expiry should trigger a refresh attempt while every
 * other verification failure stays a hard error.
 *
 * The `cause` chain is part of the contract: this error always
 * carries the underlying `jose` `JWTExpired` error as `cause`.
 */
export class KnucklesTokenExpiredError extends KnucklesTokenError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options)
    this.name = 'KnucklesTokenExpiredError'
  }
}

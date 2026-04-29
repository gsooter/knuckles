/**
 * The Knuckles TypeScript SDK.
 *
 * Designed for Node 18+ backends — the `fetch` API and the `jose` JWKS
 * client are both runtime-available there. The same client also works
 * unchanged in modern browsers, but the `clientSecret` must never ship
 * in browser bundles. Treat the SDK as a server-side import.
 *
 * @example
 * ```ts
 * import { KnucklesClient } from '@knuckles/client'
 *
 * const knuckles = new KnucklesClient({
 *   baseUrl: process.env.KNUCKLES_URL!,
 *   clientId: process.env.KNUCKLES_CLIENT_ID!,
 *   clientSecret: process.env.KNUCKLES_CLIENT_SECRET!,
 * })
 *
 * // Validate an access token locally (JWKS-cached, no network after warmup).
 * const claims = await knuckles.verifyAccessToken(token)
 *
 * // Drive a sign-in ceremony.
 * const start = await knuckles.google.start({
 *   redirectUrl: 'https://my-app/auth/google/callback',
 * })
 * // ... browser round trip ...
 * const pair = await knuckles.google.complete({ code, state: start.state })
 * ```
 */

import {
  createRemoteJWKSet,
  jwtVerify,
  type JWTPayload,
  type JWTVerifyResult,
} from 'jose'

import {
  KnucklesAPIError,
  KnucklesAuthError,
  KnucklesNetworkError,
  KnucklesRateLimitError,
  KnucklesTokenError,
  KnucklesValidationError,
} from './errors.js'
import type {
  AccessTokenClaims,
  CeremonyStart,
  PasskeyChallenge,
  PasskeyDescriptor,
  TokenPair,
  UserProfile,
} from './types.js'

const DEFAULT_TIMEOUT_MS = 10_000

export interface KnucklesClientOptions {
  /** Knuckles base URL (e.g. `https://auth.example.com`). */
  baseUrl: string
  /** This consuming app's `client_id`. */
  clientId: string
  /** This consuming app's `client_secret`. Must not ship in browser bundles. */
  clientSecret: string
  /** Per-request timeout in ms. Default 10_000. */
  timeoutMs?: number
}

interface RequestOptions {
  method: 'GET' | 'POST' | 'DELETE'
  path: string
  json?: Record<string, unknown>
  bearer?: string
  sendClientHeaders?: boolean
  expectJson?: boolean
}

/** Promote an HTTP error envelope to the matching SDK exception class. */
function mapApiError(opts: {
  code: string
  message: string
  statusCode: number
}): KnucklesAPIError {
  if (opts.statusCode === 401 || opts.statusCode === 403) {
    return new KnucklesAuthError(opts)
  }
  if (opts.statusCode === 422) {
    return new KnucklesValidationError(opts)
  }
  if (opts.statusCode === 429) {
    return new KnucklesRateLimitError(opts)
  }
  return new KnucklesAPIError(opts)
}

function tokenPairFromJson(data: Record<string, unknown>): TokenPair {
  return {
    accessToken: data['access_token'] as string,
    accessTokenExpiresAt: new Date(data['access_token_expires_at'] as string),
    refreshToken: data['refresh_token'] as string,
    refreshTokenExpiresAt: new Date(data['refresh_token_expires_at'] as string),
    tokenType: 'Bearer',
  }
}

export class KnucklesClient {
  readonly magicLink: MagicLinkClient
  readonly google: OAuthClient
  readonly apple: OAuthClient
  readonly passkey: PasskeyClient

  private readonly baseUrl: string
  private readonly clientId: string
  private readonly clientSecret: string
  private readonly timeoutMs: number
  private readonly jwks: ReturnType<typeof createRemoteJWKSet>

  constructor(opts: KnucklesClientOptions) {
    this.baseUrl = opts.baseUrl.replace(/\/$/, '')
    this.clientId = opts.clientId
    this.clientSecret = opts.clientSecret
    this.timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS
    this.jwks = createRemoteJWKSet(
      new URL(`${this.baseUrl}/.well-known/jwks.json`),
    )
    this.magicLink = new MagicLinkClient(this)
    this.google = new OAuthClient(this, {
      startPath: '/v1/auth/google/start',
      completePath: '/v1/auth/google/complete',
    })
    this.apple = new OAuthClient(this, {
      startPath: '/v1/auth/apple/start',
      completePath: '/v1/auth/apple/complete',
    })
    this.passkey = new PasskeyClient(this)
  }

  /**
   * Validate a Knuckles access token locally via the cached JWKS.
   * No network call after the first verify on a fresh process.
   *
   * @throws KnucklesTokenError on signature, audience, issuer, or expiry failure.
   */
  async verifyAccessToken(token: string): Promise<AccessTokenClaims> {
    let result: JWTVerifyResult<JWTPayload>
    try {
      result = await jwtVerify(token, this.jwks, {
        issuer: this.baseUrl,
        audience: this.clientId,
        algorithms: ['RS256'],
        requiredClaims: ['iss', 'sub', 'aud', 'iat', 'exp'],
      })
    } catch (err) {
      throw new KnucklesTokenError(
        `Token verification failed: ${(err as Error).message}`,
      )
    }
    return result.payload as AccessTokenClaims
  }

  /**
   * Rotate a refresh token into a new access + refresh pair.
   *
   * Always store the new refresh token from the response. A second
   * presentation of an already-used refresh token returns
   * `REFRESH_TOKEN_REUSED`, revoking every refresh token for the user.
   */
  async refresh(refreshToken: string): Promise<TokenPair> {
    const body = await this.request({
      method: 'POST',
      path: '/v1/token/refresh',
      json: { refresh_token: refreshToken },
    })
    return tokenPairFromJson(body['data'] as Record<string, unknown>)
  }

  /** Revoke a single refresh token (idempotent on unknown values). */
  async logout(refreshToken: string): Promise<void> {
    await this.request({
      method: 'POST',
      path: '/v1/logout',
      json: { refresh_token: refreshToken },
      expectJson: false,
    })
  }

  /** Revoke every refresh token for the signed-in user. Returns count. */
  async logoutAll(opts: { accessToken: string }): Promise<number> {
    const body = await this.request({
      method: 'POST',
      path: '/v1/logout/all',
      bearer: opts.accessToken,
    })
    const data = body['data'] as Record<string, unknown>
    return data['revoked'] as number
  }

  /** Return the signed-in user's profile. */
  async me(opts: { accessToken: string }): Promise<UserProfile> {
    const body = await this.request({
      method: 'GET',
      path: '/v1/me',
      bearer: opts.accessToken,
    })
    const data = body['data'] as Record<string, unknown>
    return {
      id: data['id'] as string,
      email: data['email'] as string,
      displayName: (data['display_name'] as string | null) ?? null,
      avatarUrl: (data['avatar_url'] as string | null) ?? null,
      appClientId: data['app_client_id'] as string,
    }
  }

  /** Internal HTTP wrapper (used by sub-clients via the friendly accessor). */
  async request(opts: RequestOptions): Promise<Record<string, unknown>> {
    const url = `${this.baseUrl}${opts.path}`
    const headers: Record<string, string> = {}
    if (opts.sendClientHeaders !== false) {
      headers['X-Client-Id'] = this.clientId
      headers['X-Client-Secret'] = this.clientSecret
    }
    if (opts.bearer) {
      headers['Authorization'] = `Bearer ${opts.bearer}`
    }
    if (opts.json !== undefined) {
      headers['Content-Type'] = 'application/json'
    }

    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), this.timeoutMs)
    const init: RequestInit = {
      method: opts.method,
      headers,
      signal: controller.signal,
    }
    if (opts.json !== undefined) {
      init.body = JSON.stringify(opts.json)
    }
    let response: Response
    try {
      response = await fetch(url, init)
    } catch (err) {
      throw new KnucklesNetworkError(
        `Knuckles call failed: ${(err as Error).message}`,
      )
    } finally {
      clearTimeout(timer)
    }

    if (
      response.status === 204 ||
      (opts.expectJson === false && response.ok)
    ) {
      return {}
    }

    let body: unknown
    try {
      body = await response.json()
    } catch {
      if (response.ok) {
        throw new KnucklesNetworkError(
          'Knuckles returned a non-JSON success response.',
        )
      }
      throw new KnucklesAPIError({
        code: 'UNPARSEABLE_RESPONSE',
        message: `Knuckles returned non-JSON HTTP ${response.status}.`,
        statusCode: response.status,
      })
    }

    if (response.ok) {
      return body as Record<string, unknown>
    }
    const env = (body as { error?: { code?: string; message?: string } })
      .error
    throw mapApiError({
      code: env?.code ?? 'UNKNOWN',
      message: env?.message ?? '',
      statusCode: response.status,
    })
  }
}

export class MagicLinkClient {
  constructor(private readonly client: KnucklesClient) {}

  /**
   * Send a magic-link email. Returns 202 regardless of whether the
   * email exists (no account-enumeration). Per-email rate-limited.
   */
  async start(opts: { email: string; redirectUrl: string }): Promise<void> {
    await this.client.request({
      method: 'POST',
      path: '/v1/auth/magic-link/start',
      json: { email: opts.email, redirect_url: opts.redirectUrl },
      expectJson: false,
    })
  }

  /** Redeem a magic-link token for a session. */
  async verify(token: string): Promise<TokenPair> {
    const body = await this.client.request({
      method: 'POST',
      path: '/v1/auth/magic-link/verify',
      json: { token },
    })
    return tokenPairFromJson(body['data'] as Record<string, unknown>)
  }
}

interface OAuthPaths {
  startPath: string
  completePath: string
}

export class OAuthClient {
  constructor(
    private readonly client: KnucklesClient,
    private readonly paths: OAuthPaths,
  ) {}

  /** Get the consent URL and the matching state JWT. */
  async start(opts: { redirectUrl: string }): Promise<CeremonyStart> {
    const body = await this.client.request({
      method: 'POST',
      path: this.paths.startPath,
      json: { redirect_url: opts.redirectUrl },
    })
    const data = body['data'] as Record<string, unknown>
    return {
      authorizeUrl: data['authorize_url'] as string,
      state: data['state'] as string,
    }
  }

  /**
   * Finish the ceremony and mint a session.
   *
   * For Apple, pass the `user` payload verbatim on first sign-in.
   */
  async complete(opts: {
    code: string
    state: string
    user?: Record<string, unknown>
  }): Promise<TokenPair> {
    const json: Record<string, unknown> = {
      code: opts.code,
      state: opts.state,
    }
    if (opts.user !== undefined) {
      json['user'] = opts.user
    }
    const body = await this.client.request({
      method: 'POST',
      path: this.paths.completePath,
      json,
    })
    return tokenPairFromJson(body['data'] as Record<string, unknown>)
  }
}

export class PasskeyClient {
  constructor(private readonly client: KnucklesClient) {}

  /** Get discoverable-credential auth options (anonymous user). */
  async signInBegin(): Promise<PasskeyChallenge> {
    const body = await this.client.request({
      method: 'POST',
      path: '/v1/auth/passkey/sign-in/begin',
    })
    const data = body['data'] as Record<string, unknown>
    return {
      options: data['options'] as Record<string, unknown>,
      state: data['state'] as string,
    }
  }

  /** Verify the assertion and mint a session. */
  async signInComplete(opts: {
    credential: Record<string, unknown>
    state: string
  }): Promise<TokenPair> {
    const body = await this.client.request({
      method: 'POST',
      path: '/v1/auth/passkey/sign-in/complete',
      json: { credential: opts.credential, state: opts.state },
    })
    return tokenPairFromJson(body['data'] as Record<string, unknown>)
  }

  /** Get registration options for the signed-in user. */
  async registerBegin(opts: {
    accessToken: string
  }): Promise<PasskeyChallenge> {
    const body = await this.client.request({
      method: 'POST',
      path: '/v1/auth/passkey/register/begin',
      bearer: opts.accessToken,
    })
    const data = body['data'] as Record<string, unknown>
    return {
      options: data['options'] as Record<string, unknown>,
      state: data['state'] as string,
    }
  }

  /** Verify an attestation and persist the credential. Returns its id. */
  async registerComplete(opts: {
    accessToken: string
    credential: Record<string, unknown>
    state: string
    name?: string
  }): Promise<string> {
    const json: Record<string, unknown> = {
      credential: opts.credential,
      state: opts.state,
    }
    if (opts.name !== undefined) {
      json['name'] = opts.name
    }
    const body = await this.client.request({
      method: 'POST',
      path: '/v1/auth/passkey/register/complete',
      json,
      bearer: opts.accessToken,
    })
    const data = body['data'] as Record<string, unknown>
    return data['credential_id'] as string
  }

  /** List the user's registered passkeys. */
  async list(opts: { accessToken: string }): Promise<PasskeyDescriptor[]> {
    const body = await this.client.request({
      method: 'GET',
      path: '/v1/auth/passkey',
      bearer: opts.accessToken,
    })
    const items = body['data'] as Array<Record<string, unknown>>
    return items.map((item) => ({
      credentialId: item['credential_id'] as string,
      name: (item['name'] as string | null) ?? null,
      transports: (item['transports'] as string | null) ?? null,
      createdAt: new Date(item['created_at'] as string),
      lastUsedAt: item['last_used_at']
        ? new Date(item['last_used_at'] as string)
        : null,
    }))
  }

  /** Delete one of the user's passkeys. */
  async delete(opts: {
    accessToken: string
    credentialId: string
  }): Promise<void> {
    await this.client.request({
      method: 'DELETE',
      path: `/v1/auth/passkey/${encodeURIComponent(opts.credentialId)}`,
      bearer: opts.accessToken,
      expectJson: false,
    })
  }
}

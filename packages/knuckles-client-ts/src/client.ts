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
  errors as joseErrors,
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
  KnucklesTokenExpiredError,
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

/**
 * Hardcoded SDK version. Kept in sync with `package.json` by hand on every
 * release — see `PUBLISHING.md`. Importing JSON at runtime would force every
 * consumer's bundler to ship `package.json`, which is awkward in some
 * setups, so we mirror the constant here instead. (Lives in this module so
 * the JWKS User-Agent default can use it without a circular import.)
 */
export const VERSION = '0.1.1'

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
  /**
   * Extra HTTP headers for the JWKS fetch. When no `User-Agent` is
   * supplied the SDK defaults it to `knuckles-client-ts/<version>`.
   * Node-only nuance: browsers strip forbidden headers like
   * `User-Agent` from fetch requests.
   */
  jwksHeaders?: Record<string, string>
  /**
   * Operator admin token. When set, `client.admin` methods
   * authenticate with the `X-Admin-Token` header (the app-client
   * headers are not sent on admin routes).
   */
  adminToken?: string
}

interface RequestOptions {
  method: 'GET' | 'POST' | 'PATCH' | 'PUT' | 'DELETE'
  path: string
  json?: Record<string, unknown>
  bearer?: string
  sendClientHeaders?: boolean
  extraHeaders?: Record<string, string>
  expectJson?: boolean
}

/** Parse a `Retry-After` header value into whole seconds (delta form only). */
function parseRetryAfter(raw: string | null): number | null {
  if (raw === null) return null
  const seconds = Number.parseInt(raw.trim(), 10)
  return Number.isNaN(seconds) ? null : seconds
}

/** Promote an HTTP error envelope to the matching SDK exception class. */
function mapApiError(opts: {
  code: string
  message: string
  statusCode: number
  retryAfter?: number | null
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
  /**
   * Profile + account management. Callable for backwards
   * compatibility — `client.me({ accessToken })` behaves exactly like
   * the pre-0.1.1 `me()` method — with the newer account-management
   * endpoints hanging off properties (`client.me.updateProfile(...)`).
   */
  readonly me: MeClient
  /** Refresh-session listing + revocation. */
  readonly sessions: SessionsClient
  /**
   * Operator-only app-client management. Every method throws unless
   * the client was constructed with `adminToken`.
   */
  readonly admin: AdminClient

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
      {
        headers: {
          'User-Agent': `knuckles-client-ts/${VERSION}`,
          ...opts.jwksHeaders,
        },
        timeoutDuration: this.timeoutMs,
      },
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
    this.me = buildMeClient(this)
    this.sessions = new SessionsClient(this)
    this.admin = new AdminClient(this, opts.adminToken)
  }

  /**
   * Validate a Knuckles access token locally via the cached JWKS.
   * No network call after the first verify on a fresh process.
   *
   * @throws KnucklesTokenExpiredError when the only failure is an
   *   expired `exp`; the underlying `jose` `JWTExpired` error is
   *   attached as `cause` (part of the contract).
   * @throws KnucklesTokenError on any other signature, audience, or
   *   issuer failure.
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
      if (err instanceof joseErrors.JWTExpired) {
        throw new KnucklesTokenExpiredError(
          `Token verification failed: ${err.message}`,
          { cause: err },
        )
      }
      throw new KnucklesTokenError(
        `Token verification failed: ${(err as Error).message}`,
        { cause: err },
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
    if (opts.extraHeaders) {
      Object.assign(headers, opts.extraHeaders)
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
      retryAfter: parseRetryAfter(response.headers.get('Retry-After')),
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

/**
 * Profile + account-management namespace.
 *
 * Callable for backwards compatibility — `client.me({ accessToken })`
 * returns the `UserProfile` exactly as before. The newer
 * account-management endpoints return the server's `data` payload as
 * plain records (their shapes are newer and pass through verbatim).
 */
export interface MeClient {
  /** Return the signed-in user's profile (`GET /v1/me`). */
  (opts: { accessToken: string }): Promise<UserProfile>

  /**
   * Partially update the signed-in user's profile (`PATCH /v1/me`).
   *
   * Only the fields you pass are sent. An omitted field is left
   * untouched server-side; an explicit `null` clears it.
   */
  updateProfile(opts: {
    accessToken: string
    displayName?: string | null
    avatarUrl?: string | null
  }): Promise<Record<string, unknown>>

  /** Permanently delete the signed-in user's account (`DELETE /v1/me`). */
  deleteAccount(opts: { accessToken: string }): Promise<void>

  /**
   * List the OAuth providers linked to the signed-in user
   * (`GET /v1/me/providers`). Each row carries `provider`,
   * `created_at`, and `scopes`.
   */
  listProviders(opts: {
    accessToken: string
  }): Promise<Array<Record<string, unknown>>>

  /**
   * Unlink one OAuth provider (`google` or `apple`) from the
   * signed-in user (`DELETE /v1/me/providers/{provider}`).
   */
  unlinkProvider(opts: { accessToken: string; provider: string }): Promise<void>

  /**
   * Start an email-change ceremony (`POST /v1/me/email/start`).
   * Knuckles emails a confirmation link to `newEmail`; the change
   * only applies once `verifyEmailChange` redeems the token.
   */
  startEmailChange(opts: {
    accessToken: string
    newEmail: string
    redirectUrl: string
  }): Promise<void>

  /**
   * Redeem an email-change token and apply the new address
   * (`POST /v1/me/email/verify`). Client-headers-only — no bearer;
   * the token itself proves the ceremony. Returns the `data` record
   * carrying the new `email`.
   */
  verifyEmailChange(token: string): Promise<Record<string, unknown>>
}

/** Build the callable `client.me` namespace bound to one client. */
function buildMeClient(client: KnucklesClient): MeClient {
  const profile = async (opts: {
    accessToken: string
  }): Promise<UserProfile> => {
    const body = await client.request({
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

  return Object.assign(profile, {
    async updateProfile(opts: {
      accessToken: string
      displayName?: string | null
      avatarUrl?: string | null
    }): Promise<Record<string, unknown>> {
      const json: Record<string, unknown> = {}
      if ('displayName' in opts) {
        json['display_name'] = opts.displayName ?? null
      }
      if ('avatarUrl' in opts) {
        json['avatar_url'] = opts.avatarUrl ?? null
      }
      const body = await client.request({
        method: 'PATCH',
        path: '/v1/me',
        json,
        bearer: opts.accessToken,
      })
      return body['data'] as Record<string, unknown>
    },

    async deleteAccount(opts: { accessToken: string }): Promise<void> {
      await client.request({
        method: 'DELETE',
        path: '/v1/me',
        bearer: opts.accessToken,
        expectJson: false,
      })
    },

    async listProviders(opts: {
      accessToken: string
    }): Promise<Array<Record<string, unknown>>> {
      const body = await client.request({
        method: 'GET',
        path: '/v1/me/providers',
        bearer: opts.accessToken,
      })
      return body['data'] as Array<Record<string, unknown>>
    },

    async unlinkProvider(opts: {
      accessToken: string
      provider: string
    }): Promise<void> {
      await client.request({
        method: 'DELETE',
        path: `/v1/me/providers/${encodeURIComponent(opts.provider)}`,
        bearer: opts.accessToken,
        expectJson: false,
      })
    },

    async startEmailChange(opts: {
      accessToken: string
      newEmail: string
      redirectUrl: string
    }): Promise<void> {
      await client.request({
        method: 'POST',
        path: '/v1/me/email/start',
        json: { new_email: opts.newEmail, redirect_url: opts.redirectUrl },
        bearer: opts.accessToken,
        expectJson: false,
      })
    },

    async verifyEmailChange(token: string): Promise<Record<string, unknown>> {
      const body = await client.request({
        method: 'POST',
        path: '/v1/me/email/verify',
        json: { token },
      })
      return body['data'] as Record<string, unknown>
    },
  })
}

export class SessionsClient {
  constructor(private readonly client: KnucklesClient) {}

  /**
   * List the signed-in user's active sessions (`GET /v1/sessions`).
   * Each row carries `id`, `created_at`, and `expires_at`.
   */
  async list(opts: {
    accessToken: string
  }): Promise<Array<Record<string, unknown>>> {
    const body = await this.client.request({
      method: 'GET',
      path: '/v1/sessions',
      bearer: opts.accessToken,
    })
    return body['data'] as Array<Record<string, unknown>>
  }

  /**
   * Revoke one of the signed-in user's sessions
   * (`DELETE /v1/sessions/{sessionId}`).
   */
  async revoke(opts: { accessToken: string; sessionId: string }): Promise<void> {
    await this.client.request({
      method: 'DELETE',
      path: `/v1/sessions/${encodeURIComponent(opts.sessionId)}`,
      bearer: opts.accessToken,
      expectJson: false,
    })
  }
}

/**
 * Operator-only app-client management.
 *
 * Active only when the parent `KnucklesClient` was constructed with
 * `adminToken`. Admin routes authenticate with the `X-Admin-Token`
 * header alone — the app-client headers are not sent. Every method
 * returns the server's `data` payload verbatim.
 */
export class AdminClient {
  constructor(
    private readonly client: KnucklesClient,
    private readonly adminToken: string | undefined,
  ) {}

  /** Issue one admin call with `X-Admin-Token` auth. */
  private async request(opts: {
    method: 'GET' | 'POST' | 'PATCH' | 'PUT'
    path: string
    json?: Record<string, unknown>
  }): Promise<Record<string, unknown>> {
    if (this.adminToken === undefined) {
      throw new Error(
        'Admin API is not configured: construct KnucklesClient with ' +
          'adminToken to use client.admin.',
      )
    }
    const requestOpts: RequestOptions = {
      method: opts.method,
      path: opts.path,
      sendClientHeaders: false,
      extraHeaders: { 'X-Admin-Token': this.adminToken },
    }
    if (opts.json !== undefined) {
      requestOpts.json = opts.json
    }
    return this.client.request(requestOpts)
  }

  /**
   * Register a new app-client (tenant). The returned record includes
   * the one-time plaintext `client_secret` — store it now; it is
   * never shown again.
   */
  async createAppClient(opts: {
    clientId: string
    appName: string
    allowedOrigins?: string[]
  }): Promise<Record<string, unknown>> {
    const json: Record<string, unknown> = {
      client_id: opts.clientId,
      app_name: opts.appName,
    }
    if (opts.allowedOrigins !== undefined) {
      json['allowed_origins'] = opts.allowedOrigins
    }
    const body = await this.request({
      method: 'POST',
      path: '/v1/admin/app-clients',
      json,
    })
    return body['data'] as Record<string, unknown>
  }

  /** List every registered app-client (no secrets). */
  async listAppClients(): Promise<Array<Record<string, unknown>>> {
    const body = await this.request({
      method: 'GET',
      path: '/v1/admin/app-clients',
    })
    return body['data'] as Array<Record<string, unknown>>
  }

  /** Fetch one app-client by id (no secrets). */
  async getAppClient(clientId: string): Promise<Record<string, unknown>> {
    const body = await this.request({
      method: 'GET',
      path: `/v1/admin/app-clients/${encodeURIComponent(clientId)}`,
    })
    return body['data'] as Record<string, unknown>
  }

  /**
   * Partially update an app-client's configuration. `fields` is
   * passed through verbatim as the PATCH body (snake_case keys, e.g.
   * `{ app_name: ..., resend_from_email: ... }`).
   */
  async updateAppClient(
    clientId: string,
    fields: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    const body = await this.request({
      method: 'PATCH',
      path: `/v1/admin/app-clients/${encodeURIComponent(clientId)}`,
      json: fields,
    })
    return body['data'] as Record<string, unknown>
  }

  /**
   * Rotate an app-client's secret. The returned record includes the
   * new one-time plaintext `client_secret` — store it now; it is
   * never shown again.
   */
  async rotateSecret(clientId: string): Promise<Record<string, unknown>> {
    const body = await this.request({
      method: 'POST',
      path: `/v1/admin/app-clients/${encodeURIComponent(clientId)}/rotate-secret`,
    })
    return body['data'] as Record<string, unknown>
  }

  /** Replace an app-client's allowed origins (the complete new list). */
  async setOrigins(
    clientId: string,
    allowedOrigins: string[],
  ): Promise<Record<string, unknown>> {
    const body = await this.request({
      method: 'PUT',
      path: `/v1/admin/app-clients/${encodeURIComponent(clientId)}/origins`,
      json: { allowed_origins: allowedOrigins },
    })
    return body['data'] as Record<string, unknown>
  }
}

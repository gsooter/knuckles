# @knuckles/client

[![npm version](https://img.shields.io/npm/v/@knuckles/client.svg)](https://www.npmjs.com/package/@knuckles/client)
[![Node version](https://img.shields.io/node/v/@knuckles/client.svg)](https://www.npmjs.com/package/@knuckles/client)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Types: included](https://img.shields.io/badge/types-included-blue.svg)](#)
[![Provenance](https://img.shields.io/badge/npm-provenance-blue)](https://docs.npmjs.com/generating-provenance-statements)

TypeScript SDK for the **[Knuckles](https://github.com/gsooter/knuckles)**
identity service. Knuckles handles user accounts, sign-in ceremonies
(magic-link, Google, Apple, WebAuthn passkey), and JWT issuance for a
fleet of consuming applications. This package is what those Node
backends import.

> **Why an SDK?** The three things consuming apps get wrong by default
> are: forgetting `audience` verification on JWTs, forgetting to swap
> in the rotated refresh token after a refresh, and treating
> `REFRESH_TOKEN_REUSED` as a generic 401 instead of a "revoke
> everything" signal. The SDK encodes all three correctly so you don't
> have to.

> **Server-side import.** The SDK uses native `fetch` and `jose`, both
> of which run in browsers — but `clientSecret` must never appear in a
> browser bundle. Treat this package as a Node-only import.

---

## Table of contents

- [Install](#install)
- [Quick start](#quick-start)
- [Concepts in 30 seconds](#concepts-in-30-seconds)
- [The full API](#the-full-api)
- [Token verification, in depth](#token-verification-in-depth)
- [Refresh-token rotation, in depth](#refresh-token-rotation-in-depth)
- [Exception handling](#exception-handling)
- [Configuration reference](#configuration-reference)
- [Recipes](#recipes)
  - [Express middleware](#express-middleware)
  - [Hono middleware](#hono-middleware)
  - [Next.js (App Router) route handler](#nextjs-app-router-route-handler)
- [Versioning policy](#versioning-policy)
- [Compatibility matrix](#compatibility-matrix)
- [Development](#development)

---

## Install

```bash
npm install @knuckles/client
# pnpm add @knuckles/client
# yarn add @knuckles/client
# bun add @knuckles/client
```

Requires Node 18+. Pure JavaScript output (ESM); types are bundled.

## Quick start

```ts
import { KnucklesClient } from '@knuckles/client'

const knuckles = new KnucklesClient({
  baseUrl: process.env.KNUCKLES_URL!,           // your Knuckles deployment
  clientId: process.env.KNUCKLES_CLIENT_ID!,    // the client_id you registered
  clientSecret: process.env.KNUCKLES_CLIENT_SECRET!, // server-only
})

// 1. Verify an access token locally — JWKS-cached, no network after warmup.
const claims = await knuckles.verifyAccessToken(accessToken)
const userId = claims.sub

// 2. Drive a sign-in ceremony.
const start = await knuckles.google.start({
  redirectUrl: 'https://my-app/auth/google/callback',
})
// ... your frontend redirects the browser to start.authorizeUrl ...
// ... Google redirects back to your callback with ?code=...&state=... ...
const pair = await knuckles.google.complete({ code, state: start.state })

// 3. Hand the user their session — store however you store sessions.
console.log(pair.accessToken)         // short-lived RS256 JWT
console.log(pair.refreshToken)        // opaque, rotates on every use

// 4. When the access token nears expiry, rotate.
const newPair = await knuckles.refresh(pair.refreshToken)
// IMPORTANT: store newPair.refreshToken. The old one is now consumed.
```

## Concepts in 30 seconds

- **One client per process.** The `KnucklesClient` holds the JWKS
  cache and reuses connections via the global `fetch`. Construct once
  at startup; reuse everywhere.
- **App-client credentials live on your backend.** `clientId` is
  public-ish, `clientSecret` is treated like any other server secret.
  Browsers never see the secret.
- **The user's tokens are what you store.** After a successful
  ceremony you get a `TokenPair`. Where you put it (HTTP-only cookie,
  database row, native keychain) is your application's choice.
- **Access tokens are validated locally.** `verifyAccessToken` caches
  Knuckles' public keys (JWKS) and verifies signatures in-process. No
  per-request network hop to Knuckles.
- **Refresh tokens rotate on every use.** Always store the *new*
  refresh token from a refresh response. Re-presenting a consumed
  refresh token is treated as a security incident — see below.

## The full API

| Method | Returns | Notes |
|---|---|---|
| `client.verifyAccessToken(token)` | `Promise<AccessTokenClaims>` | Local. Throws `KnucklesTokenError` on failure. |
| `client.refresh(refreshToken)` | `Promise<TokenPair>` | Always store the new refresh token. |
| `client.logout(refreshToken)` | `Promise<void>` | Idempotent; unknown tokens succeed silently. |
| `client.logoutAll({ accessToken })` | `Promise<number>` | Revokes every refresh token for the user. Returns count. |
| `client.me({ accessToken })` | `Promise<UserProfile>` | Current user's profile from `/v1/me`. |
| `client.magicLink.start({ email, redirectUrl })` | `Promise<void>` | May throw `KnucklesRateLimitError`. |
| `client.magicLink.verify(token)` | `Promise<TokenPair>` | Redeems the token from the email. |
| `client.google.start({ redirectUrl })` | `Promise<CeremonyStart>` | Returns `authorizeUrl` + `state`. |
| `client.google.complete({ code, state })` | `Promise<TokenPair>` | |
| `client.apple.start({ redirectUrl })` | `Promise<CeremonyStart>` | |
| `client.apple.complete({ code, state, user? })` | `Promise<TokenPair>` | Pass `user` only on first sign-in for that Apple ID. |
| `client.passkey.signInBegin()` | `Promise<PasskeyChallenge>` | Discoverable-credential flow; no bearer needed. |
| `client.passkey.signInComplete({ credential, state })` | `Promise<TokenPair>` | |
| `client.passkey.registerBegin({ accessToken })` | `Promise<PasskeyChallenge>` | User must be signed in. |
| `client.passkey.registerComplete({ accessToken, credential, state, name? })` | `Promise<string>` | Returns the credential id. |
| `client.passkey.list({ accessToken })` | `Promise<PasskeyDescriptor[]>` | |
| `client.passkey.delete({ accessToken, credentialId })` | `Promise<void>` | Ownership-checked. |

## Token verification, in depth

```ts
const claims = await knuckles.verifyAccessToken(token)
```

What the SDK does, in order:

1. Fetches `{baseUrl}/.well-known/jwks.json` once per process and
   caches the public keys in-memory (via `jose`'s `createRemoteJWKSet`).
2. Parses the JWT header to find its `kid`, looks up the matching
   public key from the cache.
3. Verifies the RS256 signature.
4. Verifies the `iss` claim equals your `baseUrl`.
5. Verifies the `aud` claim equals your `clientId`.
6. Verifies `iat`, `sub`, `exp` are present and `exp` is in the
   future.
7. Returns the decoded claims.

Any failure throws `KnucklesTokenError`. The SDK does *not*
automatically refresh the token — that's a higher-level decision
your app makes (refresh, or require re-authentication).

## Refresh-token rotation, in depth

Knuckles uses one-shot rotating refresh tokens. The contract:

- Every successful refresh returns a *new* refresh token. Store it
  immediately, replacing the old one.
- The old refresh token is now consumed. Presenting it again is the
  signal of a leak — Knuckles revokes every refresh token for the
  user and returns `REFRESH_TOKEN_REUSED`.

Correct usage:

```ts
import { KnucklesAuthError, KnucklesTokenError } from '@knuckles/client'

async function getValidAccessToken(session: Session): Promise<string> {
  try {
    await knuckles.verifyAccessToken(session.accessToken)
    return session.accessToken
  } catch (err) {
    if (!(err instanceof KnucklesTokenError)) throw err
    // expired or invalid — try a refresh
  }

  let pair: TokenPair
  try {
    pair = await knuckles.refresh(session.refreshToken)
  } catch (err) {
    if (err instanceof KnucklesAuthError && err.code === 'REFRESH_TOKEN_REUSED') {
      // SECURITY EVENT — every session for this user has been revoked
      // server-side. Sign them out everywhere.
      await session.delete()
      throw new SessionRevokedError()
    }
    // Otherwise: refresh expired or invalid — sign out, redirect to login.
    await session.delete()
    throw new SignInRequiredError()
  }

  session.accessToken = pair.accessToken
  session.refreshToken = pair.refreshToken   // <-- the rotation
  await session.save()
  return pair.accessToken
}
```

## Exception handling

```
KnucklesError                       // base for everything the SDK throws
├── KnucklesNetworkError            // fetch failed / non-JSON response
├── KnucklesTokenError              // local JWKS verification failed
└── KnucklesAPIError                // Knuckles returned a typed error
    ├── KnucklesAuthError           // 401 / 403
    ├── KnucklesValidationError     // 422
    └── KnucklesRateLimitError      // 429
```

Every `KnucklesAPIError` carries `.code`, `.message`, `.statusCode`.
Codes that warrant special handling:

| Code | What it means | What to do |
|---|---|---|
| `REFRESH_TOKEN_REUSED` | A consumed refresh token was presented again. **Every** refresh token for this user has been revoked. | Sign user out across every device. Force re-authentication. |
| `REFRESH_TOKEN_EXPIRED` | 30-day lifetime elapsed. | Redirect to sign-in. |
| `REFRESH_TOKEN_INVALID` | Token unknown to Knuckles. | Same as expired. |
| `INVALID_CLIENT` | Wrong `clientId`/`clientSecret`, or refresh token issued for a different app. | Configuration bug — log loudly. |
| `RATE_LIMITED` | Per-email throttle on magic-link sends. | Surface a friendly retry message. |
| `MAGIC_LINK_*` | Token bad / expired / used. | Show "this link is no longer valid; request a new one." |
| `*_AUTH_FAILED` | Provider-side ceremony failure. | Show a generic "couldn't sign you in with that method." |

Other codes are bugs in your integration or in Knuckles itself — log
the full exception (`code`, `message`, `statusCode`) and treat as 5xx.

## Configuration reference

```ts
new KnucklesClient({
  baseUrl: string,         // required
  clientId: string,        // required
  clientSecret: string,    // required
  timeoutMs?: number,      // per-request HTTP timeout, default 10_000
})
```

- **`baseUrl`** — exact origin Knuckles publishes itself as (also the
  `iss` claim it embeds). No trailing slash.
- **`clientId`** — used as the JWT `aud` Knuckles embeds. The SDK
  also enforces it on every `verifyAccessToken` call.
- **`clientSecret`** — sent as `X-Client-Secret` on every request
  that needs app-client auth. Keep it server-side.
- **`timeoutMs`** — per-call timeout. Knuckles ceremonies talk to
  Google/Apple over the network, so leaving headroom (10s default)
  is reasonable.

## Recipes

### Express middleware

```ts
import express, { type NextFunction, type Request, type Response } from 'express'
import { KnucklesClient, KnucklesTokenError } from '@knuckles/client'

const knuckles = new KnucklesClient({
  baseUrl: process.env.KNUCKLES_URL!,
  clientId: process.env.KNUCKLES_CLIENT_ID!,
  clientSecret: process.env.KNUCKLES_CLIENT_SECRET!,
})

export interface AuthRequest extends Request {
  userId?: string
}

export async function requireAuth(
  req: AuthRequest,
  res: Response,
  next: NextFunction,
) {
  const match = /^Bearer (.+)$/i.exec(req.header('authorization') ?? '')
  if (!match?.[1]) {
    res.status(401).json({ error: 'missing_bearer' })
    return
  }
  try {
    const claims = await knuckles.verifyAccessToken(match[1])
    req.userId = claims.sub
    next()
  } catch (err) {
    if (err instanceof KnucklesTokenError) {
      res.status(401).json({ error: 'invalid_token' })
      return
    }
    next(err)
  }
}

const app = express()
app.use('/api', requireAuth)
app.get('/api/me', (req: AuthRequest, res) => res.json({ userId: req.userId }))
```

### Hono middleware

```ts
import { Hono } from 'hono'
import { KnucklesClient, KnucklesTokenError } from '@knuckles/client'

const knuckles = new KnucklesClient({
  baseUrl: process.env.KNUCKLES_URL!,
  clientId: process.env.KNUCKLES_CLIENT_ID!,
  clientSecret: process.env.KNUCKLES_CLIENT_SECRET!,
})

const app = new Hono()

app.use('/api/*', async (c, next) => {
  const match = /^Bearer (.+)$/i.exec(c.req.header('authorization') ?? '')
  if (!match?.[1]) return c.json({ error: 'missing_bearer' }, 401)
  try {
    const claims = await knuckles.verifyAccessToken(match[1])
    c.set('userId', claims.sub)
  } catch (err) {
    if (err instanceof KnucklesTokenError) {
      return c.json({ error: 'invalid_token' }, 401)
    }
    throw err
  }
  await next()
})

app.get('/api/me', (c) => c.json({ userId: c.get('userId') }))
```

### Next.js (App Router) route handler

```ts
// app/api/me/route.ts
import { NextRequest, NextResponse } from 'next/server'
import { KnucklesClient, KnucklesTokenError } from '@knuckles/client'

let _client: KnucklesClient | undefined
function knuckles() {
  return (_client ??= new KnucklesClient({
    baseUrl: process.env.KNUCKLES_URL!,
    clientId: process.env.KNUCKLES_CLIENT_ID!,
    clientSecret: process.env.KNUCKLES_CLIENT_SECRET!,
  }))
}

export async function GET(req: NextRequest) {
  const accessToken = req.cookies.get('access_token')?.value
  if (!accessToken) return NextResponse.json({ error: 'unauthenticated' }, { status: 401 })
  try {
    await knuckles().verifyAccessToken(accessToken)
  } catch (err) {
    if (err instanceof KnucklesTokenError) {
      return NextResponse.json({ error: 'invalid_token' }, { status: 401 })
    }
    throw err
  }
  return NextResponse.json(await knuckles().me({ accessToken }))
}
```

## Versioning policy

- **0.x is pre-stable.** Read [`CHANGELOG.md`](./CHANGELOG.md) before
  upgrading minor versions; method signatures may change.
- **1.0+ follows strict semver.** Breaking changes require a major
  version bump.
- **Pin in production.** `"@knuckles/client": "0.1.0"` (no caret) is
  the right move at this stage.

## Compatibility matrix

| `@knuckles/client` | Knuckles server API | Node |
|---|---|---|
| 0.1.x | v1 (every route under `/v1/...` as of 2026-04) | 18, 20, 22, 24 |

If your Knuckles deployment is older than the SDK targets, calls to
new endpoints (e.g. `/v1/auth/passkey` GET) will return 404. Upgrade
the server first.

## Development

The SDK lives in the [Knuckles monorepo](https://github.com/gsooter/knuckles)
under `packages/knuckles-client-ts/`.

```bash
cd packages/knuckles-client-ts
npm install
npm run typecheck
npm run build      # → dist/ with .js + .d.ts
```

Tests are not yet written for the TS SDK — the Python SDK has 24
tests covering the same logic, and the TS surface is a 1:1 mirror.
Adding a `vitest`-based test suite is the first item for v0.2.

## License

MIT — see [`LICENSE`](./LICENSE).

/**
 * Express middleware that validates a Knuckles bearer token on
 * every protected request. Drop it in front of any router that
 * should require authentication.
 *
 * The validation uses the SDK's JWKS-cached verifier — no network
 * call after the first request on a fresh process.
 *
 * Usage:
 *   import express from 'express'
 *   import { requireAuth, AuthRequest } from './middleware'
 *
 *   const app = express()
 *   app.use('/api', requireAuth)
 *   app.get('/api/me', (req: AuthRequest, res) => {
 *     res.json({ userId: req.userId })
 *   })
 */

import type { NextFunction, Request, Response } from 'express'

import { KnucklesClient, KnucklesTokenError } from '@knuckles/client'

const knuckles = new KnucklesClient({
  baseUrl: requireEnv('KNUCKLES_URL'),
  clientId: requireEnv('KNUCKLES_CLIENT_ID'),
  clientSecret: requireEnv('KNUCKLES_CLIENT_SECRET'),
})

export interface AuthRequest extends Request {
  userId?: string
  accessTokenClaims?: Record<string, unknown>
}

export async function requireAuth(
  req: AuthRequest,
  res: Response,
  next: NextFunction,
): Promise<void> {
  const header = req.header('authorization') ?? ''
  const match = /^Bearer (.+)$/i.exec(header)
  if (!match || !match[1]) {
    res.status(401).json({ error: 'missing_bearer' })
    return
  }

  try {
    const claims = await knuckles.verifyAccessToken(match[1])
    req.userId = claims.sub
    req.accessTokenClaims = claims
    next()
  } catch (err) {
    if (err instanceof KnucklesTokenError) {
      res.status(401).json({ error: 'invalid_token', detail: err.message })
      return
    }
    throw err
  }
}

function requireEnv(name: string): string {
  const value = process.env[name]
  if (!value) throw new Error(`Missing required env var: ${name}`)
  return value
}

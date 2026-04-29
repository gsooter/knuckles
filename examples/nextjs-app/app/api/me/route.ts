/**
 * Server-side endpoint that validates the access-token cookie and
 * returns the user's profile. Uses the JWKS-cached verifier for
 * sub-millisecond verification after warmup.
 */

import { NextRequest, NextResponse } from 'next/server'

import { knuckles } from '../../../lib/knuckles'

export async function GET(req: NextRequest): Promise<NextResponse> {
  const accessToken = req.cookies.get('access_token')?.value
  if (!accessToken) {
    return NextResponse.json({ error: 'unauthenticated' }, { status: 401 })
  }

  try {
    await knuckles().verifyAccessToken(accessToken)
  } catch {
    return NextResponse.json({ error: 'invalid_token' }, { status: 401 })
  }

  const profile = await knuckles().me({ accessToken })
  return NextResponse.json(profile)
}

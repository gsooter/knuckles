/**
 * Magic-link verify handler.
 *
 * The magic-link email points at `/auth/verify?token=<...>`. This
 * route exchanges the token for a session and writes the cookies.
 */

import { NextRequest, NextResponse } from 'next/server'

import { knuckles } from '../../../lib/knuckles'

export async function GET(req: NextRequest): Promise<NextResponse> {
  const token = new URL(req.url).searchParams.get('token')
  if (!token) {
    return NextResponse.redirect(`${process.env.APP_URL}/sign-in?error=missing_token`)
  }

  const pair = await knuckles().magicLink.verify(token)
  const response = NextResponse.redirect(`${process.env.APP_URL}/`)
  response.cookies.set('access_token', pair.accessToken, {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    expires: pair.accessTokenExpiresAt,
  })
  response.cookies.set('refresh_token', pair.refreshToken, {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    expires: pair.refreshTokenExpiresAt,
  })
  return response
}

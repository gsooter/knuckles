/**
 * Next.js App Router route handlers for the Google sign-in ceremony.
 *
 * Two endpoints under one file:
 *
 * * `GET /auth/google`            — kick off; redirects browser to Google.
 * * `GET /auth/google/callback`   — Google redirects back here with code+state.
 *
 * The callback writes the issued access + refresh tokens into HTTP-only
 * cookies and redirects the user into the signed-in area.
 */

import { NextRequest, NextResponse } from 'next/server'

import { knuckles } from '../../../lib/knuckles'

const REDIRECT_URL = `${process.env.APP_URL}/auth/google/callback`

export async function GET(req: NextRequest): Promise<NextResponse> {
  const url = new URL(req.url)

  // Callback variant: Google has redirected back with ?code=...&state=...
  if (url.pathname.endsWith('/callback')) {
    const code = url.searchParams.get('code')
    const state = url.searchParams.get('state')
    if (!code || !state) {
      return NextResponse.redirect(`${process.env.APP_URL}/sign-in?error=missing_code`)
    }

    const pair = await knuckles().google.complete({ code, state })
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

  // Start variant: redirect the browser to Google's consent screen.
  const start = await knuckles().google.start({ redirectUrl: REDIRECT_URL })
  return NextResponse.redirect(start.authorizeUrl)
}

/**
 * Server-rendered sign-in page that presents all four Knuckles paths.
 *
 * The Google button is a plain link — `/auth/google` is a route
 * handler that does the start step and redirects to Google. The
 * magic-link form posts to `/api/auth/magic-link` which calls
 * `knuckles.magicLink.start(...)` server-side.
 *
 * Apple and passkey buttons follow the same pattern (omitted here
 * for brevity — same shape as Google).
 */

import { redirect } from 'next/navigation'

import { knuckles } from '../../lib/knuckles'

async function sendMagicLink(formData: FormData): Promise<void> {
  'use server'
  const email = formData.get('email')
  if (typeof email !== 'string' || !email) return
  await knuckles().magicLink.start({
    email,
    redirectUrl: `${process.env.APP_URL}/auth/verify`,
  })
  redirect('/sign-in?sent=1')
}

export default function SignInPage(): JSX.Element {
  return (
    <main>
      <h1>Sign in</h1>

      <a href="/auth/google">Continue with Google</a>

      <form action={sendMagicLink}>
        <label>
          Email
          <input name="email" type="email" required />
        </label>
        <button type="submit">Email me a sign-in link</button>
      </form>
    </main>
  )
}

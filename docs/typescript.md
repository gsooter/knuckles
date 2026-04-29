---
title: TypeScript
layout: default
parent: Integration
nav_order: 2
description: "Step-by-step walkthrough: a real Express app that signs users in with Knuckles."
---

# TypeScript integration walkthrough
{: .no_toc }

We're going to build a small Express + TypeScript app that signs
users in with Knuckles. By the end you'll have:

- A `/sign-in` page with Google and magic-link.
- Working OAuth callbacks.
- A `/me` endpoint protected by a real signed token.
- Cookie-based session, with silent refresh.

If you're using **Next.js** specifically, the patterns are identical
— Express maps cleanly to Next's API routes, route handlers, or
middleware. There's a finished Next.js example at
[`examples/nextjs-app/`](https://github.com/gsooter/knuckles/tree/main/examples/nextjs-app).

<details open markdown="block">
<summary>Table of contents</summary>

1. TOC
{:toc}

</details>

---

## Before you start

You need:

- **Knuckles running and reachable** (see [Quickstart](quickstart.html)).
- **An app-client registered** with `--allowed-origin
  http://localhost:3000`:
  ```bash
  python scripts/register_app_client.py \
      --client-id my-ts-app \
      --app-name "My TS App" \
      --allowed-origin http://localhost:3000
  ```
- **Google OAuth set up in Knuckles** with
  `http://localhost:3000/auth/google/callback` in the authorized
  redirect URIs.

---

## Step 1 — Set up the project

```bash
mkdir my-ts-app && cd my-ts-app
npm init -y
npm install express cookie-parser dotenv @knuckles/client
npm install -D typescript tsx @types/express @types/cookie-parser @types/node
npx tsc --init --target es2022 --module nodenext --moduleResolution nodenext --strict
```

Create `.env`:

```bash
KNUCKLES_URL=http://localhost:5001
KNUCKLES_CLIENT_ID=my-ts-app
KNUCKLES_CLIENT_SECRET=kn_xxxxxxxxxxxxxxxxxxxxx
COOKIE_SECRET=any-long-random-string
```

---

## Step 2 — Create the Knuckles client (one place)

```ts
// src/knuckles.ts
import { KnucklesClient } from '@knuckles/client'

export const knuckles = new KnucklesClient({
  baseUrl: process.env.KNUCKLES_URL!,
  clientId: process.env.KNUCKLES_CLIENT_ID!,
  clientSecret: process.env.KNUCKLES_CLIENT_SECRET!,
})
```

The SDK is safe to keep as a module-level singleton — JWKS keys are
cached internally.

---

## Step 3 — App skeleton

```ts
// src/server.ts
import 'dotenv/config'
import express from 'express'
import cookieParser from 'cookie-parser'

import { knuckles } from './knuckles.js'

const app = express()
app.use(express.urlencoded({ extended: false }))
app.use(express.json())
app.use(cookieParser(process.env.COOKIE_SECRET!))

// In a real app: store sessions in Postgres / Redis. For brevity here
// we use a Map keyed by a session id we hand to the browser.
type SessionRow = { userId: string; email?: string; accessToken: string; refreshToken: string }
const sessions = new Map<string, SessionRow>()

app.get('/', (req, res) => {
  const sid = req.signedCookies['sid']
  const row = sid ? sessions.get(sid) : undefined
  if (row) {
    res.send(`<p>Signed in as ${row.email}.</p><p><a href="/logout">Sign out</a></p>`)
  } else {
    res.send('<a href="/sign-in">Sign in</a>')
  }
})

app.listen(3000, () => console.log('Listening on http://localhost:3000'))
```

Run it:

```bash
npx tsx src/server.ts
```

Visit `http://localhost:3000` — you should see "Sign in."

---

## Step 4 — The sign-in page

```ts
app.get('/sign-in', (_req, res) => {
  res.send(`
    <h1>Sign in</h1>
    <form method="post" action="/sign-in/magic-link">
      <input type="email" name="email" placeholder="you@example.com" required />
      <button>Email me a link</button>
    </form>
    <hr>
    <a href="/sign-in/google">Sign in with Google</a>
  `)
})
```

---

## Step 5 — Wire up Google sign-in

```ts
app.get('/sign-in/google', async (_req, res) => {
  const { authorizeUrl } = await knuckles.google.start({
    redirectUrl: 'http://localhost:3000/auth/google/callback',
  })
  res.redirect(authorizeUrl)
})

app.get('/auth/google/callback', async (req, res) => {
  const code = String(req.query.code)
  const state = String(req.query.state)

  const pair = await knuckles.google.complete({ code, state })
  await persistSession(res, pair)
  res.redirect('/')
})
```

Helper that stores the session and sets the cookie:

```ts
import crypto from 'node:crypto'
import type { Response } from 'express'
import type { TokenPair } from '@knuckles/client'

async function persistSession(res: Response, pair: TokenPair): Promise<void> {
  const claims = await knuckles.verifyAccessToken(pair.accessToken)
  const sid = crypto.randomUUID()
  sessions.set(sid, {
    userId: claims.sub,
    email: claims.email,
    accessToken: pair.accessToken,
    refreshToken: pair.refreshToken,
  })
  res.cookie('sid', sid, {
    httpOnly: true,
    sameSite: 'lax',
    signed: true,
    secure: process.env.NODE_ENV === 'production',
  })
}
```

{: .note }
The Map-as-session-store is for brevity. In production: persist
sessions in your real database, keyed by `sid`. The browser only
sees the opaque `sid` — never the access or refresh token.

---

## Step 6 — Wire up magic-link sign-in

```ts
app.post('/sign-in/magic-link', async (req, res) => {
  await knuckles.magicLink.start({
    email: req.body.email,
    redirectUrl: 'http://localhost:3000/auth/verify',
  })
  res.send('Check your email for a sign-in link.')
})

app.get('/auth/verify', async (req, res) => {
  const token = String(req.query.token)
  const pair = await knuckles.magicLink.verify(token)
  await persistSession(res, pair)
  res.redirect('/')
})
```

Try it: visit `/sign-in`, type your email, watch the Knuckles
terminal for the link, paste it. Land on `/` signed in.

---

## Step 7 — Protect a route (middleware)

```ts
import type { NextFunction, Request, Response } from 'express'
import { KnucklesTokenError, KnucklesAuthError } from '@knuckles/client'

declare module 'express' {
  interface Request {
    user?: { id: string; email?: string }
  }
}

async function requireSignIn(req: Request, res: Response, next: NextFunction): Promise<void> {
  const sid = req.signedCookies['sid']
  const row = sid ? sessions.get(sid) : undefined
  if (!row) {
    res.status(401).json({ error: 'not signed in' })
    return
  }

  let claims
  try {
    claims = await knuckles.verifyAccessToken(row.accessToken)
  } catch (err) {
    if (!(err instanceof KnucklesTokenError)) throw err
    // Try silent refresh.
    if (!(await tryRefresh(row))) {
      sessions.delete(sid)
      res.clearCookie('sid')
      res.status(401).json({ error: 'session expired' })
      return
    }
    claims = await knuckles.verifyAccessToken(row.accessToken)
  }

  req.user = { id: claims.sub, email: claims.email }
  next()
}

app.get('/me', requireSignIn, (req, res) => {
  res.json(req.user)
})
```

---

## Step 8 — Silent refresh

```ts
async function tryRefresh(row: SessionRow): Promise<boolean> {
  try {
    const pair = await knuckles.refresh(row.refreshToken)
    row.accessToken = pair.accessToken
    row.refreshToken = pair.refreshToken  // IMPORTANT: rotate
    return true
  } catch (err) {
    if (
      err instanceof KnucklesAuthError &&
      (err.code === 'REFRESH_TOKEN_REUSED' || err.code === 'REFRESH_TOKEN_EXPIRED')
    ) {
      return false
    }
    throw err
  }
}
```

{: .important }
**Always store the new refresh token from the response.** Knuckles
rotates refresh tokens — the old one becomes invalid the moment you
use it. The SDK doesn't have separate `RefreshTokenReused` /
`RefreshTokenExpired` classes — both surface as `KnucklesAuthError`,
and you switch on `err.code` to tell them apart.

---

## Step 9 — Sign out

```ts
app.get('/logout', async (req, res) => {
  const sid = req.signedCookies['sid']
  const row = sid ? sessions.get(sid) : undefined
  if (row) {
    try {
      await knuckles.logout(row.refreshToken)
    } catch { /* idempotent */ }
    sessions.delete(sid)
  }
  res.clearCookie('sid')
  res.redirect('/')
})
```

---

## Step 10 — Try the whole thing

```bash
npx tsx src/server.ts
```

Open `http://localhost:3000`:

1. Click **Sign in.**
2. **Sign in with Google** → back on `/` with your email.
3. **Sign out.**
4. **Magic-link form** → token in Knuckles terminal → paste → signed in.
5. Visit `/me` → user id + email as JSON.

That's a working integration. ✅

---

## Passkeys

Passkeys involve the browser, so this part has frontend code too.
The end-to-end pattern:

### Sign-in (no user yet)

```ts
// Backend route
app.post('/sign-in/passkey/begin', async (_req, res) => {
  const { options, state } = await knuckles.passkey.signInBegin()
  res.json({ options, state })
})

app.post('/sign-in/passkey/complete', async (req, res) => {
  const pair = await knuckles.passkey.signInComplete({
    credential: req.body.credential,
    state: req.body.state,
  })
  await persistSession(res, pair)
  res.json({ ok: true })
})
```

```html
<!-- Frontend -->
<button id="passkey-signin">Sign in with passkey</button>
<script type="module">
  document.getElementById('passkey-signin').onclick = async () => {
    // 1. Ask the backend for the WebAuthn options.
    const begin = await fetch('/sign-in/passkey/begin', { method: 'POST' }).then(r => r.json())
    // 2. Hand them to the browser's WebAuthn API.
    const cred = await navigator.credentials.get({
      publicKey: begin.options.publicKey,
    })
    // 3. POST the result back to the backend.
    await fetch('/sign-in/passkey/complete', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ credential: cred, state: begin.state }),
    })
    location.href = '/'
  }
</script>
```

### Registration (user is already signed in)

```ts
app.post('/passkey/register/begin', requireSignIn, async (req, res) => {
  const sid = req.signedCookies['sid']
  const row = sessions.get(sid)!
  const result = await knuckles.passkey.registerBegin({ accessToken: row.accessToken })
  res.json(result)
})

app.post('/passkey/register/complete', requireSignIn, async (req, res) => {
  const sid = req.signedCookies['sid']
  const row = sessions.get(sid)!
  await knuckles.passkey.registerComplete({
    accessToken: row.accessToken,
    credential: req.body.credential,
    state: req.body.state,
    name: req.body.name,
  })
  res.json({ ok: true })
})
```

The frontend uses `navigator.credentials.create()` instead of `.get()`.
Same shape otherwise.

{: .tip }
Once a user has a passkey, they can sign in without typing
anything: their device autofills the passkey choice when they
tap a "Sign in" button. This is by far the smoothest sign-in
experience available today.

---

## Common patterns from here

- **Get the user's profile from Knuckles directly:**
  `await knuckles.me({ accessToken: row.accessToken })` — useful if
  the user updated their email elsewhere.
- **Sign the user out everywhere (every device):**
  `await knuckles.logoutAll({ accessToken: row.accessToken })`.

See [Recipes](recipes.html) for these and more.

---

## Where the SDK lives

Source:
[`packages/knuckles-client-ts/`](https://github.com/gsooter/knuckles/tree/main/packages/knuckles-client-ts).
npm: [`@knuckles/client`](https://www.npmjs.com/package/@knuckles/client).

The SDK is small (~700 lines) and fully typed. If you ever wonder
"what does `knuckles.google.start` actually send?", read the source
— it's a thin wrapper over `fetch`.

---
title: Concepts
layout: default
nav_order: 2
description: "Plain-English explanations of the auth ideas Knuckles uses."
---

# Concepts
{: .no_toc }

A friendly tour of the ideas behind "logging in." If you've never
wired up authentication before, read this once before touching any
code. None of it is Knuckles-specific — these are the building blocks
every login system uses.

<details open markdown="block">
<summary>Table of contents</summary>

1. TOC
{:toc}

</details>

---

## What "logging in" actually means

When someone "logs in," two questions get answered:

1. **Who are you?** (identity) — usually proven with an email, a
   password, a Google account, a fingerprint, or a hardware key.
2. **What are you allowed to do here?** (authorization) — once we
   know who you are, what features you can use.

Knuckles answers question 1. Question 2 stays inside your app —
Knuckles tells you "this user is `alice@example.com`," and your app
decides what Alice can do.

Once a user has answered question 1, your app needs a way to remember
them across page loads (otherwise they'd have to sign in on every
click). That's where **sessions** come in.

---

## Sessions, cookies, and tokens

A **session** is just "the system remembers this user is signed in for
a while." There are two common ways to remember:

### Session cookies (the old way)

The server stores a row in a database: "session ID `abc123` belongs to
Alice." It writes a cookie to the browser with that session ID. Every
request, the browser sends the cookie back, and the server looks up
the row.

- 👍 Simple. Server has full control — kicks any session at will.
- 👎 Every API call hits the database to check the session. Bad for
  scaling. Bad for splitting your app into many backend services
  ("microservices") that all need to know who the user is.

### Tokens (what Knuckles uses)

Instead of a database row, the server writes a small **signed string**
called a **token**. The browser sends it back on every request, and
any server with the right verification key can read it without
calling the database.

The token contains a tiny JSON payload like:

```json
{
  "sub": "alice@example.com",
  "exp": 1714099200
}
```

`sub` = subject (who the user is). `exp` = expiration time.

The signature proves the server made the token. If anyone tampers
with the JSON, the signature stops matching.

This kind of signed token is called a **JWT** ("JSON Web Token,"
pronounced "jot").

{: .note }
You don't have to understand the cryptography to use JWTs. The
SDK handles signing and verifying for you. What matters is the
shape: a small payload + a signature.

---

## What a JWT looks like

A JWT is a single string with three parts separated by dots:

```
eyJhbGciOiJSUzI1NiIs...   .   eyJzdWIiOiJhbGljZUBl...   .   X8JtPq2...
       header                       payload                  signature
```

Each part is base64-encoded. The header says what algorithm signed it
(Knuckles uses RS256). The payload is the JSON above. The signature
is the cryptographic proof.

When your app gets a JWT from Knuckles, your app **verifies the
signature locally** using a public key. No network call needed.

That's the whole point of JWTs: every server in your fleet can check
"is this token real and unexpired?" without phoning home.

---

## Access tokens vs. refresh tokens

Knuckles gives your app **two tokens** when a user signs in:

| Token | Lifetime | What it does |
|---|---|---|
| **Access token** | 1 hour | Sent on every API call to prove "this is Alice." A JWT. |
| **Refresh token** | 30 days | Used to get a new access token when the current one expires. Opaque (a random string, not a JWT). |

Why two? Because access tokens are sent on every request — if one
leaks, an attacker only gets 1 hour of access. The refresh token is
sent only when you're getting a new access token, so it's harder to
intercept.

Knuckles **rotates** refresh tokens: every time you use one, you get a
fresh refresh token in return. If anyone tries to reuse the old one,
Knuckles knows there's been a leak and signs the user out everywhere.

---

## OAuth ("Sign in with Google" / "Sign in with Apple")

OAuth is the protocol behind every "Sign in with X" button. The flow:

1. User clicks **"Sign in with Google."**
2. Your app redirects them to `accounts.google.com` with a special
   URL.
3. Google asks "do you want to share your email with this app?"
4. User clicks **Allow.** Google redirects them back to your app
   with a temporary code in the URL.
5. Your app trades that code for the user's identity (email, name,
   profile picture).

That whole back-and-forth is what Knuckles handles for you. You call
two functions — `start()` to get the Google URL, `complete()` after
the user comes back — and Knuckles does steps 2 through 5.

{: .tip }
You'll hear the word **"OAuth flow"** or **"sign-in flow"** a lot.
It just means "the sequence of redirects and API calls that
happens when someone clicks Sign in with Google." Knuckles also
calls these **"ceremonies."**

---

## Magic-link sign-in

Magic-link is the simplest sign-in method:

1. User types their email.
2. You email them a link like
   `https://your-app.com/auth/verify?token=xyz`.
3. User clicks it, lands back on your site, signed in.

No passwords. The token in the URL is a one-time, time-limited proof
that the user controls the email address they typed.

Knuckles handles the email sending (via [Resend](https://resend.com)),
the token generation, the expiry, and the one-time use guarantee.

---

## Passkeys

A passkey is **the modern replacement for passwords.** It's a small
chunk of cryptography stored on the user's device — phone, laptop,
hardware key — that proves they're who they say.

When the user "signs in with a passkey," their device performs a
cryptographic handshake with your site. The user just touches Face
ID / Touch ID / Windows Hello. No password to type, no password to
leak, no password to remember.

The technical name is **WebAuthn**. It's a W3C standard, supported by
every modern browser. Knuckles handles the WebAuthn dance for you.

{: .tip }
Passkeys are the future. If you can only support one method,
support both **email magic-link AND passkey** — they cover almost
every user.

---

## How Knuckles fits into your app

Here's the picture again:

```
[ Browser ]  →  [ Your app's backend ]  →  [ Knuckles ]
                           ↓
                  [ Your app's database ]
```

- **Your backend** is where your business logic lives. It talks to
  Knuckles to start sign-in flows and verify tokens.
- **Knuckles** is a separate small service (you run it). It handles
  every sign-in ceremony. It has its own database (just users,
  passkeys, refresh tokens — nothing about your product).
- **Your database** stores everything else: the user's preferences,
  their data, their orders, their photos, whatever your app actually
  is.

The link between Knuckles and your database is the **user ID** in the
JWT. Knuckles knows Alice as `user_id = uuid-1234`. Your database
stores Alice's preferences keyed by that same `uuid-1234`.

---

## Three things Knuckles does NOT do

It's worth knowing what's *not* in scope, so you don't go looking for
features that aren't there:

1. **Authorization / permissions / roles.** Knuckles tells you who
   the user is. Your app decides what they can do.
2. **User profile data beyond identity.** Knuckles stores email and
   display name. Profile photo URLs, bios, preferences — those go in
   your app's database, not Knuckles.
3. **Connecting external services like Spotify or GitHub.** Knuckles
   does identity OAuth (Google / Apple) but it does *not* manage
   integrations with arbitrary third-party APIs. Those connections
   live in your app.

---

## Glossary

A quick lookup table for terms you'll see across the docs:

| Term | What it means |
|---|---|
| **JWT** | A signed JSON token. Three base64 chunks, dot-separated. |
| **JWKS** | "JWT Key Set." The list of public keys Knuckles publishes so apps can verify signatures. |
| **Issuer (`iss`)** | The URL of who minted a token. For Knuckles tokens, it's the public URL of your Knuckles deployment. |
| **Audience (`aud`)** | The `client_id` of the app the token was minted *for*. Apps reject tokens whose audience doesn't match. |
| **Subject (`sub`)** | The user ID inside the token. |
| **Access token** | Short-lived (1h) JWT sent on every API request. |
| **Refresh token** | Longer-lived (30d) opaque string used to get new access tokens. |
| **OAuth** | The protocol behind "Sign in with Google / Apple." |
| **WebAuthn / passkey** | The standard for fingerprint / Face ID / hardware-key sign-in. |
| **Magic-link** | Sign-in by clicking a one-time link sent to your email. |
| **`app_client`** | A registered app that uses Knuckles. Has a `client_id` + `client_secret`. |
| **CORS** | The rule that controls which other websites' JavaScript can call your API. Relevant if your frontend talks to Knuckles directly. |
| **RS256** | The cryptographic algorithm Knuckles uses for JWT signatures. RSA, 256-bit hash. |

---

## Where to go next

- **Want to see it work right now?** → [Quickstart](quickstart.html)
- **Want the full setup with every step explained?** → [Setup Guide](ONBOARDING.html)
- **Ready to add Knuckles to a real app?** → [Integration](INTEGRATION.html)

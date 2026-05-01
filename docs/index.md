---
title: Welcome
layout: default
nav_order: 1
description: "A drop-in identity service that handles user sign-in for your app."
permalink: /
---

# Knuckles

**A drop-in identity service that handles user sign-in for your app.**
{: .fs-6 .fw-300 }

You're building an app and you need users to be able to sign in.
You want them to use **"Sign in with Google"** or **"Sign in with
Apple"** or get an **email magic link** or use a modern
**passkey** — but you don't want to spend a week learning OAuth, JWT,
WebAuthn, password hashing, session cookies, refresh-token rotation,
key signing, and the other ten things that go into "logging users
in safely."

That's what Knuckles is for.

[Get started in 5 minutes →](quickstart.html){: .btn .btn-primary .fs-5 .mb-4 .mb-md-0 .mr-2 }
[I want to understand it first](concepts.html){: .btn .fs-5 }

---

## What it does for you

You run **one small service** (Knuckles itself), and you add **one
small library** to your app. From then on:

- A user clicks "Sign in with Google" → Knuckles handles the whole
  back-and-forth with Google → your app gets back the user's email
  and a token that proves who they are.
- Same flow for Apple, magic-link email, or passkey.
- Your app never sees a password. You never write password reset
  flows. You never store password hashes. You never get pwned by a
  password leak.
- Tokens are validated **inside your app** with no network call —
  fast, private, works even if Knuckles is briefly down.

## Who this is for

You should keep reading if any of these match:

- ✅ You're building a web app (or mobile app, or anything that has
  users).
- ✅ You want to add "Sign in with Google" or similar without
  becoming an OAuth expert.
- ✅ You're comfortable running a small service somewhere
  (Railway, Render, Fly, your own Docker host) — but you don't want
  to manage user databases yourself.
- ✅ You want strong security defaults (rotating tokens, modern
  passkey support, signed JWTs) without making security decisions.

You should look elsewhere if:

- ❌ You don't want to run *any* service at all — try a hosted
  identity provider like Auth0, Clerk, or Supabase Auth instead.
- ❌ You need extremely advanced features like SAML SSO,
  fine-grained permissions, or enterprise SCIM provisioning.

---

## What's in this site

<div class="code-example" markdown="1">

| Page | What you'll find |
|---|---|
| [Concepts](concepts.html) | Plain-English explanations of "what is logging in," sessions, JWTs, OAuth, passkeys, magic links. **Start here if you've never wired up auth before.** |
| [Quickstart](quickstart.html) | The fastest path from "git clone" to "I see a real user signed in." Five minutes. |
| [Setup Guide](ONBOARDING.html) | The full step-by-step setup for your own Knuckles deployment, with every command and every env var explained. |
| [Integration](INTEGRATION.html) | How to add Knuckles to your existing app. Has sub-pages for Python and TypeScript. |
| [Recipes](recipes.html) | Copy-paste solutions for common needs: protecting routes, logging users out, refreshing tokens, etc. |
| [Error reference](errors.html) | Every error code Knuckles can return, what it means, and how to recover. |
| [API Reference](api/) | Auto-generated reference for every HTTP endpoint, for if you're rolling your own client. |
| [FAQ](faq.html) | Questions beginners actually ask. |

</div>

---

## A typical setup, in three pictures

**1. You run Knuckles.** It's a small Python web service. Stick it on
Railway / Render / Fly / wherever — costs you a couple bucks a month.

```
[ users ]  →  [ your app ]  →  [ Knuckles ]  →  [ Postgres ]
                                       ↑
                              [ Google / Apple / Resend ]
```

**2. You install the SDK in your app.**

```python
# Python
pip install knuckles-client
```

```bash
# Node / TypeScript
npm install @knuckles/client
```

**3. You write a few lines of code to drive sign-in.**

```python
from knuckles_client import KnucklesClient

knuckles = KnucklesClient(
    base_url="https://auth.your-app.com",
    client_id="your-app",
    client_secret="...",
)

# When a user clicks "Sign in with Google":
start = knuckles.google.start(redirect_url="https://your-app.com/auth/callback")
# Send the user's browser to start.authorize_url
# Google redirects back to your callback with code + state in the URL
# Then:
session = knuckles.google.complete(code=code, state=state)
# session.access_token + session.refresh_token are yours to store
```

That's the whole shape. Every page in this site fills in the details
of one piece of that picture.

---

## Where to go next

- **Brand new to web auth?** → [Concepts](concepts.html) for the
  vocabulary, then [Quickstart](quickstart.html) for hands-on.
- **You know the drill, just show me the code.** →
  [Quickstart](quickstart.html) → [Integration](INTEGRATION.html)
  → your language.
- **Already have Knuckles running, just need to wire up an app.** →
  [Integration](INTEGRATION.html).
- **Something's broken.** → [FAQ](faq.html).

---

## Roadmap

Today Knuckles is a **self-hosted service** — you deploy it
separately and your apps talk to it over HTTP. That's the right
shape for shops with multiple apps, isolation requirements, or a
non-Python backend.

**Library mode** — `pip install knuckles` and three lines of code
in your existing Flask app — is the next planned milestone. It will
target the same niche the [Lucia](https://lucia-auth.com/) library
fills for TypeScript: drop-in modern auth (passkeys + OAuth +
magic-link) with no separate infrastructure to deploy. See
[`DECISIONS.md`](https://github.com/gsooter/knuckles/blob/main/DECISIONS.md)
for the architectural trade-offs and why this is a future change,
not a current one.

The HTTP API and SDK shape will remain stable — apps integrating
today will keep working unchanged when library mode lands.

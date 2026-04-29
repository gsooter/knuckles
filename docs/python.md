---
title: Python
layout: default
parent: Integration
nav_order: 1
description: "Step-by-step walkthrough: a real Flask app that signs users in with Knuckles."
---

# Python integration walkthrough
{: .no_toc }

We're going to build a tiny Flask app, **from empty folder to
real users signing in,** using the `knuckles-client` SDK. By the end
you'll have:

- A `/sign-in` page that offers Google and magic-link.
- Working OAuth callbacks for both.
- A `/me` endpoint that's protected by a real signed token.
- Server-side cookie storage for the access token, with silent
  refresh.

The same pattern works for FastAPI, Django, Pyramid — anywhere you
have HTTP handlers and a session store. Flask is just the most
beginner-friendly to read.

<details open markdown="block">
<summary>Table of contents</summary>

1. TOC
{:toc}

</details>

---

## Before you start

You need:

- **Knuckles running and reachable.** Either on your laptop (see
  [Quickstart](quickstart.html)) or somewhere deployed.
- **An app-client registered** with `--allowed-origin
  http://localhost:5000`. From the Knuckles repo:
  ```bash
  python scripts/register_app_client.py \
      --client-id my-flask-app \
      --app-name "My Flask App" \
      --allowed-origin http://localhost:5000
  ```
  Save the `client_secret` it prints.
- **Google OAuth set up in Knuckles** (see
  [Setup Guide](ONBOARDING.html), Part 3.2) with
  `http://localhost:5000/auth/google/callback` in the authorized
  redirect URIs.

---

## Step 1 — Set up the project

```bash
mkdir my-flask-app && cd my-flask-app
python3.12 -m venv .venv
source .venv/bin/activate

pip install flask knuckles-client python-dotenv
```

Create `.env`:

```bash
KNUCKLES_URL=http://localhost:5001
KNUCKLES_CLIENT_ID=my-flask-app
KNUCKLES_CLIENT_SECRET=kn_xxxxxxxxxxxxxxxxxxxxx
FLASK_SECRET_KEY=any-long-random-string
```

The `FLASK_SECRET_KEY` is unrelated to Knuckles — Flask uses it to
sign session cookies for storing your **own** session data
(specifically, the refresh token).

---

## Step 2 — Create the Knuckles client (one place)

Make `knuckles.py` — a thin module that owns the SDK instance.

```python
# knuckles.py
"""Single source of the configured Knuckles client."""
from __future__ import annotations

import os

from knuckles_client import KnucklesClient


def get_client() -> KnucklesClient:
    """Build a process-singleton Knuckles client.

    Returns:
        The shared KnucklesClient.
    """
    return KnucklesClient(
        base_url=os.environ["KNUCKLES_URL"],
        client_id=os.environ["KNUCKLES_CLIENT_ID"],
        client_secret=os.environ["KNUCKLES_CLIENT_SECRET"],
    )


client = get_client()
```

The SDK is safe to keep as a module-level singleton — it caches JWKS
internally and is thread-safe.

---

## Step 3 — Build the app skeleton

Make `app.py`:

```python
# app.py
import os
from flask import Flask, render_template_string, request, redirect, url_for, session, jsonify, abort
from dotenv import load_dotenv

from knuckles import client
from knuckles_client.exceptions import (
    KnucklesAuthError,
    KnucklesTokenError,
    RefreshTokenReusedError,
    RefreshTokenExpiredError,
)

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET_KEY"]


@app.get("/")
def index():
    if session.get("user_id"):
        return f'<p>Signed in as {session["email"]}.</p><p><a href="/logout">Sign out</a></p>'
    return '<a href="/sign-in">Sign in</a>'


if __name__ == "__main__":
    app.run(port=5000, debug=True)
```

Run it:

```bash
flask --app app run --port 5000 --debug
```

Visit `http://localhost:5000` — you should see "Sign in." Now we'll
make the link actually work.

---

## Step 4 — The sign-in page

Add a `/sign-in` route that offers two methods:

```python
@app.get("/sign-in")
def sign_in():
    return render_template_string("""
      <h1>Sign in</h1>
      <form method="post" action="/sign-in/magic-link">
        <input type="email" name="email" placeholder="you@example.com" required />
        <button>Email me a link</button>
      </form>
      <hr>
      <a href="/sign-in/google">Sign in with Google</a>
    """)
```

---

## Step 5 — Wire up Google sign-in

Two routes: one starts the flow, one completes it.

```python
@app.get("/sign-in/google")
def google_start():
    """Redirect the user to Google's consent page."""
    result = client.google.start(
        redirect_url=url_for("google_callback", _external=True),
    )
    # We don't need to keep the state — Knuckles validates it on complete().
    return redirect(result.authorize_url)


@app.get("/auth/google/callback")
def google_callback():
    """Google sent the user back. Trade code+state for tokens."""
    code = request.args["code"]
    state = request.args["state"]

    pair = client.google.complete(code=code, state=state)

    _store_session(pair.access_token, pair.refresh_token)
    return redirect("/")
```

The `_store_session` helper writes the access token and the user's
identity into Flask's session cookie, and tucks the refresh token
into a server-side store (we'll use the session for both for
simplicity, but in real apps you'd want a database):

```python
def _store_session(access_token: str, refresh_token: str) -> None:
    """Persist the tokens after a successful sign-in.

    Args:
        access_token: The RS256 access token from Knuckles.
        refresh_token: The opaque refresh token from Knuckles.
    """
    claims = client.verify_access_token(access_token)
    session["user_id"] = claims["sub"]
    session["email"] = claims.get("email")
    session["access_token"] = access_token
    session["refresh_token"] = refresh_token
```

{: .note }
We use Flask's signed-cookie session here for brevity. In a real
app, store the **refresh token server-side** (in Postgres /
Redis), keyed by your own session ID. The browser only ever sees
the session ID — never the refresh token.

---

## Step 6 — Wire up magic-link sign-in

Two routes again: one sends the email, one verifies the token.

```python
@app.post("/sign-in/magic-link")
def magic_link_start():
    """Email the user a magic link."""
    email = request.form["email"]
    client.magic_link.start(
        email=email,
        redirect_url=url_for("magic_link_verify", _external=True),
    )
    return "Check your email for a sign-in link."


@app.get("/auth/verify")
def magic_link_verify():
    """Redeem the magic-link token from the URL."""
    token = request.args["token"]
    pair = client.magic_link.verify(token=token)
    _store_session(pair.access_token, pair.refresh_token)
    return redirect("/")
```

Try it: visit `/sign-in`, type your email, watch the Knuckles terminal
for the link, paste it into your browser. You should land back on `/`
signed in.

---

## Step 7 — Protect a route

The pattern: read the access token, verify it locally, do something
with `claims["sub"]`. Wrap it in a decorator:

```python
from functools import wraps


def signed_in(view):
    """Decorator that requires a verified Knuckles access token.

    Args:
        view: The Flask view to wrap.

    Returns:
        The wrapped view that 401s on missing/bad tokens.
    """
    @wraps(view)
    def wrapped(*args, **kwargs):
        token = session.get("access_token")
        if not token:
            return jsonify({"error": "not signed in"}), 401
        try:
            claims = client.verify_access_token(token)
        except KnucklesTokenError:
            # Try a silent refresh.
            if not _try_refresh():
                return jsonify({"error": "session expired"}), 401
            claims = client.verify_access_token(session["access_token"])
        request.user_id = claims["sub"]
        request.email = claims.get("email")
        return view(*args, **kwargs)
    return wrapped


@app.get("/me")
@signed_in
def me():
    return jsonify({"user_id": request.user_id, "email": request.email})
```

`verify_access_token` does the JWKS-cached signature check locally —
no network call after the first verify of the process.

---

## Step 8 — Silent refresh

When the access token expires (1h after sign-in), use the refresh
token to get a fresh pair:

```python
def _try_refresh() -> bool:
    """Trade the stored refresh token for a new pair.

    Returns:
        True if refresh succeeded; False if the user must sign in again.
    """
    refresh = session.get("refresh_token")
    if not refresh:
        return False
    try:
        pair = client.tokens.refresh(refresh_token=refresh)
    except (RefreshTokenReusedError, RefreshTokenExpiredError):
        # Either the token leaked and was used elsewhere (reuse-detected),
        # or its 30-day window elapsed. Either way the user must sign in.
        session.clear()
        return False
    session["access_token"] = pair.access_token
    session["refresh_token"] = pair.refresh_token  # IMPORTANT: rotate
    return True
```

{: .important }
**Always store the new refresh token from the response.** Knuckles
rotates refresh tokens — the old one becomes invalid the moment
you use it. If you forget to update your storage, the next
refresh attempt fires `RefreshTokenReusedError` and the user is
signed out everywhere.

---

## Step 9 — Sign out

```python
@app.get("/logout")
def logout():
    """Revoke the refresh token and clear the local session."""
    refresh = session.get("refresh_token")
    if refresh:
        try:
            client.tokens.revoke(refresh_token=refresh)
        except KnucklesAuthError:
            pass  # Already revoked / expired — fine, just clear locally.
    session.clear()
    return redirect("/")
```

`tokens.revoke` is idempotent — if the token's already used or
expired, it's a no-op.

---

## Step 10 — Try the whole thing

```bash
flask --app app run --port 5000 --debug
```

Open `http://localhost:5000`:

1. Click **Sign in.**
2. Try **Sign in with Google** → land back on `/` showing your email.
3. Click **Sign out.**
4. Try the magic-link form → check the Knuckles terminal for the link
   → paste → land on `/` again.
5. Hit `http://localhost:5000/me` → see your user ID and email as JSON.

That's a complete integration. ✅

---

## What you just built (in 70 lines of glue)

```
[ user ] →  /  →  /sign-in  →  /sign-in/google → Google → /auth/google/callback
                                /sign-in/magic-link → Resend → /auth/verify
[ user ] →  /me  →  signed_in decorator → verify_access_token (cached JWKS, local)
                                       → on 401: _try_refresh → tokens.refresh
[ user ] →  /logout  →  tokens.revoke + session.clear
```

The whole sign-in story in one page, with no Knuckles internals
leaking into your code.

---

## Common patterns from here

- **Want to call Knuckles for the user profile?** Use
  `client.users.me(access_token=session["access_token"])`. It returns
  a fresh copy of the user's profile (in case they updated it
  somewhere else).
- **Want to enroll passkeys?** Add `passkey.register_begin()` /
  `passkey.register_complete()` once a user is signed in. The
  walkthrough is in the [TypeScript guide](typescript.html#passkeys)
  because you need browser JS to do the WebAuthn API call — the
  Python pattern is the same on the backend, with the browser doing
  the cryptography in between.
- **Want to log the user out of every device, not just this one?** Use
  `client.tokens.revoke_all(access_token=...)`. Hits
  `/v1/logout/all`, which kills every refresh token for the user.

See [Recipes](recipes.html) for these and more.

---

## Where the SDK lives

Source: [`packages/knuckles-client-py/`](https://github.com/gsooter/knuckles/tree/main/packages/knuckles-client-py).
PyPI: [`knuckles-client`](https://pypi.org/project/knuckles-client/).

The SDK is small and readable — about 800 lines including tests. If
you ever wonder "what does `client.google.start` actually do?", you
can read it in 30 seconds.

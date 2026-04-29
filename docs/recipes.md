---
title: Recipes
layout: default
nav_order: 6
description: "Copy-paste solutions for common needs: protecting routes, refreshing, signing out everywhere, and more."
---

# Recipes
{: .no_toc }

Short, copy-pasteable solutions for things you'll need to do once
you have a working integration. Each recipe is independent — pick
the ones you need.

<details open markdown="block">
<summary>Table of contents</summary>

1. TOC
{:toc}

</details>

---

## Protect a route

Only let signed-in users in.

### Python (Flask)

```python
from functools import wraps
from flask import session, jsonify, request
from knuckles_client.exceptions import KnucklesTokenError

from knuckles import client


def signed_in(view):
    @wraps(view)
    def wrapped(*a, **kw):
        token = session.get("access_token")
        if not token:
            return jsonify({"error": "unauthorized"}), 401
        try:
            claims = client.verify_access_token(token)
        except KnucklesTokenError:
            return jsonify({"error": "unauthorized"}), 401
        request.user_id = claims["sub"]
        return view(*a, **kw)
    return wrapped
```

### TypeScript (Express)

```ts
import { KnucklesTokenError } from '@knuckles/client'

export async function requireSignIn(req, res, next) {
  const sid = req.signedCookies['sid']
  const row = sid ? sessions.get(sid) : undefined
  if (!row) return res.status(401).json({ error: 'unauthorized' })
  try {
    const claims = await knuckles.verifyAccessToken(row.accessToken)
    req.user = { id: claims.sub, email: claims.email }
    next()
  } catch (err) {
    if (err instanceof KnucklesTokenError) return res.status(401).json({ error: 'unauthorized' })
    throw err
  }
}
```

---

## Refresh the access token silently

When the access token expires, get a new pair from the refresh token
without bothering the user.

### Python

```python
from knuckles_client.exceptions import KnucklesAuthError

def try_refresh(session) -> bool:
    refresh = session.get("refresh_token")
    if not refresh:
        return False
    try:
        pair = client.refresh(refresh)
    except KnucklesAuthError as exc:
        if exc.code in {"REFRESH_TOKEN_REUSED", "REFRESH_TOKEN_EXPIRED"}:
            session.clear()
            return False
        raise
    session["access_token"] = pair.access_token
    session["refresh_token"] = pair.refresh_token  # ← rotate!
    return True
```

### TypeScript

```ts
import { KnucklesAuthError } from '@knuckles/client'

async function tryRefresh(row): Promise<boolean> {
  try {
    const pair = await knuckles.refresh(row.refreshToken)
    row.accessToken = pair.accessToken
    row.refreshToken = pair.refreshToken  // ← rotate!
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
**Always** persist the new refresh token from the response. The
old one is invalidated the moment you use it.

---

## Sign the user out

Revoke the refresh token and clear the local session.

### Python

```python
from knuckles_client.exceptions import KnucklesAuthError

@app.get("/logout")
def logout():
    if refresh := session.get("refresh_token"):
        try:
            client.logout(refresh)
        except KnucklesAuthError:
            pass  # already revoked, fine
    session.clear()
    return redirect("/")
```

### TypeScript

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

## Sign the user out of EVERY device

Useful for "Sign out everywhere" buttons in account settings.

### Python

```python
@app.post("/account/sign-out-everywhere")
@signed_in
def sign_out_everywhere():
    client.logout_all(access_token=session["access_token"])
    session.clear()
    return redirect("/")
```

### TypeScript

```ts
app.post('/account/sign-out-everywhere', requireSignIn, async (req, res) => {
  const row = sessions.get(req.signedCookies['sid'])!
  await knuckles.logoutAll({ accessToken: row.accessToken })
  sessions.delete(req.signedCookies['sid'])
  res.clearCookie('sid')
  res.redirect('/')
})
```

This kills every refresh token for the user — every browser, every
phone, every tab.

---

## Get the user's current profile

The access token contains a snapshot of the user's email at sign-in
time. If they update their email later (via another app), the token
still has the old value. To get the freshest copy:

### Python

```python
profile = client.me(access_token=session["access_token"])
# profile.id, profile.email, profile.display_name, profile.avatar_url
```

### TypeScript

```ts
const profile = await knuckles.me({ accessToken: row.accessToken })
```

---

## Force an extra check on a sensitive action

For "delete account" or "change email" — actions you want re-auth for
even within an existing session — require a *fresh* sign-in (within
the last few minutes).

```python
def require_recent_sign_in(max_age_seconds: int = 300):
    def deco(view):
        @wraps(view)
        @signed_in
        def wrapped(*a, **kw):
            claims = client.verify_access_token(session["access_token"])
            iat = claims["iat"]
            if time.time() - iat > max_age_seconds:
                return jsonify({"error": "please sign in again"}), 401
            return view(*a, **kw)
        return wrapped
    return deco

@app.post("/account/delete")
@require_recent_sign_in(max_age_seconds=300)
def delete_account():
    ...
```

The `iat` claim ("issued at") tells you when the access token was
minted. After silent refresh, this resets — so a user has to actually
sign in again, not just keep the session alive.

---

## List a user's passkeys

For an account-settings page where users see their devices.

### Python

```python
passkeys = client.passkey.list(access_token=session["access_token"])
for pk in passkeys:
    print(pk.credential_id, pk.name, pk.created_at)
```

### TypeScript

```ts
const passkeys = await knuckles.passkey.list({ accessToken: row.accessToken })
```

---

## Delete a passkey

```python
client.passkey.delete(
    credential_id="cred-uuid-here",
    access_token=session["access_token"],
)
```

```ts
await knuckles.passkey.delete({
  credentialId: 'cred-uuid-here',
  accessToken: row.accessToken,
})
```

Knuckles enforces ownership — you can't delete someone else's passkey
even if you know its ID.

---

## Handle "this email is already used by another method"

When a user signs in with Google but their email already has a
magic-link account (or vice versa), Knuckles links the two
automatically — same email = same user. You don't have to do
anything special.

But if you want to **show** the user a message like "we noticed you
previously signed in with Google," you can detect it by checking
whether the user already had OAuth providers attached. Add a column
to your own user table that you update on every sign-in:

```python
@app.get("/auth/verify")
def magic_link_verify():
    pair = client.magic_link.verify(request.args["token"])
    claims = client.verify_access_token(pair.access_token)

    user_row = my_db.upsert_user(
        knuckles_user_id=claims["sub"],
        email=claims["email"],
        last_sign_in_method="magic_link",
    )
    # ...
```

---

## Block CORS to your Knuckles deployment

By default Knuckles allows any origin to request `/.well-known/jwks.json`
(for JWKS to work cross-origin). Most other endpoints don't accept
direct browser calls anyway because they require client headers.

If you want strict CORS — only echo `Access-Control-Allow-Origin` for
origins registered with an `app_client` — set:

```
KNUCKLES_STRICT_CORS=true
```

This is recommended for production deploys you don't want strangers
poking at.

---

## Wire a healthcheck dashboard

If you run something like Better Stack / Upptime / a status page:

| What to monitor | URL | Expected |
|---|---|---|
| Liveness | `GET /health` | 200, body `{"status":"ok"}` |
| JWKS | `GET /.well-known/jwks.json` | 200, JSON with `keys[]` |
| OIDC metadata | `GET /.well-known/openid-configuration` | 200, JSON with `issuer` and `jwks_uri` |

If any of those fail, the rest of your apps will start failing token
verification within ~1h (cached JWKS keys time out).

---

## Run the magic-link cleanup nightly

`scripts/cleanup_magic_links.py` deletes expired magic-link rows.
Wire it to your platform's scheduler:

**Railway** — add a "Scheduled job" service with the command:

```bash
python scripts/cleanup_magic_links.py --older-than-hours 24
```

**Cron** (your own server):

```cron
0 3 * * * /path/to/python /path/to/scripts/cleanup_magic_links.py --older-than-hours 24
```

Idempotent — safe to run as often as you want.

---

## Need a recipe that isn't here?

Open an issue on [GitHub](https://github.com/gsooter/knuckles/issues)
or check the [FAQ](faq.html). The
[Setup Guide](ONBOARDING.html) covers operational tasks (key rotation,
secret rotation, incident response).

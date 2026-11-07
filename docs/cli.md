---
title: CLI
layout: default
nav_order: 9
description: "Set up and check Knuckles tenants from the command line."
---

# The `knuckles` CLI

The CLI is the quickest way to add a new site to your Knuckles server.
It creates the tenant, writes the app's credentials into its `.env`,
configures each sign-in method from the files the provider consoles
give you, and tells you what's still wrong.

```bash
pip install knuckles-cli
```

{: .note }
Your Knuckles server needs `KNUCKLES_ADMIN_TOKEN` set. Without it the
admin API is switched off, and the CLI reports `ADMIN_API_DISABLED`.

## Set up a new site

```bash
knuckles login --url https://auth.example.com          # prompts for the admin token

knuckles init my-site --name "My Site" \
  --origin https://my-site.com --origin http://localhost:3000 \
  --env-file ../my-site/.env
```

Your app now has `KNUCKLES_URL`, `KNUCKLES_CLIENT_ID` and
`KNUCKLES_CLIENT_SECRET` in its `.env`. Next, turn on the sign-in
methods you want.

### Email magic links

Add your sending domain in Resend and wait until it shows
**Verified**. Then:

```bash
knuckles providers email my-site --from "My Site <signin@mail.my-site.com>"
```

The CLI asks for the Resend API key and checks that the domain is
verified before storing anything.

### Sign in with Google

In Google Cloud Console, create an OAuth client of type **Web
application**, add your app's callback URL as an authorized redirect
URI, and click **Download JSON**. Then:

```bash
knuckles providers google my-site --client-secret-json ~/Downloads/client_secret_*.json
```

If a redirect URI's origin isn't one of the site's allowed origins,
the CLI warns you, because that sign-in would be rejected.

### Sign in with Apple

You need your Apple team id, the Services ID for the website, and the
Sign in with Apple key file (`AuthKey_<KEYID>.p8`):

```bash
knuckles providers apple my-site --services-id com.my-site.web \
  --team-id AB12CD34EF --p8 ~/Downloads/AuthKey_ABCDE12345.p8
```

The CLI reads the key id from the filename and checks the key's type
before uploading.

### Passkeys

```bash
knuckles providers passkey my-site --origin https://my-site.com
```

{: .warning }
Once users have registered passkeys, changing the `rp_id` invalidates
every one of them. The server refuses unless you pass `--force-rp-id`.

## Check everything

```bash
knuckles doctor my-site
```

```
✓ health: Server and database are up.
✓ issuer: Tokens are issued by https://auth.example.com.
✓ jwks: 1 signing key(s) published.
✓ https: Served over HTTPS.
✓ my-site: origins: https://my-site.com, http://localhost:3000
✓ my-site: email: Configured.
! my-site: apple: Not configured. ...
✓ my-site: passkey: rp_id my-site.com for https://my-site.com.
```

`doctor` exits with status 1 if any check fails, so you can run it in
CI after a deploy.

## Using it from scripts and coding agents

Put `--json` before the subcommand to get the same
`{"data": ...}` / `{"error": {"code", "message"}}` envelope as the
API. `KNUCKLES_URL` and `KNUCKLES_ADMIN_TOKEN` work in place of
`login`. The full command reference is in the
[package README](https://github.com/gsooter/knuckles/tree/main/packages/knuckles-cli).

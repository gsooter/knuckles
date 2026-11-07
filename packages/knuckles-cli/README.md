# knuckles-cli

The operator CLI for [Knuckles](https://github.com/gsooter/knuckles).
It lets you add a new site, configure its sign-in methods, and check
that everything is wired correctly, using just your Knuckles URL and
admin token. You don't need a checkout, database access, or `curl`.

```bash
pip install knuckles-cli
```

It talks to a running Knuckles over HTTP only: the public discovery
endpoints plus the `/v1/admin/*` API, so the server needs
`KNUCKLES_ADMIN_TOKEN` set (Decisions #021 and #025).

## Five-minute setup for a new site

```bash
# 1. Point the CLI at your server. The token is read from
#    $KNUCKLES_ADMIN_TOKEN, a file (--token-file, '-' = stdin), or a
#    hidden prompt. It never goes on the command line.
knuckles login --url https://auth.example.com

# 2. Create the tenant and drop its credentials into the app's .env
knuckles init my-site --name "My Site" \
  --origin https://my-site.com --origin http://localhost:3000 \
  --env-file ../my-site/.env

# 3. Turn on sign-in methods (any subset)
knuckles providers email   my-site --from "My Site <signin@mail.my-site.com>"
knuckles providers google  my-site --client-secret-json ~/Downloads/client_secret_*.json
knuckles providers apple   my-site --services-id com.my-site.web \
  --team-id AB12CD34EF --p8 ~/Downloads/AuthKey_ABCDE12345.p8
knuckles providers passkey my-site --origin https://my-site.com

# 4. Check it
knuckles doctor my-site
```

## Commands

| Command | What it does |
|---|---|
| `login --url URL` | Verifies the admin token against the server, then stores the profile. |
| `logout` | Forgets the stored profile. |
| `init ID --name N --origin O [--env-file F]` | Creates a tenant and prints the next setup steps. |
| `apps list` / `apps show ID` | Lists tenants, or shows one. Secrets appear only as `*_configured` booleans. |
| `apps create ID --name N --origin O [--env-file F]` | Creates a tenant without the next-steps output. |
| `apps rotate-secret ID [--env-file F --force]` | Mints a new client secret. The old one stops working immediately. |
| `apps set-origins ID ORIGIN...` | Replaces the tenant's allowed origins. |
| `providers google ID --client-secret-json F` | Configures Google from the JSON file Google Cloud Console downloads. It warns if a redirect URI's origin isn't allowed. |
| `providers apple ID --services-id S --team-id T --p8 F` | Checks the key is P-256 and reads the key id from `AuthKey_<KEYID>.p8`. |
| `providers email ID --from ADDR` | Configures Resend. It checks that the sending domain is verified before storing the key. |
| `providers passkey ID --origin O [--rp-id R]` | Derives the WebAuthn relying party and checks that the origin fits under the `rp_id`. |
| `providers clear ID GROUP` | Resets `email`, `google`, `apple` or `passkey` to the operator env fallback. |
| `doctor [ID]` | Checks the server (health, `issuer`, JWKS, HTTPS) and each tenant (origins, config groups, passkey fit). |

### Where secrets come from

The CLI never takes a secret as a command-line argument, because
those end up in shell history and `ps`. Each secret is read from the
first source available:

| Secret | `--*-file` option (`-` = stdin) | Env var | Otherwise |
|---|---|---|---|
| Admin token | `login --token-file` | `KNUCKLES_ADMIN_TOKEN` | hidden prompt |
| Resend API key | `--api-key-file` | `KNUCKLES_RESEND_API_KEY` | hidden prompt |
| Google client secret (manual entry) | `--client-secret-file` | `KNUCKLES_GOOGLE_CLIENT_SECRET` | hidden prompt |

## For scripts and coding agents

- Pass `--json` (before the subcommand) to get the Knuckles API
  envelope: `{"data": ...}` on success, `{"error": {"code", "message"}}`
  on failure. Server error codes such as `APP_CLIENT_NOT_FOUND` are
  passed through verbatim.
- Exit codes: `0` success, `1` failure (including any failing
  `doctor` check), `2` usage error.
- No config file needed: `KNUCKLES_URL` and `KNUCKLES_ADMIN_TOKEN`
  override the stored profile.
- Profiles are stored in `$XDG_CONFIG_HOME/knuckles/config.json`
  (mode 0600), or at `KNUCKLES_CONFIG` if that's set. Select one with
  `--profile NAME` or `KNUCKLES_PROFILE`.

## What `doctor` can't see

`doctor` sees only what the admin API returns. Encrypted values show
up as booleans, and whether an empty group inherits the operator's
env vars depends on server-side state
(`KNUCKLES_ALLOW_ENV_TENANT_FALLBACK`). That's why empty groups are
warnings, not failures. Resend domain verification is checked once,
by `providers email`, while the key is in hand.

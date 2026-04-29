# Knuckles

A drop-in identity service that handles user sign-in for your app —
**Sign in with Google**, **Sign in with Apple**, **email magic
link**, and **WebAuthn passkey** — without making you become an
OAuth/JWT/WebAuthn expert.

**Documentation:** <https://gsooter.github.io/knuckles/>

**Python SDK:** [`pip install knuckles-client`](https://pypi.org/project/knuckles-client/)

---

## What's in this repo

```
knuckles/                    # The Knuckles Flask service (self-hosted today)
packages/
├── knuckles-client-py/      # Python SDK on PyPI as `knuckles-client`
└── knuckles-client-ts/      # TypeScript SDK (source; not yet on npm)
docs/                        # Beginner-friendly docs site (GitHub Pages)
examples/                    # Next.js, Express, Flask middleware examples
scripts/                     # Admin CLI (register an app_client, etc.)
```

## Today's architecture: self-hosted service + SDK

You deploy `knuckles/` to Railway / Render / Fly / your own Docker
host. Your apps install the `knuckles-client` SDK and call your
Knuckles instance over HTTP. Tokens are RS256-signed JWTs that your
apps verify locally against the JWKS endpoint — no per-request
network call.

The full setup (15 minutes from scratch) is at
<https://gsooter.github.io/knuckles/setup>. Apple and Google API key
walkthroughs are step-by-step there.

## Roadmap

A **library mode** — `pip install knuckles` and three lines in your
Flask app, no separate service to deploy — is on the roadmap. The
goal: become for Python what [Lucia](https://lucia-auth.com/) is for
TypeScript. See
[`DECISIONS.md`](DECISIONS.md) entry #016 for the architectural
trade-offs and migration plan.

The HTTP API and SDK shape stay stable. Apps integrating today
will keep working unchanged when library mode lands.

## Scope (the one hard rule)

**Identity only.** Knuckles owns: user accounts, sign-in ceremonies,
JWT issuance, refresh-token rotation, passkey credentials. Knuckles
does not own: music-service connections, profile data beyond email
and display name, analytics, product data, or anything else that
isn't "who is this person and how do they prove it." Full rule in
[`CLAUDE.md`](CLAUDE.md).

## Token model

- **Access token** — RS256 JWT, 1h TTL, validated locally against
  the JWKS endpoint.
- **Refresh token** — opaque, 30d TTL, rotated on every use,
  reuse-detection revokes every refresh token for the user.
- **Key id (`kid`)** — every token carries the `kid` of the signing
  key; JWKS publishes the public key so rotation is a config change.

## Local dev (running the service yourself)

```bash
# Generate an RS256 keypair for JWT signing
openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048
KNUCKLES_JWT_PRIVATE_KEY=$(base64 < private.pem | tr -d '\n')

cp .env.example .env
# Paste KNUCKLES_JWT_PRIVATE_KEY into .env
# Generate KNUCKLES_STATE_SECRET:
#   python -c "import secrets; print(secrets.token_urlsafe(48))"

pip install -e ".[dev]"
alembic -c knuckles/alembic.ini upgrade head
flask --app knuckles.app run --port 5001
```

Full walkthrough including Postgres, Resend, Google OAuth, Apple
OAuth, and passkey config: <https://gsooter.github.io/knuckles/setup>.

## Tests

```bash
pytest --cov=knuckles --cov-fail-under=80
```

## License

MIT. See [`LICENSE`](LICENSE).

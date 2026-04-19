# Knuckles

Centralized identity and authentication service. Knuckles owns user
accounts, login ceremonies, and JWT issuance for a set of consuming
applications.

**Scope: identity only.** Knuckles never touches music services,
analytics, product data, or anything else that isn't "who is this person
and how do they prove it." See `CLAUDE.md` for the full scope rule.

Consuming apps (Greenroom is the first) register as `app_clients` and
validate Knuckles-issued JWTs locally via the public JWKS endpoint. No
app re-implements sign-in.

## Identity paths (all ship in the first release)

- **WebAuthn passkey** — primary, listed first in every consuming-app
  login UI.
- **Sign in with Apple**.
- **Sign in with Google**.
- **Email magic link** (SendGrid).

## Token model

- **Access token** — RS256 JWT, 1h TTL, validated locally by consuming
  apps against the JWKS.
- **Refresh token** — opaque, 30d TTL, rotated on every use, revoked on
  logout.
- **Key id (`kid`)** — every access token carries the `kid` of the
  signing key; JWKS publishes all currently-valid public keys so
  rotation is a config change.

## Consuming-app integration

Each app registers once:

- `client_id` — public identifier, sent on every Knuckles request.
- `client_secret` — used for server-to-server callbacks (e.g. token
  refresh on behalf of a specific app). Never shipped to browsers.
- Allowed origins for CORS.

JWTs carry `app_client_id` in the `aud` claim. Apps reject tokens whose
audience is not their own.

## Local development

```bash
# Generate an RS256 keypair for JWT signing
openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048
base64 -i private.pem > private.pem.b64

cp .env.example .env
# Paste private.pem.b64 contents into KNUCKLES_JWT_PRIVATE_KEY
# Generate KNUCKLES_STATE_SECRET:
#   python -c "import secrets; print(secrets.token_urlsafe(48))"

pip install -e ".[dev]"
alembic -c knuckles/alembic.ini upgrade head
flask --app knuckles.app run --port 5001
```

## Tests

```bash
pytest --cov=knuckles --cov-fail-under=80
```

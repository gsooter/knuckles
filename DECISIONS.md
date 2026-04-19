# DECISIONS.md — Knuckles

Architectural decisions log. Every significant choice is recorded here
with its rationale and the alternatives considered. Check this before
making structural changes — if something is documented here, don't
reverse it without discussion.

---

## Decision Log

---

### 001 — Knuckles Is Identity-Only; Music Services Live In Greenroom

**Date:** 2026-04-19
**Status:** Decided

**Decision:** Knuckles handles user identity (magic-link, Google,
Apple, WebAuthn passkey), token issuance + refresh, JWKS, and app
clients — and nothing else. Music-service connections (Spotify, Apple
Music, Tidal, and any future equivalent) do not exist in Knuckles. They
are a Greenroom-level concern: Greenroom owns its own
`music_service_connections` table, its own OAuth routes under
`api/v1/music/`, and its own settings UI for connect/disconnect.
Knuckles has no knowledge of what services a user has connected
inside any consuming app.

**Rationale:**
A centralized auth service is only valuable if its surface stays small
and universal across consumers. The moment Knuckles knows about
"Spotify," every future consuming app has to reason about "does my app
use Spotify or not" when asking Knuckles for a user. That couples
Knuckles to a specific product's data model and turns it from
identity-infrastructure into a leaky shared backend. Music-service
tokens also have a fundamentally different lifecycle: they refresh
frequently, they carry per-app scopes, and the data they gate
(listening history, library) is only meaningful inside the consuming
app's feature set. Keeping them in Greenroom means one app owns the
full picture of one concern, rather than two apps sharing an awkward
split.

**Alternatives considered:**
- **Knuckles handles every OAuth provider** including music services —
  rejected. Bakes Greenroom-specific concepts (music listening) into
  the identity service and blocks every future app from making its own
  decisions about which music services to integrate.
- **Knuckles handles OAuth, Greenroom handles the data** — rejected.
  Half-split: Knuckles owns the tokens, Greenroom wants them. Requires
  a server-to-server handoff that adds a failure mode without removing
  any coupling (Knuckles still knows Spotify exists).
- **Greenroom continues to handle all identity AND music services** —
  rejected separately (see Greenroom DECISIONS.md #028): auth belongs
  in a shared service.

**Consequences:**
- Knuckles has no `services/connected_services.py`, no
  `api/v1/services.py` route file, no `/v1/services/*` endpoints, no
  `SPOTIFY_*` / `TIDAL_*` / `APPLE_MUSIC_*` environment variables.
- `user_oauth_providers.provider` enum is exactly `{google, apple}`.
  Adding `spotify`, `apple_music`, `tidal`, or any music-service value
  is a violation of this decision and must be rejected at review.
- CLAUDE.md encodes this as a hard rule so future sessions don't
  accidentally re-add music services when the prompt doesn't mention
  them.
- Greenroom adds a local `music_service_connections` table keyed by
  Knuckles `user_id`. Greenroom never needs to call Knuckles to
  enumerate or refresh music-service credentials.

---

### 002 — RS256 + JWKS Is The Trust Model

**Date:** 2026-04-19
**Status:** Decided

**Decision:** Knuckles signs access tokens with an RSA-2048 private
key (RS256) held only by Knuckles. Every consuming app validates
tokens by fetching `GET /.well-known/jwks.json` once, caching the
public key locally, and verifying RS256 signatures per request without
calling Knuckles. Each signing key has a stable `kid` and the JWKS
can serve multiple keys at once so rotation is a config change.

**Rationale:**
The whole point of extracting auth into a separate service is that
apps should not be able to mint tokens — only Knuckles should. A
shared HMAC secret (HS256) gives every consuming app the ability to
both validate *and* issue tokens, which means a leak of any app's
environment compromises every other app on the same secret. RS256
keeps signing authority in Knuckles alone; a compromise of a consuming
app lets an attacker validate tokens (fine) but not mint them (the
thing that matters). Consuming apps validating offline against JWKS
also means Knuckles is not on the request path for every API call in
every consuming app — which is good both for latency and for blast
radius if Knuckles is down.

**Alternatives considered:**
- **HS256 with a shared secret** — rejected per above.
- **RS256 but proxy every validation through a Knuckles
  `/introspect` endpoint** — rejected. Adds a hop to every request in
  every consuming app, and tokens expire anyway so the "fresh
  revocation" story isn't meaningfully improved.
- **Per-app asymmetric keys** — considered. Rejected because it's the
  same trust property with more operational overhead (N keys to
  rotate, N JWKS to publish). One issuer, one JWKS, `aud` per app is
  the standard pattern.

**Consequences:**
- Private key is stored as a base64-encoded PEM in a Knuckles env var.
  Never in source control, never in any consuming app.
- Every consuming app fetches JWKS on boot and caches it on disk so a
  Knuckles outage does not take down validation. Hardening phase adds
  a graceful-degradation path for expired disk cache.
- Key rotation: issue a new `kid`, start signing with the new key,
  publish both in JWKS until all outstanding tokens expire, then
  retire the old `kid`. No coordinated consuming-app deploy needed.

---

### 003 — App Clients Are Explicit From Day One

**Date:** 2026-04-19
**Status:** Decided

**Decision:** Every consuming application registers as a row in
`app_clients` with a public `client_id` and a hashed `client_secret`.
Every access token carries `aud = client_id`. Consuming apps reject
tokens whose audience is not their own. Server-to-server Knuckles
endpoints (refresh, logout) authenticate the app via `client_id +
client_secret`; user-facing endpoints authenticate the user via the
access token.

**Rationale:**
Multi-tenancy has to be first-class or it's never added. Today we
have Greenroom as the only consumer, but the whole point of
extracting auth is to serve future apps. Shaping the schema, token
claims, and middleware around app_clients now is cheap; retrofitting
once a second app exists is painful (every existing token has to be
re-minted; every existing row has to be backfilled).

**Alternatives considered:**
- **Implicit single-tenant at launch, multi-tenant later** — rejected
  on the cost-of-retrofit argument above.
- **OAuth 2.0 dynamic client registration (RFC 7591)** — deferred.
  Manual registration via a migration is fine while consumers are a
  handful; dynamic registration is there when it's not.

**Consequences:**
- Adding a new consuming app is a single migration row plus giving
  the app its client credentials out-of-band.
- Consuming apps must use `audience` verification when decoding JWTs.
  A missing audience check is a bug at the consuming-app layer.
- Client secrets are hashed with SHA-256 (high-entropy strings; no
  password-hashing algorithm needed).

---

### 004 — Refresh Tokens Are Rotated And One-Shot

**Date:** 2026-04-19
**Status:** Decided

**Decision:** Refresh tokens are opaque 32-byte random strings, stored
only as SHA-256 hashes in `refresh_tokens.token_hash`, with a 30-day
TTL. Every call to `POST /v1/auth/token/refresh` invalidates the
presented refresh token (`used_at` set) and issues a brand new
refresh token. A token presented twice (after being used) is treated
as a compromise signal: all active refresh tokens for that user are
revoked.

**Rationale:**
Static long-lived refresh tokens are the weakest link in a modern
token setup — any leak gives an attacker indefinite session renewal.
Rotation keeps the window to 30 days *between* uses, and reuse
detection turns any copy of a stolen-then-rotated token into an alarm
instead of a foothold. This is the refresh-token pattern OAuth 2.1
codifies for public clients.

**Alternatives considered:**
- **Static refresh tokens** — rejected per above.
- **Refresh tokens as JWTs** — rejected. Revocation requires a server-
  side check anyway (a JWT can't be invalidated client-side), so
  storing them as rows avoids the pretense.
- **No refresh tokens, just long-lived access tokens** — rejected.
  Long-lived access tokens can't be revoked cheaply (would require
  token-introspection on every request), and the whole RS256+JWKS
  pattern depends on tokens being short-lived.

**Consequences:**
- `refresh_tokens` table has `used_at` instead of `revoked_at` alone,
  so the reuse case is distinguishable from the revoke case.
- Logout deletes or revokes the current refresh token but not the
  user's other sessions; explicit "sign out everywhere" revokes all
  active refresh tokens for that user.
- Clients must be prepared to swap in the rotated refresh token each
  time they call `/token/refresh`.

---

### 005 — Ceremony State Lives In Signed JWTs, Not Redis

**Date:** 2026-04-19
**Status:** Decided

**Decision:** OAuth `state` and WebAuthn challenge state are
short-lived HS256 JWTs signed with `KNUCKLES_STATE_SECRET`. They
carry a `purpose` claim (e.g. `google_oauth`, `passkey_register`) that
is verified on the return leg so a state token for one flow can't be
replayed into another. No Redis, no server-side session table.

**Rationale:**
State tokens are carried by the user's browser across a redirect and
then handed back. Making Knuckles stateless for these flows removes
Redis from the hot path, simplifies deployment, and means a Knuckles
replica restart doesn't drop in-flight ceremonies. The HMAC secret is
separate from the RS256 signing key because state tokens never leave
Knuckles — rotating the state secret doesn't require touching any
consuming app.

**Alternatives considered:**
- **Redis with a short TTL** — rejected. Adds a dependency for
  no additional safety; a leaked Redis key gets an attacker the same
  state an HMAC leak would.
- **DB row per ceremony** — rejected. Write amplification on a
  per-login path, plus a cleanup Celery task for the noise.

**Consequences:**
- `KNUCKLES_STATE_SECRET` is a required env var. Treat it like any
  other session-signing key.
- State token TTLs are measured in minutes (5 default) because they
  exist only for the round trip.

---

### 006 — Magic-Link Tokens Are Hashed At Rest

**Date:** 2026-04-19
**Status:** Decided (inherited from Greenroom Decision 027)

**Decision:** `magic_link_tokens.token_hash` stores only the SHA-256
hex digest of the raw token. The raw token exists in the outgoing
email URL and in memory during the verify request. Verification
hashes the incoming value and looks it up by the hash column.

**Rationale:**
A magic-link token is a short-lived password-equivalent. If the
database is compromised, an attacker with plaintext tokens has a
15-minute window to sign in as any user with a pending link. Storing
the hash reduces that to "hash must be inverted before the TTL
expires," which is computationally infeasible for a 32-byte random
secret.

**Alternatives considered:**
- **Encrypt with an app-level key** — rejected. Key lives in the same
  environment; a DB breach typically reads the key too.
- **Plaintext with short TTL alone** — rejected. TTL defends against
  replay, not against concurrent disclosure.

**Consequences:**
- `generate_magic_link(email)` returns the raw token (for the email
  body) and inserts only the hash.
- `verify_magic_link(token)` hashes the incoming token and does an
  equality check against the hash column.
- A nightly cleanup task deletes rows whose `expires_at` is more
  than 24 hours old so the table stays small.

---

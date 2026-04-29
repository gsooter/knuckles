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

### 007 — App-Client Authentication via X-Client-Id + X-Client-Secret

**Date:** 2026-04-19
**Status:** Decided

**Decision:** Every Knuckles endpoint that mutates session state
(`/v1/token/refresh`, `/v1/logout`, and future ceremony-completion
endpoints) requires the calling app to prove its identity with
`X-Client-Id` and `X-Client-Secret` headers. The secret is stored as
a SHA-256 hex digest and checked with `hmac.compare_digest` to defeat
timing attacks. The resolved `AppClient` row is attached to `flask.g`
so downstream code can read it without another query.

**Rationale:**
The refresh-token rotation endpoint is the single most attractive
target in the service — a leaked refresh token combined with an
unauthenticated rotation endpoint would let any holder mint arbitrary
access tokens. Requiring the caller to also present its client secret
reduces the blast radius to "attacker who has *both* the refresh token
*and* the shared client secret" — a far harder bar to clear than
stealing a token from browser storage alone.

The client-secret model also gives us per-consumer audit trails and
the ability to rotate a compromised app's credentials without
invalidating every user session.

**Alternatives considered:**
- **Public client with refresh-token-only auth** — rejected. That
  works for confidential OAuth clients operating entirely in the
  browser, but browser-side secrets are effectively public. A
  server-side client with a secret is the right fit for consuming
  apps that run a backend (Greenroom does).
- **mTLS between services** — rejected for now. Operational overhead
  is high relative to the benefit at our current scale; header-based
  auth is sufficient and upgrade-compatible.

**Consequences:**
- Every consuming app ships its client secret in an env var, not
  the frontend bundle.
- `AppClient.client_secret_hash` is mandatory; there is no "public
  client" escape hatch.
- Rotating a compromised secret is a database update plus redeploy
  — no mass session invalidation required.

---

### 008 — Refresh-Token Reuse Detection Revokes All User Tokens

**Date:** 2026-04-19
**Status:** Decided

**Decision:** When a refresh token that has already been consumed
(`used_at IS NOT NULL`) is presented again, Knuckles marks every
still-active refresh token for the same user as used before returning
`REFRESH_TOKEN_REUSED`. The legitimate client's still-outstanding
token is invalidated along with the attacker's copy.

**Rationale:**
If two parties present the same consumed token, one of them is an
attacker — and we cannot tell which. The industry-standard response
(OAuth 2.0 Security BCP §4.14.2) is to assume both copies are
compromised and force re-authentication on every session for that
user. The user's re-login re-establishes trust; the attacker's copy
becomes inert.

**Alternatives considered:**
- **Revoke only the reused token's lineage** — rejected. Distinguishing
  lineages requires a parent-pointer chain, and the attacker's
  rotations would sever it on the legitimate user's next refresh.
  The blanket revoke is simpler and strictly safer.
- **Flag suspicious activity and let the user log in to confirm** —
  rejected as premature. No UX for this exists yet; a hard revoke
  with a clear error code is the right starting point.

**Consequences:**
- A reuse event logs every user out of every device, across every
  consuming app. User must re-authenticate everywhere.
- Any future suspicious-activity UI would layer on top of this
  behavior, not replace it.

---

### 009 — Magic-Link Email Backend Is a Protocol, Not a Class Hierarchy

**Date:** 2026-04-19
**Status:** Decided

**Decision:** The email-sender seam is defined by
:class:`knuckles.services.email.EmailSender`, a `typing.Protocol` with
a single ``send(*, to, subject, body)`` method. Concrete senders
(:class:`ResendEmailSender`, the in-process test fake) implement
the protocol structurally — no inheritance, no shared base class.
Service-layer functions accept ``EmailSender | None`` and fall back
to :func:`get_default_sender` when the caller passes nothing.

**Rationale:**
A Protocol gives the service layer typed dependency injection without
forcing tests to import the HTTP client used by the production sender.
Tests hand-roll a recorder class with `send` and a `sent` list;
production makes a direct HTTP call to Resend. Both pass the same
type check.

**Alternatives considered:**
- **Abstract base class** — rejected. Inheritance ties tests to the
  abstract type's import graph (and any side effects in that module).
  A Protocol is structurally typed, so the test fake never has to
  import the production sender.
- **Function-based seam (pass a `Callable`)** — rejected. The
  surface is a single method today but will grow (multipart bodies,
  attachments, idempotency keys) and a class is the cleaner shape
  for that growth.

**Consequences:**
- Adding a new email backend (e.g., a queue-backed asynchronous
  sender) means writing a new class with `send` — no registration,
  no config switch, no plugin registry.
- The service layer never imports the production sender — only
  :func:`get_default_sender` does, which keeps the dependency graph
  shallow for tests. The 2026-04-20 swap from SendGrid to Resend was
  a single-file change because of this seam.

---

### 010 — OAuth State Carries Redirect URI and App-Client Binding

**Date:** 2026-04-19
**Status:** Decided

**Decision:** The state JWT minted by Knuckles for an OAuth ceremony
embeds two fields beyond the boilerplate ``purpose``/``iat``/``exp``:
the consuming app's ``redirect_uri`` and the calling
``app_client_id``. :func:`google_oauth.complete` (and Apple's coming
sibling) re-derives both from the state and rejects any mismatch
between the state's ``app_client_id`` and the caller's
``X-Client-Id``.

**Rationale:**
- The OAuth provider requires the same ``redirect_uri`` on the token
  exchange as on the authorize step. Storing it server-side requires
  Redis or DB; embedding it in the signed state JWT keeps Knuckles
  stateless without weakening security (HMAC + 10-minute TTL).
- Embedding ``app_client_id`` prevents an attacker who steals an
  in-flight state token from completing the ceremony against a
  different app's session-issuance.

**Alternatives considered:**
- **Server-side state in Redis** — rejected. Adds an operational
  dependency for a single-roundtrip value that a JWT solves cleanly.
- **Trust the caller's claimed redirect_uri at complete time** —
  rejected. Allows a malicious caller to pivot a leaked code by
  mismatching the redirect_uri.
- **Single global ``redirect_uri`` baked into config** — rejected.
  Each consuming app needs its own callback path; per-app
  pre-registration in Google Cloud Console is operationally cleaner
  than forcing every app to share Knuckles' frontend.

**Consequences:**
- Each consuming app must pre-register its callback URL with the
  Knuckles Google OAuth client in the Google Cloud Console.
- Apple's flow will use the same shape (purpose discriminator +
  embedded ``redirect_uri`` + ``app_client_id``).
- State TTL is 10 minutes — long enough for a slow user, short enough
  to bound replay risk if the signing secret is later rotated.

---

### 011 — Single-Service Boot: Migrate Then Gunicorn

**Date:** 2026-04-19
**Status:** Decided

**Decision:** ``scripts/start.sh`` runs ``alembic upgrade head`` then
``exec`` s gunicorn. Knuckles ships as a single Railway service whose
container CMD is that script — no separate release-phase container,
no out-of-band migration runner.

**Rationale:**
- The Knuckles schema is small (six tables) and migrations are
  expected to be quick. The cost of a brief startup migration is
  measured in seconds.
- Coupling migration to boot makes deploys atomic per-service. If the
  migration fails, the container exits non-zero and Railway's restart
  policy backs off — exactly the failure mode we want, and visible in
  Railway's deploy logs.
- A separate release-phase container would require a second Railway
  service, env-var duplication, and ordering logic in the deploy
  pipeline — operational weight Knuckles doesn't have headcount for.

**Alternatives considered:**
- **Release-phase migration container** (à la Heroku): rejected for
  the operational weight reason above.
- **Manual migrations via Railway CLI**: rejected — easy to forget,
  can't be enforced in CI, hostile to CI/CD.
- **In-process migrations triggered from ``create_app``**: rejected.
  Multi-worker gunicorn would race on the migration table; running
  in the entrypoint guarantees a single execution per deploy.

**Consequences:**
- Knuckles boot time on a deploy that includes a migration is
  dominated by the migration; non-migrating deploys boot in under
  a second.
- Long-running migrations in the future will need a separate
  release-phase container or pre-deploy migration script. Revisit
  this decision when a single migration crosses ~10 seconds.

---

### 012 — Redirect URLs Must Match A Registered App-Client Origin

**Date:** 2026-04-26
**Status:** Decided

**Decision:** Every Knuckles ceremony that accepts a caller-supplied
``redirect_url`` (magic-link ``/start``, Google ``/start``, Apple
``/start``) validates that the URL's origin
(``scheme://host[:port]``, default 80/443 dropped) appears in the
calling app-client's ``allowed_origins`` list. A mismatch raises
``VALIDATION_ERROR`` with HTTP 422.

**Rationale:**
``app_clients.allowed_origins`` was always collected at registration
but never consulted, which let any holder of a valid client_secret
inject any URL into a magic-link email or pivot a leaked OAuth
authorization code to an attacker-controlled callback. The check is
free (origin parsing + a set lookup), every consuming app already
has the data registered, and it closes the most obvious abuse path
without changing the public API shape for legitimate callers.

**Alternatives considered:**
- **Compare full redirect URL strings** — rejected. Forces operators
  to register every callback path, including future additions.
  Origin-only is the standard OAuth2 pattern.
- **Per-app-client redirect-URL allowlist (a separate column)** —
  rejected. ``allowed_origins`` already exists and is the right
  granularity; adding a parallel list doubles the registration
  surface for no extra safety.

**Consequences:**
- Operators must register every origin a consuming app uses (prod,
  staging, local-dev) before that app can drive a ceremony from it.
- An origin registered with a trailing ``/`` still matches the
  origin form without — see ``_origin_of`` in
  ``knuckles/core/app_client_auth.py``.
- The CORS allow-list helper (Decision #013) reuses the same
  origin-normalization logic.

---

### 013 — Strict CORS Is Opt-In, Backed By The App-Client Origin Set

**Date:** 2026-04-26
**Status:** Decided

**Decision:** When ``KNUCKLES_STRICT_CORS=true``, Knuckles emits
``Access-Control-Allow-Origin`` only when the request's ``Origin``
header appears in the union of every registered app-client's
``allowed_origins`` (with a 60s in-process cache). Default is
``false``, which keeps the wildcard ``Allow-Origin: *`` behavior
that was in place when consuming apps were proxying every Knuckles
call from their backend (so CORS was not on the request path).

**Rationale:**
A flag-gated rollout lets the production deploy ship the code and
flip it on per-environment after observing logs, instead of forcing
a coordinated cutover. The default-off behavior preserves existing
integrations (Greenroom proxies from its backend; CORS does not
matter to those calls). Once strict mode is on, browser-direct
requests from unknown origins get no ``Allow-Origin`` header — the
browser refuses the response, which is the right failure mode.

**Alternatives considered:**
- **Always-strict, no env flag** — rejected. Couples the rollout
  to a code deploy with no rollback that doesn't require another
  deploy.
- **Per-app-client CORS configuration on the request path** —
  rejected. There is no app-client context on routes like ``/health``
  or the JWKS endpoint, so a per-client lookup would need a
  fallback anyway. The union approach is simpler and equally safe.

**Consequences:**
- The cache TTL (60s) is the maximum delay between
  ``register_app_client.py`` and a new origin being honored by CORS.
- A future Redis-backed implementation would replace
  ``knuckles/core/cors.py`` without changing the
  ``is_origin_allowed`` signature.

---

### 014 — Magic-Link Sends Are Per-Email Rate-Limited In-Process

**Date:** 2026-04-26
**Status:** Decided

**Decision:** ``POST /v1/auth/magic-link/start`` is throttled by an
in-process sliding-window counter keyed by
``(app_client_id, email)``. Default budget: 5 sends per hour. Excess
calls return HTTP 429 with code ``RATE_LIMITED`` and no email is
sent.

**Rationale:**
Without a limit, anyone holding valid app-client credentials could
loop a victim's address through Resend, weaponizing Knuckles into
an email bomb. Per-IP limits are not useful because consuming apps
proxy from a single backend IP — per-email is the right axis, scoped
per app-client so two apps' budgets don't collide. In-process
counters are intentionally minimal: each gunicorn worker keeps its
own state (effective limit ≈ ``WEB_CONCURRENCY × 5/hour``), which
is plenty until traffic justifies a Redis-backed limiter.

**Alternatives considered:**
- **Redis-backed precise distributed limiter** — deferred. Adds an
  operational dependency for a problem that the in-process counter
  bounds adequately at current scale. The ``RateLimiter.allow``
  signature is stable so a future swap is a one-file change.
- **Per-IP rate limiting** — rejected for the proxy-architecture
  reason above. Could be added in addition without conflict.

**Consequences:**
- A user who genuinely needs more than 5 magic-link emails in an
  hour for the same app gets blocked. The 429 carries a clear
  message — the consuming app can surface it as a friendly retry
  prompt.
- Tests reset the limiter via the autouse
  ``_reset_rate_and_cors_caches`` fixture so ordering is hermetic.

---

### 015 — Client SDKs Live In The Knuckles Repo, Not Separate Repos

**Date:** 2026-04-26
**Status:** Decided

**Decision:** Two first-party SDKs ship inside the Knuckles repo:
``packages/knuckles-client-py/`` (Python, ``pip install knuckles-client``)
and ``packages/knuckles-client-ts/`` (TypeScript, ``npm install
@knuckles/client``). Both expose a single ``KnucklesClient`` class
with sub-clients per ceremony, JWKS-cached local token verification,
and a typed exception hierarchy mapped to the Knuckles error-code
vocabulary. An OpenAPI 3.1 contract lives at ``docs/openapi.yaml``
for any consumer outside those two ecosystems.

**Rationale:**
The most common integration mistakes are: forgetting ``audience``
verification, forgetting to swap in the rotated refresh token, and
treating ``REFRESH_TOKEN_REUSED`` as a generic 401. An SDK encodes
those once and removes them as failure modes for every consumer.
Co-locating the SDKs with the service keeps drift impossible —
adding a new endpoint server-side is paired with the SDK addition
in the same change.

**Alternatives considered:**
- **Separate repos per SDK** — rejected. Releases would lag the
  service; PRs touching both surfaces would span repos. With one
  consuming app today (Greenroom) the coupling is a feature.
- **Generate the SDK from OpenAPI** — deferred. Hand-written gives
  ergonomic method names (``client.google.start(...)`` vs
  ``client.googleStart(...)``) and proper async-first shapes.
  Consider a generator if a third or fourth SDK ecosystem becomes
  necessary.

**Consequences:**
- Adding a Knuckles endpoint requires adding the matching SDK method
  in the same PR. Both SDK READMEs list the full method surface so
  the gap is visible at review.
- The OpenAPI spec is the contract for non-Python/TS consumers; it
  must stay in sync with the routes (``docs/openapi.yaml`` covers
  every path in ``knuckles/api/v1/``).
- The TypeScript SDK targets Node 18+ (native ``fetch``, ``jose`` for
  JWKS). It runs unchanged in browsers but must not — the
  ``client_secret`` must stay server-side.

### 016 — Library Mode Is Roadmap, Not Current State

**Status:** Accepted (planned, not implemented)

**Decision:**
The first shipping release of Knuckles is **service mode only** — a
self-hosted Flask service with a separate database, called over HTTP
by consuming apps via the ``knuckles-client`` SDK. A planned future
release will add **library mode**: a ``pip install knuckles`` Flask
extension (``Knuckles(app, db)``) that registers auth routes onto a
host app and stores its tables (``knuckles_users`` etc.) in the
host's database.

**The HTTP API and SDK shape stay frozen across this transition.**
Apps integrating today (Greenroom is the first) will keep working
unchanged when library mode lands.

**Rationale:**
The market for new hosted-SaaS auth providers is crowded
(Auth0/Clerk/Stytch/WorkOS are heavily VC-funded; Supabase Auth and
Clerk's free tier cover indie devs). The market for a **modern,
passwordless-first, drop-in auth library for Python** is genuinely
underserved — Flask-Login is password-shaped, Authlib requires
hand-wiring every provider, python-social-auth is dated. The closest
TypeScript analog is `Lucia <https://lucia-auth.com/>`_ /
`Better-Auth <https://better-auth.com/>`_, both well-loved and
free-forever libraries.

The library-mode play is the right shape for adoption-as-influence
because:

- Distribution cost is zero — PyPI, no hosting fees.
- Adoption surface is large — every Python web app is a potential
  user.
- The path from Greenroom-as-reference-deployment to library-mode is
  additive; current users don't break.
- Future monetization stays open via brand/trademark + a separate
  ``knuckles-enterprise`` package or a hosted offering, decided on
  evidence (observed adoption, inbound interest) rather than now.

**Why this is deferred, not done:**
Library mode is a real refactor (~3–4 days of focused work) that
touches ``knuckles/app.py``, ``knuckles/core/database.py``,
``knuckles/core/config.py``, the Alembic migration story (table
prefix), and the entire docs site. Doing it well requires the
maintainer to not be in the middle of shipping a different product.
At the time this decision was recorded, the maintainer's primary
focus is shipping Greenroom; pulling on library mode now would delay
that. Service mode is a complete, secure, deployed system — it is
not a stopgap, it is one of two supported architectures.

**Alternatives considered:**

- **Hosted SaaS pivot** — rejected for now. The TAM exists but the
  buildout (signup, billing, dashboards, support, SOC 2) is months
  of work for unvalidated demand. The maintainer is a builder, not
  a SaaS founder. Preserves optionality: today's service-mode
  architecture is the right primitive to grow into a hosted product
  later if signal appears.
- **Open-core (OSS library + paid hosted tier from day one)** —
  rejected for now. Doubles the work surface (two products to
  maintain) before either has traction. Revisit once library mode
  ships and there is observed demand for hosting.
- **Drop service mode entirely once library mode ships** — rejected.
  Service mode genuinely fits multi-app shops and non-Python
  backends. Both architectures are first-class going forward.

**Implementation plan (when work resumes):**

The refactor is sequenceable into independently shippable phases so
work can pause cleanly between any two:

1. **Decouple package from app/db ownership** — split
   ``knuckles/app.py`` into ``create_app()`` (service mode, current
   behavior unchanged) and ``_register(app, get_session, config)``
   (library primitive). Make ``Settings`` constructible from a dict.
   Add ``knuckles/extension.py`` defining
   ``Knuckles(app, db, config)``.
2. **Public model exports** — ``knuckles/models.py`` re-exports
   ``User``, ``RefreshToken``, ``AppClient``, ``Passkey``,
   ``MagicLinkToken``, ``UserOAuthProvider`` so library callers can
   query via their own session.
3. **Table prefix + migrations** — all tables prefixed
   ``knuckles_`` (configurable via ``Knuckles(app, db, prefix=...)``).
   Alembic migration handles the rename for the existing
   service-mode deployment. New ``flask knuckles upgrade`` CLI.
4. **Helpers** — ``knuckles.verify_access_token``,
   ``knuckles.require_signed_in`` decorator,
   ``knuckles.current_user`` proxy. Mirrors the SDK surface
   in-process.
5. **PyPI release** as ``knuckles`` (claim the name when ready;
   fallback ``knuckles-flask`` if taken).
6. **Docs rewrite** — library mode becomes the default Quickstart;
   service mode moves to a "multi-app / advanced" page.

**Consequences:**

- The current docs at ``docs/`` describe service mode (with a
  roadmap pointer to this decision). Apple/Google/Resend setup
  walkthroughs in ``docs/ONBOARDING.md`` are valid for both modes —
  the env vars and provider configs don't change between
  architectures.
- The repo structure already accommodates both modes: ``knuckles/``
  is the importable package source today, and
  ``packages/knuckles-client-py/`` is an independent release
  schedule for the HTTP SDK.
- Greenroom keeps using service mode + ``knuckles-client``. Its
  integration is stable, will not break when library mode lands,
  and migrating Greenroom to library mode is optional, separately
  scheduled work.
- The brand name "Knuckles" and the GitHub repo are commercially
  valuable independent of the code license. MIT-licensing the code
  preserves adoption optionality without giving away the option to
  build a paid offering later.

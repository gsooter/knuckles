# Knuckles integration examples

Each subdirectory is a focused snippet, not a full app. Copy what you
need.

| Folder | What it shows |
|---|---|
| `nextjs-app/` | Next.js (App Router) sign-in page + callback handlers + a server-side helper. Uses `@knuckles/client`. |
| `express-middleware/` | A 30-line Express middleware that validates Knuckles bearer tokens. Uses `@knuckles/client`. |
| `python-flask/` | Flask middleware that validates Knuckles bearer tokens via `knuckles_client`. |

## Mental model these examples assume

1. The **frontend** drives the user through a ceremony: it asks the
   backend for an authorize URL, redirects the browser, and then posts
   the code/state back to the backend.
2. The **backend** is the only thing that holds Knuckles' app-client
   secret. It calls `/v1/auth/<method>/{start,complete}` server-side
   and hands the resulting token pair back to the frontend (via a
   cookie or response body).
3. Subsequent API calls from the frontend carry the access token.
   The backend validates them with `client.verifyAccessToken(...)` —
   no network call once the JWKS is cached.

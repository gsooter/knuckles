# Publishing `@knuckles/client` to npm

Step-by-step checklist. The first release is the most work; subsequent
releases are just "bump the version, push a tag."

---

## One-time setup (done once per package, by the maintainer)

### 1. Decide: scoped or unscoped name?

The package is currently `@knuckles/client` (scoped). Scoped packages
on npm require you to **own the scope** — i.e. own the `knuckles`
organization on npmjs.com. Two options:

- **Keep `@knuckles/client`** — create a free npm org named `knuckles`
  (Settings → Add Organization → Free plan for unlimited public
  packages). This is the cleanest path long-term: future
  `@knuckles/cli`, `@knuckles/dashboard`, etc. all live under the
  same scope.
- **Rename to unscoped** (`knuckles-client`) — simpler for one-off
  publishing, no org to create. Edit:
  - `packages/knuckles-client-ts/package.json` → `"name": "knuckles-client"`
  - `packages/knuckles-client-ts/README.md` → install snippet + badges
  - `.github/workflows/release-sdk-ts.yml` → `environment.url`

The PyPI Python SDK is unscoped (`knuckles-client`); making the npm
one match (`knuckles-client`) keeps brand parity. Pick by which
matters more to you: scope reservation for future packages, or name
parity with PyPI.

### 2. Create your npm account

> https://www.npmjs.com/signup

- Verify the email.
- **Enable 2FA.** Settings → Account → Two-factor authentication →
  Auth-and-writes (the strict mode). Required for any package
  upload.

### 3. (If using a scope) Create the npm organization

> https://www.npmjs.com/org/create

- Pick the **Free** plan (unlimited public packages).
- Name it `knuckles` (or whatever scope you chose).
- Add yourself as the owner.

### 4. Configure Trusted Publishing on npm

npm added Trusted Publishing (OIDC-based, no token) in npm 11.5
(July 2025). Setup is per-package, but the package must exist on
npm first — so the **first publish must use a token**. Subsequent
publishes use Trusted Publishing.

**For the first publish (token-based):**

1. Generate an automation token at:
   > https://www.npmjs.com/settings/<your-username>/tokens
2. Type: **Granular Access Token**, scope: write to `@knuckles/*`
   packages (or `knuckles-client` if unscoped). Expiry: 7 days is
   plenty.
3. Add it as a GitHub Actions secret named `NPM_TOKEN`:
   Settings → Secrets and variables → Actions → New repository secret.
4. Temporarily edit `.github/workflows/release-sdk-ts.yml`'s publish
   step to:
   ```yaml
   - name: Publish (token-based, first release only)
     env:
       NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
     run: npm publish --access public
   ```
5. Push the first tag (step 6). Package gets created on npm.
6. After the first publish succeeds, configure Trusted Publishing:
   - npm package page → **Settings → Publishing access → Trusted Publishers**
   - Add a publisher: GitHub user/org `gsooter`, repo `knuckles`,
     workflow `release-sdk-ts.yml`, environment `npm`.
7. Revert the workflow to the Trusted Publishing version (the one
   committed). Delete the `NPM_TOKEN` secret. Future publishes use
   OIDC + provenance.

**For brand-new packages (some npm accounts get this directly):**

If your account has Trusted Publishing available before the package
exists, you can register a "pending publisher" the same way PyPI
does. Check your account's publishing settings; if the option is
there, use it and skip the token-based first publish entirely.

### 5. Configure the GitHub environment

In the Knuckles repo on GitHub → **Settings → Environments → New
environment** → name it `npm`. No secrets needed once Trusted
Publishing is set up. Optional: add a **required reviewer** for an
extra approval click before any release publishes.

### 6. Push the first version tag

```bash
git tag knuckles-client-ts-v0.1.0
git push origin knuckles-client-ts-v0.1.0
```

The GitHub Actions workflow (`release-sdk-ts.yml`) will:

1. Run `npm ci`, typecheck, build in `packages/knuckles-client-ts/`.
2. Verify the tag version matches `package.json` AND `src/index.ts`'s
   `VERSION` constant.
3. Run `npm pack --dry-run` to preview what will be published.
4. Publish to npm with `--provenance --access public`.

Watch it at:

> https://github.com/gsooter/knuckles/actions/workflows/release-sdk-ts.yml

A few minutes later the package is live at:

> https://www.npmjs.com/package/@knuckles/client

The package page will show a **green "Provenance" badge** linking
back to the exact GitHub Actions run that built it.

---

## Releasing a new version

Once one-time setup is done, the cycle is:

1. Land changes on `main` via PR. Typecheck + build green.
2. Bump the version in **two** places:
   - `packages/knuckles-client-ts/package.json` → `"version": "X.Y.Z"`
   - `packages/knuckles-client-ts/src/index.ts` → `export const VERSION = 'X.Y.Z'`
3. Add an entry to `CHANGELOG.md` under a new `[X.Y.Z]` heading. Move
   anything that was under `[Unreleased]` into the new section.
4. Commit (conventional commits style):
   `git commit -m "release(knuckles-client-ts): v0.2.0"`
5. Tag and push:
   ```bash
   git tag knuckles-client-ts-v0.2.0
   git push origin main knuckles-client-ts-v0.2.0
   ```
6. Workflow runs and publishes.

The workflow's tag-version-vs-`package.json`-vs-`src/index.ts` check
will fail loudly if you forget any of the three locations.

### Version-bump rules (semver while pre-1.0)

- **Patch (0.1.0 → 0.1.1):** bug fixes, doc-only changes, internal
  refactors that don't change the public API.
- **Minor (0.1.0 → 0.2.0):** new methods, new optional fields on
  options, new exception subclasses. Read the changelog before
  upgrading.
- **Major (0.x → 1.0.0):** when you commit to "I will not break
  this API without a major version bump." After 1.0.0, same
  minor/major distinction applies but more strictly.

---

## Nuances and pitfalls

- **Scoped packages publish private by default.** The `--access
  public` flag (and `publishConfig.access: "public"` in
  `package.json`) is what makes the package visible to the world.
  Without it, the publish silently goes to a "private" tier that
  nobody can install unless they're paying for npm Pro.
- **Provenance requires public packages.** Private packages can't
  get provenance statements. Same `--access public` flag is
  required.
- **Lockfile must exist for `npm ci`.** Run `npm install` once
  locally and commit `package-lock.json`. The workflow uses `npm ci`
  for reproducibility, which fails without a lockfile.
- **The `prepublishOnly` script runs the full build chain.** It's
  wired in `package.json` to `clean → typecheck → build`. If you ever
  publish manually with `npm publish`, this runs automatically and
  refuses to publish a stale `dist/`.
- **You cannot truly delete an npm release.** You can `npm unpublish`
  within 72 hours of publishing, **but** doing so blocks the version
  number from being reused for 24 hours and triggers anti-abuse
  alerts. After 72 hours, the only option is to `npm deprecate` the
  version with a message — it stays installable but warns users.
- **Don't commit `dist/` or `node_modules/`.** They're regenerated
  on every release. Both should be in `.gitignore` (already are at
  the repo root).
- **The README on npm is rendered from `README.md`.** Updates ship
  with each new version — there's no separate edit-the-page flow.
- **Tag versions must match `package.json` and `src/index.ts`.** The
  workflow enforces both. Avoids the "I tagged 0.1.1 but forgot to
  bump one of the files" footgun.
- **First-time scope ownership is one-way-ish.** Once you publish
  `@knuckles/client`, the `knuckles` org owns the scope. You can
  transfer ownership but not undo "knuckles is taken." Pick the
  scope name with that in mind.
- **Granular access tokens beat classic tokens.** If you fall back to
  token-based publishing, always pick **Granular Access Token** with
  scope limited to your specific package, not a classic
  "automation" token that works on everything.

---

## Documentation site

The SDK's reference is the README, which renders on npm and on
GitHub. The HTTP-API reference is the OpenAPI spec rendered by
Redoc at:

> https://gsooter.github.io/knuckles/

(Setup: repo Settings → Pages → Source = "Deploy from a branch",
Branch = `main`, Folder = `/docs`. Already covered in the Python
SDK's `PUBLISHING.md`.)

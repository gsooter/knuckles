# Publishing `knuckles-client` to PyPI

Step-by-step checklist. The first release is the most work; subsequent
releases are just "bump the version, push a tag."

---

## One-time setup (done once per package, by the maintainer)

### 1. Pick / verify the package name

Confirm the name is available on PyPI:

> https://pypi.org/project/knuckles-client/

If the page returns 404, the name is free. If it's taken (someone
else's package), pick an alternative — `knuckles-sdk`,
`knuckles-auth`, `pyknuckles` — and update both:

- `packages/knuckles-client-py/pyproject.toml` → `[project] name = "..."`
- `.github/workflows/release-sdk-py.yml` → `environment.url`
- `packages/knuckles-client-py/README.md` → install snippet + badges

### 2. Create your PyPI account

> https://pypi.org/account/register/

- Verify the email.
- **Enable 2FA.** PyPI requires it for any package upload. Use a TOTP
  app (Authy, 1Password, Google Authenticator) or a hardware key.

### 3. Create the project on PyPI (two paths)

**Path A — Trusted Publishing first (recommended).** PyPI lets you
register a "pending publisher" before the package exists. Go to:

> https://pypi.org/manage/account/publishing/

Add a new pending publisher with:

| Field | Value |
|---|---|
| PyPI Project Name | `knuckles-client` |
| Owner | `gsooter` (your GitHub username/org) |
| Repository name | `knuckles` |
| Workflow name | `release-sdk-py.yml` |
| Environment name | `pypi` |

Now push a tag (step 5) and the first release will create the project
*and* publish in one go, all via OIDC. No API tokens at any point.

**Path B — One-off manual upload first.** If you want to claim the
name immediately without setting up CI:

```bash
cd packages/knuckles-client-py
pip install -e ".[dev]"
python -m build                          # creates dist/*.whl + dist/*.tar.gz
python -m twine check dist/*             # validates README renders on PyPI
python -m twine upload --repository testpypi dist/*    # dry run first
python -m twine upload dist/*            # real upload
```

twine will prompt for your PyPI API token (create one at
https://pypi.org/manage/account/token/). After this initial release
you can still set up Trusted Publishing for future releases.

### 4. Configure the GitHub environment

In the Knuckles repo on GitHub → **Settings → Environments → New
environment** → name it `pypi`. No secrets needed — Trusted
Publishing handles auth via OIDC. You can optionally add **required
reviewers** if you want every release to require a manual approval
click before it publishes.

### 5. Push the first version tag

```bash
git tag knuckles-client-py-v0.1.0
git push origin knuckles-client-py-v0.1.0
```

The GitHub Actions workflow (`release-sdk-py.yml`) will:

1. Run ruff + mypy + pytest in `packages/knuckles-client-py/`.
2. Verify the tag version matches `pyproject.toml`.
3. Build sdist + wheel.
4. Publish to PyPI via Trusted Publishing.

Watch it run at:

> https://github.com/gsooter/knuckles/actions/workflows/release-sdk-py.yml

A few minutes later the package is live at:

> https://pypi.org/project/knuckles-client/

---

## Releasing a new version

Once the one-time setup is done, the cycle is:

1. Land changes on `main` via PR. Tests must be green.
2. Bump the version in **both** places:
   - `packages/knuckles-client-py/pyproject.toml` → `version = "X.Y.Z"`
   - `packages/knuckles-client-py/src/knuckles_client/__init__.py`
     → `__version__ = "X.Y.Z"`
3. Add an entry to `CHANGELOG.md` under a new `[X.Y.Z]` heading. Move
   anything that was under `[Unreleased]` into the new section.
4. Commit (conventional commits style):
   `git commit -m "release(knuckles-client-py): v0.2.0"`
5. Tag and push:
   ```bash
   git tag knuckles-client-py-v0.2.0
   git push origin main knuckles-client-py-v0.2.0
   ```
6. The release workflow runs and publishes.

### Version-bump rules (semver while pre-1.0)

- **Patch (0.1.0 → 0.1.1):** bug fixes, doc-only changes, internal
  refactors that don't change the public API.
- **Minor (0.1.0 → 0.2.0):** new methods, new optional kwargs, new
  exception subclasses. May include behavior changes — read the
  changelog before upgrading.
- **Major (0.x → 1.0.0):** when you're ready to commit to "I will
  not break this API without a major version bump." After 1.0.0,
  same minor/major distinction applies but more strictly.

---

## Nuances and pitfalls

- **The README on PyPI is rendered from `README.md`.** PyPI's renderer
  is stricter than GitHub's. Verify locally with:
  ```bash
  python -m twine check dist/*
  ```
- **You cannot truly delete a release from PyPI.** You can "yank" it
  (it stays available for users who pinned to it but is hidden from
  fresh installs). Test on TestPyPI first if you're nervous:
  https://test.pypi.org/.
- **Wheels are pure-Python.** No platform-specific builds, no manylinux
  hassles. `python -m build` produces one wheel for everyone.
- **Don't commit `dist/`, `*.egg-info/`, or `build/`.** They get
  regenerated on every release. Add to `.gitignore` if not already.
- **Token-less publishing requires HTTPS.** Trusted Publishing relies
  on GitHub's OIDC issuer being reachable. If your CI runs in a
  network-isolated env, fall back to a PyPI API token stored as a
  GitHub Actions secret.
- **The GitHub Actions tag trigger fires once.** If the workflow
  fails midway (e.g., flaky test), you cannot re-run the whole job
  by re-tagging — you'd need to bump the version, retag, and start
  over. Keep the workflow's `test` job thorough so failures show up
  before publish.
- **The first publish creates the project page.** Subsequent
  publishes can change the description (README), classifiers, URLs,
  etc. — they live on the *latest* release's metadata.
- **Be defensive about the `__version__` constant.** Some downstream
  tooling reads `package.__version__` instead of installed-package
  metadata. Keep `__init__.py` in sync with `pyproject.toml`. (Or
  later, switch to `setuptools-scm` to derive version from git tags
  automatically — out of scope for v0.1.)

---

## Documentation site (GitHub Pages)

The OpenAPI reference at `docs/openapi.yaml` is rendered as a single
HTML page (`docs/index.html`) using Redoc. To publish it:

1. In the GitHub repo → **Settings → Pages**.
2. Under "Build and deployment", set **Source** to "Deploy from a
   branch", **Branch** to `main`, **Folder** to `/docs`.
3. Save. GitHub publishes to:
   > https://gsooter.github.io/knuckles/

The page auto-updates on every push to `main` that touches `docs/`.
No build pipeline, no Jekyll tweaks — `index.html` is served verbatim.

If you want a richer multi-page docs site later, MkDocs (with the
Material theme) is the natural next step. Until then the README
serves as the SDK reference and Redoc serves as the HTTP-API reference.

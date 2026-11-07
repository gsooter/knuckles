# Changelog

All notable changes to `knuckles-cli` are recorded here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
the project adheres to [Semantic Versioning](https://semver.org/).
0.x releases are pre-stable.

## [Unreleased]

## [0.1.0]

### Added

- `login` / `logout` with stored profiles (0600) and
  `KNUCKLES_URL` / `KNUCKLES_ADMIN_TOKEN` env overrides.
- `init` and `apps list|show|create|rotate-secret|set-origins`, with
  `--env-file` to write `KNUCKLES_URL` / `KNUCKLES_CLIENT_ID` /
  `KNUCKLES_CLIENT_SECRET` into a consuming app's `.env`.
- `providers google|apple|email|passkey|clear`, which validate the
  provider console's own files locally before uploading them.
- `doctor` server and tenant checks.
- `--json` output using the Knuckles API envelope.

Targets the Knuckles admin API from Decision #021.

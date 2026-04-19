#!/usr/bin/env bash
# Production entrypoint: run pending Alembic migrations, then exec gunicorn.
#
# Why migrate-on-boot: Railway redeploys are atomic per-service, and the
# auth schema is small enough that a brief startup migration is cheaper
# than wiring a separate one-shot release-phase container. If the
# migration fails the boot fails — exactly what we want.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "[start] running alembic migrations"
python -m alembic -c knuckles/alembic.ini upgrade head

PORT="${PORT:-5001}"
WORKERS="${WEB_CONCURRENCY:-2}"
TIMEOUT="${GUNICORN_TIMEOUT:-30}"

echo "[start] launching gunicorn on :${PORT} (${WORKERS} workers)"
exec gunicorn knuckles.wsgi:app \
    --bind "0.0.0.0:${PORT}" \
    --workers "${WORKERS}" \
    --timeout "${TIMEOUT}" \
    --access-logfile - \
    --error-logfile -

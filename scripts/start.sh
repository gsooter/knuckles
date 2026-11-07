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
# Threaded workers: every OAuth/Resend ceremony blocks on upstream
# HTTP (10s timeouts), so sync workers cap the whole service at
# WEB_CONCURRENCY concurrent requests — two slow upstream calls would
# stall /health and /v1/token/refresh for every tenant. gthread keeps
# the per-request model while giving WORKERS x THREADS concurrency.
THREADS="${GUNICORN_THREADS:-8}"
# Must exceed the longest upstream wait (10s requests timeouts, plus
# headroom) so a slow provider degrades one request instead of
# SIGKILLing a worker that carries seven other in-flight requests.
TIMEOUT="${GUNICORN_TIMEOUT:-60}"

echo "[start] launching gunicorn on :${PORT} (${WORKERS} workers x ${THREADS} threads)"
exec gunicorn knuckles.wsgi:app \
    --bind "0.0.0.0:${PORT}" \
    --worker-class gthread \
    --workers "${WORKERS}" \
    --threads "${THREADS}" \
    --timeout "${TIMEOUT}" \
    --graceful-timeout 30 \
    --keep-alive 5 \
    --access-logfile - \
    --access-logformat '%(h)s "%(r)s" %(s)s %(b)s %(M)sms req_id=%({x-request-id}o)s' \
    --error-logfile -

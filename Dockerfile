# syntax=docker/dockerfile:1.7
# Production image for Knuckles. Single-stage on slim Python 3.12.
#
# psycopg2-binary ships its own libpq, so we only need libffi + libssl
# at runtime for cryptography wheels (already present in slim images
# since cryptography 42 is fully wheels-only on glibc).

FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install runtime libs gunicorn + cryptography + psycopg2 may dlopen.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libffi8 \
        libssl3 \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY knuckles ./knuckles
RUN pip install .

COPY scripts ./scripts
RUN chmod +x scripts/start.sh

# Run as non-root.
RUN useradd --create-home --uid 1001 knuckles \
    && chown -R knuckles:knuckles /app
USER knuckles

EXPOSE 5001

CMD ["./scripts/start.sh"]

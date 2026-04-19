"""WSGI entry point for gunicorn.

Production servers (Railway, Heroku) launch the Knuckles Flask app
through this module:

    gunicorn knuckles.wsgi:app

The factory call has to happen at import time because gunicorn binds
the workers before any first request, so any startup-time failure
(missing env var, bad signing key) surfaces immediately instead of on
the first /health probe.
"""

from __future__ import annotations

from knuckles.app import create_app

app = create_app()

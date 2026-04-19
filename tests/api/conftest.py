"""Shared fixtures for the API-layer test suite.

Every API test wants the real Flask app factory (to get route registration,
error handlers, CORS, and bearer-token parsing wired up) running against
the SQLite in-memory ``db_session`` fixture. That means we need to
monkeypatch :func:`knuckles.core.database.get_db` so route handlers pick
up the fixture session instead of spinning up a Postgres connection.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator

import pytest
from flask import Flask
from flask.testing import FlaskClient
from sqlalchemy.orm import Session

import knuckles.core.app_client_auth as app_client_auth_mod
import knuckles.core.database as database_mod
from knuckles.app import create_app
from knuckles.data.repositories import auth as repo


@pytest.fixture()
def app(db_session: Session, monkeypatch: pytest.MonkeyPatch) -> Iterator[Flask]:
    """Build the Knuckles Flask app with ``get_db`` routed to the test session.

    Args:
        db_session: The SQLite-backed SQLAlchemy session fixture.
        monkeypatch: pytest's monkeypatch helper.

    Yields:
        The fully-configured Flask app ready for a test client.
    """
    monkeypatch.setattr(database_mod, "get_db", lambda: db_session)
    monkeypatch.setattr(app_client_auth_mod.database, "get_db", lambda: db_session)
    app = create_app()
    yield app


@pytest.fixture()
def client(app: Flask) -> FlaskClient:
    """Return a Flask test client bound to the test app.

    Args:
        app: The Flask app fixture.

    Returns:
        An active ``FlaskClient``.
    """
    return app.test_client()


@pytest.fixture()
def app_client_creds(db_session: Session) -> tuple[str, str]:
    """Register a registered app-client and return (client_id, secret).

    Args:
        db_session: The SQLite-backed SQLAlchemy session.

    Returns:
        Tuple of (client_id, plaintext secret) callers can pass via the
        ``X-Client-Id`` and ``X-Client-Secret`` headers.
    """
    client_id = "greenroom-prod"
    secret = "super-secret"
    repo.create_app_client(
        db_session,
        client_id=client_id,
        app_name="Greenroom",
        client_secret_hash=hashlib.sha256(secret.encode("ascii")).hexdigest(),
        allowed_origins=["http://localhost:3000"],
    )
    return client_id, secret

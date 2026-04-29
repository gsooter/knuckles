"""Tests for :mod:`knuckles.core.app_client_auth`.

The decorator must accept valid ``X-Client-Id`` + ``X-Client-Secret``
pairs, reject missing/mismatched/unknown clients, and expose the
resolved ``AppClient`` to the wrapped view via ``flask.g``.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator

import pytest
from flask import Flask, g, jsonify
from flask.testing import FlaskClient
from sqlalchemy.orm import Session

import knuckles.core.database as database
from knuckles.core.app_client_auth import (
    _origin_of,
    assert_redirect_allowed,
    get_current_app_client,
    require_app_client,
)
from knuckles.core.exceptions import AppError, ValidationError
from knuckles.data.models import AppClient
from knuckles.data.repositories import auth as repo


@pytest.fixture()
def app(db_session: Session, monkeypatch: pytest.MonkeyPatch) -> Iterator[Flask]:
    """Build a minimal Flask app wired to the in-memory test session.

    The decorator reaches into ``database.get_db`` to resolve the
    request-scoped session, so we monkeypatch that helper to return
    the fixture session without going through the real engine.

    Args:
        db_session: The SQLite-backed SQLAlchemy session fixture.
        monkeypatch: pytest's monkeypatch helper.

    Yields:
        A configured Flask app with a single decorated test route.
    """
    app = Flask(__name__)
    app.config["TESTING"] = True

    monkeypatch.setattr(database, "get_db", lambda: db_session)

    @app.errorhandler(AppError)
    def _handle(exc: AppError) -> tuple[dict[str, dict[str, str]], int]:
        return {"error": {"code": exc.code, "message": exc.message}}, exc.status_code

    @app.route("/protected")
    @require_app_client
    def protected() -> object:
        client = get_current_app_client()
        return jsonify({"client_id": client.client_id})

    yield app


@pytest.fixture()
def client(app: Flask) -> FlaskClient:
    """Return the Flask test client for the decorated app.

    Args:
        app: The Flask app fixture.

    Returns:
        A ``FlaskClient`` instance bound to ``app``.
    """
    return app.test_client()


def _register_client(db_session: Session, *, secret: str = "super-secret") -> str:
    """Create an ``app_clients`` row with the SHA-256 hash of ``secret``.

    Args:
        db_session: Active SQLAlchemy session.
        secret: Plaintext client secret to hash and store.

    Returns:
        The client_id used for the new row.
    """
    repo.create_app_client(
        db_session,
        client_id="greenroom-prod",
        app_name="Greenroom",
        client_secret_hash=hashlib.sha256(secret.encode("ascii")).hexdigest(),
        allowed_origins=[],
    )
    return "greenroom-prod"


def test_require_app_client_accepts_valid_credentials(
    client: FlaskClient, db_session: Session
) -> None:
    """Correct id + secret resolve and the view sees the ``AppClient``."""
    client_id = _register_client(db_session)

    response = client.get(
        "/protected",
        headers={"X-Client-Id": client_id, "X-Client-Secret": "super-secret"},
    )

    assert response.status_code == 200
    assert response.get_json() == {"client_id": client_id}


def test_require_app_client_rejects_missing_headers(client: FlaskClient) -> None:
    """Absent headers yield ``INVALID_CLIENT`` with HTTP 401."""
    response = client.get("/protected")
    assert response.status_code == 401
    assert response.get_json()["error"]["code"] == "INVALID_CLIENT"


def test_require_app_client_rejects_unknown_client_id(
    client: FlaskClient, db_session: Session
) -> None:
    """Header id with no matching row is rejected as invalid client."""
    _register_client(db_session)

    response = client.get(
        "/protected",
        headers={"X-Client-Id": "nope", "X-Client-Secret": "super-secret"},
    )
    assert response.status_code == 401
    assert response.get_json()["error"]["code"] == "INVALID_CLIENT"


def test_require_app_client_rejects_wrong_secret(
    client: FlaskClient, db_session: Session
) -> None:
    """Correct id but wrong secret is rejected as invalid client."""
    client_id = _register_client(db_session)

    response = client.get(
        "/protected",
        headers={"X-Client-Id": client_id, "X-Client-Secret": "wrong"},
    )
    assert response.status_code == 401
    assert response.get_json()["error"]["code"] == "INVALID_CLIENT"


def test_get_current_app_client_outside_decorator_raises() -> None:
    """Calling the helper outside a decorated view raises ``RuntimeError``."""
    app = Flask(__name__)
    with app.app_context():
        g.pop("app_client", None)
        with pytest.raises(RuntimeError):
            get_current_app_client()


def _client_with_origins(*origins: str) -> AppClient:
    """Build an in-memory ``AppClient`` carrying the given allowed origins.

    Args:
        *origins: Origin strings to register as allowed.

    Returns:
        A populated :class:`AppClient` (not bound to any session).
    """
    return AppClient(
        client_id="test",
        app_name="Test",
        client_secret_hash="x",
        allowed_origins=list(origins),
    )


def test_origin_of_strips_default_ports() -> None:
    """Default 80/443 ports are dropped so they match registered origins."""
    assert _origin_of("http://localhost:80/path") == "http://localhost"
    assert _origin_of("https://example.com:443/x") == "https://example.com"


def test_origin_of_keeps_non_default_port() -> None:
    """Non-default ports survive normalization."""
    assert _origin_of("http://localhost:3000/auth") == "http://localhost:3000"


def test_origin_of_rejects_non_http_scheme() -> None:
    """``javascript:`` and friends do not parse to an origin."""
    assert _origin_of("javascript:alert(1)") is None
    assert _origin_of("not a url") is None


def test_assert_redirect_allowed_accepts_matching_origin() -> None:
    """A redirect under a registered origin passes."""
    client = _client_with_origins("http://localhost:3000")
    assert_redirect_allowed(client, "http://localhost:3000/auth/verify")


def test_assert_redirect_allowed_rejects_unregistered_origin() -> None:
    """A redirect to a different origin is a ``VALIDATION_ERROR``."""
    client = _client_with_origins("http://localhost:3000")
    with pytest.raises(ValidationError):
        assert_redirect_allowed(client, "http://evil.example.com/steal")


def test_assert_redirect_allowed_rejects_malformed_url() -> None:
    """Non-URL input is rejected as a validation error."""
    client = _client_with_origins("http://localhost:3000")
    with pytest.raises(ValidationError):
        assert_redirect_allowed(client, "not a url")


def test_assert_redirect_allowed_tolerates_trailing_slash_in_registration() -> None:
    """An origin registered with a trailing slash still matches."""
    client = _client_with_origins("http://localhost:3000/")
    assert_redirect_allowed(client, "http://localhost:3000/auth/verify")

"""Smoke tests for the Flask app factory."""

from __future__ import annotations

import pytest
from flask import Flask
from flask.testing import FlaskClient
from sqlalchemy.orm import Session

import knuckles.core.database as database_mod
from knuckles.app import create_app


@pytest.fixture
def app(db_session: Session, monkeypatch: pytest.MonkeyPatch) -> Flask:
    """Build the real app with ``get_db`` routed to the test session.

    Args:
        db_session: The SQLite-backed SQLAlchemy session fixture.
        monkeypatch: pytest's monkeypatch helper.

    Returns:
        A configured Flask app.
    """
    monkeypatch.setattr(database_mod, "get_db", lambda: db_session)
    return create_app()


@pytest.fixture
def client(app: Flask) -> FlaskClient:
    return app.test_client()


def test_health_endpoint_returns_ok(client: FlaskClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.get_json() == {"status": "ok", "database": "ok"}


def test_health_reports_degraded_when_database_is_down(
    client: FlaskClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failing connectivity probe turns /health into a 503."""
    import knuckles.app as app_mod

    def _boom(session: object) -> bool:
        raise RuntimeError("db down")

    monkeypatch.setattr(app_mod.auth_repo, "ping", _boom)
    response = client.get("/health")
    assert response.status_code == 503
    assert response.get_json()["status"] == "degraded"


def test_create_app_fails_at_boot_on_malformed_signing_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A bad KNUCKLES_JWT_PRIVATE_KEY crashes the factory, not sign-in.

    The worker must die at boot — where the deploy pipeline catches
    it — rather than pass /health and 500 every ceremony completion.
    """
    from knuckles.core.jwt import reset_key_cache

    monkeypatch.setenv("KNUCKLES_JWT_PRIVATE_KEY", "bm90LWEta2V5")
    reset_key_cache()
    with pytest.raises(ValueError):
        create_app()


def test_create_app_fails_at_boot_on_malformed_secrets_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A set-but-invalid KNUCKLES_SECRETS_KEY also fails at boot."""
    from knuckles.core.secrets import get_fernet

    monkeypatch.setenv("KNUCKLES_SECRETS_KEY", "not-a-fernet-key")
    get_fernet.cache_clear()
    with pytest.raises(ValueError):
        create_app()


def test_jwks_endpoint_publishes_public_key(client: FlaskClient) -> None:
    response = client.get("/.well-known/jwks.json")
    assert response.status_code == 200
    body = response.get_json()
    assert "keys" in body
    assert len(body["keys"]) == 1
    jwk = body["keys"][0]
    assert jwk["kid"] == "test-key-1"
    assert jwk["alg"] == "RS256"


def test_jwks_versioned_alias_returns_same_body(client: FlaskClient) -> None:
    canonical = client.get("/.well-known/jwks.json")
    alias = client.get("/v1/auth/jwks")
    assert alias.status_code == 200
    assert alias.get_json() == canonical.get_json()


def test_unknown_route_returns_json_error(client: FlaskClient) -> None:
    response = client.get("/does-not-exist")
    assert response.status_code == 404
    body = response.get_json()
    assert body["error"]["code"] == "NOT_FOUND"


def test_cors_headers_present_on_response(client: FlaskClient) -> None:
    response = client.get("/health")
    assert response.headers["Access-Control-Allow-Origin"] == "*"
    assert "Authorization" in response.headers["Access-Control-Allow-Headers"]
    assert "X-Client-Id" in response.headers["Access-Control-Allow-Headers"]

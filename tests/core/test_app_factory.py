"""Smoke tests for the Flask app factory."""

from __future__ import annotations

import pytest
from flask import Flask
from flask.testing import FlaskClient

from knuckles.app import create_app


@pytest.fixture
def app() -> Flask:
    return create_app()


@pytest.fixture
def client(app: Flask) -> FlaskClient:
    return app.test_client()


def test_health_endpoint_returns_ok(client: FlaskClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}


def test_jwks_endpoint_publishes_public_key(client: FlaskClient) -> None:
    response = client.get("/.well-known/jwks.json")
    assert response.status_code == 200
    body = response.get_json()
    assert "keys" in body
    assert len(body["keys"]) == 1
    jwk = body["keys"][0]
    assert jwk["kid"] == "test-key-1"
    assert jwk["alg"] == "RS256"


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

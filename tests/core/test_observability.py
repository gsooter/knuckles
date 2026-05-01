"""Tests for the request-id correlation primitive.

Pinning behavior so error responses, success responses, and the
``X-Request-Id`` header all carry a consistent id, and the global
error handler logs it alongside every ``AppError``.
"""

from __future__ import annotations

import logging
import re

import pytest
from flask import Flask, jsonify
from flask.testing import FlaskClient

from knuckles.app import create_app
from knuckles.core.exceptions import ValidationError


@pytest.fixture
def app() -> Flask:
    """Build an app with one extra route that intentionally raises.

    Returns:
        A Flask app instance with a ``/_boom`` route registered.
    """
    app = create_app()

    @app.route("/_boom")
    def boom() -> object:
        """Raise a known ``AppError`` so we can assert on the envelope.

        Raises:
            ValidationError: Always.
        """
        raise ValidationError("intentional test failure")

    return app


@pytest.fixture
def client(app: Flask) -> FlaskClient:
    """Return the test client.

    Args:
        app: The Flask app fixture.

    Returns:
        A ``FlaskClient`` bound to ``app``.
    """
    return app.test_client()


_UUID_RE = re.compile(r"^[0-9a-f-]{36}$")


def test_success_response_carries_x_request_id(client: FlaskClient) -> None:
    """Every response includes ``X-Request-Id`` — even successful ones."""
    response = client.get("/health")
    assert response.status_code == 200
    rid = response.headers.get("X-Request-Id")
    assert rid is not None
    assert _UUID_RE.match(rid)


def test_inbound_x_request_id_is_echoed(client: FlaskClient) -> None:
    """A caller-supplied ``X-Request-Id`` flows through end-to-end."""
    response = client.get("/health", headers={"X-Request-Id": "caller-xyz-1"})
    assert response.headers.get("X-Request-Id") == "caller-xyz-1"


def test_oversized_inbound_request_id_is_replaced(client: FlaskClient) -> None:
    """A 1KB caller-supplied id is rejected and replaced with a UUID."""
    response = client.get("/health", headers={"X-Request-Id": "a" * 1024})
    rid = response.headers.get("X-Request-Id")
    assert rid is not None
    assert rid != "a" * 1024
    assert _UUID_RE.match(rid)


def test_error_response_includes_meta_request_id(client: FlaskClient) -> None:
    """The error envelope grows a ``meta.request_id`` field."""
    response = client.get("/_boom")
    assert response.status_code == 422
    body = response.get_json()
    assert body["error"]["code"] == "VALIDATION_ERROR"
    assert body["error"]["message"] == "intentional test failure"
    assert "meta" in body
    assert body["meta"]["request_id"] == response.headers.get("X-Request-Id")


def test_error_handler_logs_with_request_id(
    client: FlaskClient, caplog: pytest.LogCaptureFixture
) -> None:
    """The error handler emits a WARNING line carrying the request id."""
    caplog.set_level(logging.WARNING, logger="knuckles.errors")
    response = client.get("/_boom", headers={"X-Request-Id": "trace-123"})
    assert response.status_code == 422
    matching = [r for r in caplog.records if "trace-123" in r.getMessage()]
    assert matching, (
        f"expected a log line containing 'trace-123', got: "
        f"{[r.getMessage() for r in caplog.records]}"
    )
    line = matching[0].getMessage()
    assert "VALIDATION_ERROR" in line
    assert "intentional test failure" in line


def test_unknown_route_404_also_carries_request_id(client: FlaskClient) -> None:
    """Werkzeug's auto 404 also includes ``meta.request_id``."""
    response = client.get("/no-such-path", headers={"X-Request-Id": "nope-1"})
    assert response.status_code == 404
    body = response.get_json()
    assert body["meta"]["request_id"] == "nope-1"
    assert response.headers.get("X-Request-Id") == "nope-1"


def test_jsonify_response_too(app: Flask, client: FlaskClient) -> None:
    """Confirm ``jsonify`` responses also pick up the header."""

    @app.route("/_ok")
    def ok() -> object:
        return jsonify({"ok": True})

    response = client.get("/_ok")
    assert response.headers.get("X-Request-Id") is not None

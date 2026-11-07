"""Tests for :mod:`knuckles.core.admin_auth`.

The ``require_admin`` decorator gates the operator provisioning
surface. With no ``KNUCKLES_ADMIN_TOKEN`` configured the routes must
404 — existing deployments keep a zero admin attack surface. With a
token configured, only an exactly-matching ``X-Admin-Token`` header
reaches the wrapped view.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from flask import Flask, jsonify
from flask.testing import FlaskClient

from knuckles.core.admin_auth import require_admin
from knuckles.core.exceptions import AppError

_ADMIN_TOKEN = "test-admin-token-with-enough-entropy"


@pytest.fixture()
def app() -> Iterator[Flask]:
    """Build a minimal Flask app with a single admin-gated route.

    Yields:
        A configured Flask app whose ``/admin-protected`` route is
        wrapped in :func:`require_admin`.
    """
    app = Flask(__name__)
    app.config["TESTING"] = True

    @app.errorhandler(AppError)
    def _handle(exc: AppError) -> tuple[dict[str, dict[str, str]], int]:
        """Render an ``AppError`` as the standard JSON error envelope.

        Args:
            exc: The raised application error.

        Returns:
            Tuple of error body and HTTP status code.
        """
        return {"error": {"code": exc.code, "message": exc.message}}, exc.status_code

    @app.route("/admin-protected")
    @require_admin
    def protected() -> object:
        """Return a marker payload proving the view executed.

        Returns:
            A JSON response containing ``{"ok": True}``.
        """
        return jsonify({"ok": True})

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


def test_disabled_when_env_empty_returns_404(
    client: FlaskClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With no admin token configured, the route 404s even with a header."""
    monkeypatch.delenv("KNUCKLES_ADMIN_TOKEN", raising=False)

    response = client.get(
        "/admin-protected", headers={"X-Admin-Token": "anything-at-all"}
    )

    assert response.status_code == 404
    assert response.get_json()["error"]["code"] == "NOT_FOUND"


def test_missing_header_rejected_401(
    client: FlaskClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A configured token plus a missing header is a clean 401."""
    monkeypatch.setenv("KNUCKLES_ADMIN_TOKEN", _ADMIN_TOKEN)

    response = client.get("/admin-protected")

    assert response.status_code == 401
    assert response.get_json()["error"]["code"] == "UNAUTHORIZED"


def test_wrong_token_rejected_401(
    client: FlaskClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A mismatched ``X-Admin-Token`` is rejected with 401."""
    monkeypatch.setenv("KNUCKLES_ADMIN_TOKEN", _ADMIN_TOKEN)

    response = client.get(
        "/admin-protected", headers={"X-Admin-Token": "not-the-token"}
    )

    assert response.status_code == 401
    assert response.get_json()["error"]["code"] == "UNAUTHORIZED"


def test_non_ascii_token_rejected_401_not_500(
    client: FlaskClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A non-ASCII header value hashes to a mismatch, never a crash."""
    monkeypatch.setenv("KNUCKLES_ADMIN_TOKEN", _ADMIN_TOKEN)

    response = client.get(
        "/admin-protected", headers={"X-Admin-Token": "ñøt-the-tøken"}
    )

    assert response.status_code == 401
    assert response.get_json()["error"]["code"] == "UNAUTHORIZED"


def test_correct_token_runs_view(
    client: FlaskClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The exact configured token reaches the wrapped view."""
    monkeypatch.setenv("KNUCKLES_ADMIN_TOKEN", _ADMIN_TOKEN)

    response = client.get("/admin-protected", headers={"X-Admin-Token": _ADMIN_TOKEN})

    assert response.status_code == 200
    assert response.get_json() == {"ok": True}

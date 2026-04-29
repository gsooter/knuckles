"""HTTP-layer tests for the post-audit additions.

Covers:

* ``GET /v1/auth/passkey`` and ``DELETE /v1/auth/passkey/<id>`` —
  user-scoped passkey management.
* ``POST /v1/logout/all`` — revoke every refresh token for the
  signed-in user.
* ``GET /.well-known/openid-configuration`` — partial OIDC discovery.
* JWKS ``Cache-Control`` header.
* ``KNUCKLES_STRICT_CORS`` per-origin allow-list behavior.
* The magic-link 429 path when the per-email rate limit is exhausted.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator

import pytest
from flask import Flask
from flask.testing import FlaskClient
from sqlalchemy.orm import Session

import knuckles.api.v1.magic_link as magic_link_route_mod
import knuckles.core.app_client_auth as app_client_auth_mod
import knuckles.core.cors as cors_mod
import knuckles.core.database as database_mod
from knuckles.app import create_app
from knuckles.core.jwt import issue_access_token
from knuckles.core.rate_limit import magic_link_limiter
from knuckles.data.repositories import auth as repo
from knuckles.services import tokens


def _bearer_for(user_id: str, app_client_id: str) -> dict[str, str]:
    """Build an ``Authorization: Bearer`` header for a user.

    Args:
        user_id: UUID string to embed as ``sub``.
        app_client_id: ``aud`` claim to embed.

    Returns:
        Header dict suitable for the test client.
    """
    token = issue_access_token(user_id=user_id, app_client_id=app_client_id)
    return {"Authorization": f"Bearer {token}"}


def _client_headers(creds: tuple[str, str]) -> dict[str, str]:
    """Build ``X-Client-*`` headers from the ``app_client_creds`` fixture."""
    client_id, secret = creds
    return {"X-Client-Id": client_id, "X-Client-Secret": secret}


# ---------------------------------------------------------------------------
# Passkey list & delete
# ---------------------------------------------------------------------------


def test_passkey_list_returns_owned_credentials(
    client: FlaskClient,
    db_session: Session,
    app_client_creds: tuple[str, str],
) -> None:
    """A user sees only the passkeys they own."""
    user = repo.create_user(db_session, email="owner@example.com")
    repo.create_passkey(
        db_session,
        user_id=user.id,
        credential_id="cred-1",
        public_key="cHVibGlj",
        sign_count=0,
        name="Laptop",
    )
    other = repo.create_user(db_session, email="other@example.com")
    repo.create_passkey(
        db_session,
        user_id=other.id,
        credential_id="cred-other",
        public_key="cHVibGlj",
        sign_count=0,
    )

    response = client.get(
        "/v1/auth/passkey", headers=_bearer_for(str(user.id), app_client_creds[0])
    )
    assert response.status_code == 200
    data = response.get_json()["data"]
    assert len(data) == 1
    assert data[0]["credential_id"] == "cred-1"
    assert data[0]["name"] == "Laptop"


def test_passkey_list_requires_bearer(client: FlaskClient) -> None:
    """No bearer token → 401."""
    response = client.get("/v1/auth/passkey")
    assert response.status_code == 401


def test_passkey_delete_removes_owned_credential(
    client: FlaskClient,
    db_session: Session,
    app_client_creds: tuple[str, str],
) -> None:
    """A user can delete their own passkey."""
    user = repo.create_user(db_session, email="owner@example.com")
    repo.create_passkey(
        db_session,
        user_id=user.id,
        credential_id="cred-mine",
        public_key="cHVibGlj",
        sign_count=0,
    )

    response = client.delete(
        "/v1/auth/passkey/cred-mine",
        headers=_bearer_for(str(user.id), app_client_creds[0]),
    )
    assert response.status_code == 204
    assert repo.list_passkeys_for_user(db_session, user.id) == []


def test_passkey_delete_refuses_to_touch_other_users_credentials(
    client: FlaskClient,
    db_session: Session,
    app_client_creds: tuple[str, str],
) -> None:
    """Deleting another user's credential id returns 404 and leaves it alone."""
    user = repo.create_user(db_session, email="me@example.com")
    other = repo.create_user(db_session, email="other@example.com")
    repo.create_passkey(
        db_session,
        user_id=other.id,
        credential_id="cred-other",
        public_key="cHVibGlj",
        sign_count=0,
    )

    response = client.delete(
        "/v1/auth/passkey/cred-other",
        headers=_bearer_for(str(user.id), app_client_creds[0]),
    )
    assert response.status_code == 404
    assert response.get_json()["error"]["code"] == "PASSKEY_AUTH_FAILED"
    assert len(repo.list_passkeys_for_user(db_session, other.id)) == 1


def test_passkey_delete_unknown_id_returns_404(
    client: FlaskClient,
    db_session: Session,
    app_client_creds: tuple[str, str],
) -> None:
    """Deleting a credential id that does not exist returns 404."""
    user = repo.create_user(db_session, email="me@example.com")
    response = client.delete(
        "/v1/auth/passkey/ghost",
        headers=_bearer_for(str(user.id), app_client_creds[0]),
    )
    assert response.status_code == 404


# ---------------------------------------------------------------------------
# Sign-out-everywhere
# ---------------------------------------------------------------------------


def test_logout_all_revokes_every_refresh_token_for_user(
    client: FlaskClient,
    db_session: Session,
    app_client_creds: tuple[str, str],
) -> None:
    """Issues two pairs, then ``/v1/logout/all`` marks both consumed."""
    client_id, _ = app_client_creds
    user = repo.create_user(db_session, email="multi@example.com")
    pair_a = tokens.issue_session(db_session, user_id=user.id, app_client_id=client_id)
    pair_b = tokens.issue_session(db_session, user_id=user.id, app_client_id=client_id)

    headers = {
        **_client_headers(app_client_creds),
        **_bearer_for(str(user.id), client_id),
    }
    response = client.post("/v1/logout/all", headers=headers)
    assert response.status_code == 200
    assert response.get_json()["data"]["revoked"] == 2

    # Both refresh tokens are now consumed.
    for plaintext in (pair_a.refresh_token, pair_b.refresh_token):
        token_hash = hashlib.sha256(plaintext.encode("ascii")).hexdigest()
        row = repo.get_refresh_token_by_hash(db_session, token_hash)
        assert row is not None and row.used_at is not None


def test_logout_all_requires_both_client_and_bearer(
    client: FlaskClient,
    db_session: Session,
    app_client_creds: tuple[str, str],
) -> None:
    """Bearer alone is not enough — client headers are also required."""
    user = repo.create_user(db_session, email="x@example.com")
    response = client.post(
        "/v1/logout/all", headers=_bearer_for(str(user.id), app_client_creds[0])
    )
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# OIDC discovery + JWKS cache headers
# ---------------------------------------------------------------------------


def test_openid_configuration_returns_discovery_doc(client: FlaskClient) -> None:
    """The discovery doc carries ``issuer`` and ``jwks_uri``."""
    response = client.get("/.well-known/openid-configuration")
    assert response.status_code == 200
    body = response.get_json()
    assert body["issuer"] == "http://localhost:5001"
    assert body["jwks_uri"].endswith("/.well-known/jwks.json")
    assert "RS256" in body["id_token_signing_alg_values_supported"]


def test_jwks_carries_cache_control_header(client: FlaskClient) -> None:
    """JWKS responses are cacheable so consumers don't refetch per request."""
    response = client.get("/.well-known/jwks.json")
    assert response.status_code == 200
    assert "max-age" in response.headers.get("Cache-Control", "")


# ---------------------------------------------------------------------------
# Strict-CORS allow-list
# ---------------------------------------------------------------------------


@pytest.fixture()
def strict_cors_app(
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
    app_client_creds: tuple[str, str],
) -> Iterator[Flask]:
    """Build the app with strict CORS turned on for this test only.

    Args:
        db_session: SQLite-backed session.
        monkeypatch: pytest helper.
        app_client_creds: registers ``http://localhost:3000`` as
            allowed.

    Yields:
        The configured Flask app.
    """
    monkeypatch.setenv("KNUCKLES_STRICT_CORS", "true")
    monkeypatch.setattr(database_mod, "get_db", lambda: db_session)
    monkeypatch.setattr(app_client_auth_mod.database, "get_db", lambda: db_session)
    monkeypatch.setattr(
        cors_mod.database,
        "get_session_factory",
        lambda: (lambda: db_session),
    )
    cors_mod.reset_cache()
    yield create_app()
    cors_mod.reset_cache()


def test_strict_cors_echoes_registered_origin(
    strict_cors_app: Flask, app_client_creds: tuple[str, str]
) -> None:
    """An allowed origin gets ``Access-Control-Allow-Origin: <origin>``."""
    response = strict_cors_app.test_client().get(
        "/health", headers={"Origin": "http://localhost:3000"}
    )
    assert response.status_code == 200
    assert response.headers.get("Access-Control-Allow-Origin") == (
        "http://localhost:3000"
    )


def test_strict_cors_omits_header_for_unknown_origin(
    strict_cors_app: Flask, app_client_creds: tuple[str, str]
) -> None:
    """An unregistered origin gets no CORS header — browser will block."""
    response = strict_cors_app.test_client().get(
        "/health", headers={"Origin": "http://evil.example.com"}
    )
    assert response.status_code == 200
    assert "Access-Control-Allow-Origin" not in response.headers


# ---------------------------------------------------------------------------
# Magic-link rate limit
# ---------------------------------------------------------------------------


def test_magic_link_rate_limit_returns_429(
    client: FlaskClient,
    app_client_creds: tuple[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Once the per-email budget is exhausted, ``/start`` returns 429."""
    monkeypatch.setattr(
        magic_link_route_mod, "get_default_sender", lambda: _SilentSender()
    )

    # Exhaust the limiter for this email.
    bucket = f"{app_client_creds[0]}:user@example.com"
    for _ in range(5):
        assert magic_link_limiter.allow(bucket)

    response = client.post(
        "/v1/auth/magic-link/start",
        json={
            "email": "user@example.com",
            "redirect_url": "http://localhost:3000/auth/verify",
        },
        headers=_client_headers(app_client_creds),
    )
    assert response.status_code == 429
    assert response.get_json()["error"]["code"] == "RATE_LIMITED"


# ---------------------------------------------------------------------------
# Redirect-URL validation at the route layer
# ---------------------------------------------------------------------------


def test_magic_link_start_rejects_unregistered_redirect(
    client: FlaskClient,
    app_client_creds: tuple[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A redirect URL outside the app-client's allowed origins is 422."""
    monkeypatch.setattr(
        magic_link_route_mod, "get_default_sender", lambda: _SilentSender()
    )
    response = client.post(
        "/v1/auth/magic-link/start",
        json={
            "email": "user@example.com",
            "redirect_url": "http://evil.example.com/steal",
        },
        headers=_client_headers(app_client_creds),
    )
    assert response.status_code == 422
    assert response.get_json()["error"]["code"] == "VALIDATION_ERROR"


class _SilentSender:
    """Email backend that drops every send.

    Used so the rate-limit test doesn't depend on the route's mailer
    fixture wiring.
    """

    def send(
        self,
        *,
        to: str,
        subject: str,
        body: str,
        from_name: str | None = None,
    ) -> None:
        """Discard the outbound email.

        Args:
            to: Recipient address (ignored).
            subject: Subject line (ignored).
            body: Email body (ignored).
            from_name: Optional display name (ignored).
        """
        return None

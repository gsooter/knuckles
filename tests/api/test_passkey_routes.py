"""Tests for the WebAuthn passkey HTTP routes.

Four endpoints exercised:

* ``/v1/auth/passkey/register/begin`` and ``/register/complete`` —
  bearer-token auth required (the user is enrolling a passkey on
  their existing account).
* ``/v1/auth/passkey/sign-in/begin`` and ``/sign-in/complete`` —
  app-client auth required (the user is anonymous; sign-in is the
  moment we *learn* who they are).

The two ``verify_*`` calls inside the service are monkeypatched so
the tests don't need real cryptographic signatures.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest
from flask.testing import FlaskClient
from sqlalchemy.orm import Session

from knuckles.core.jwt import issue_access_token
from knuckles.data.repositories import auth as repo
from knuckles.services import passkey


@dataclass
class _FakeRegistration:
    """Stand-in for ``webauthn.VerifiedRegistration``.

    Attributes:
        credential_id: Raw credential id bytes.
        credential_public_key: Raw COSE public-key bytes.
        sign_count: Initial sign count.
    """

    credential_id: bytes
    credential_public_key: bytes
    sign_count: int


@dataclass
class _FakeAuthentication:
    """Stand-in for ``webauthn.VerifiedAuthentication``.

    Attributes:
        new_sign_count: Sign count reported by the authenticator.
    """

    new_sign_count: int


def _stub_register(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force the registration verifier to a fixed success.

    Args:
        monkeypatch: pytest's monkeypatch helper.
    """
    monkeypatch.setattr(
        passkey,
        "verify_registration_response",
        lambda **_kw: _FakeRegistration(
            credential_id=b"cred-id-bytes",
            credential_public_key=b"public-key-bytes",
            sign_count=0,
        ),
    )


def _stub_authenticate(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force the authentication verifier to a fixed success.

    Args:
        monkeypatch: pytest's monkeypatch helper.
    """
    monkeypatch.setattr(
        passkey,
        "verify_authentication_response",
        lambda **_kw: _FakeAuthentication(new_sign_count=7),
    )


def _auth_headers(creds: tuple[str, str]) -> dict[str, str]:
    """Build the X-Client-Id / X-Client-Secret header pair.

    Args:
        creds: ``(client_id, secret)`` from the ``app_client_creds`` fixture.

    Returns:
        Header dict for the test client's ``headers`` kwarg.
    """
    client_id, secret = creds
    return {"X-Client-Id": client_id, "X-Client-Secret": secret}


def _bearer_for(user_id: str, app_client_id: str) -> dict[str, str]:
    """Mint an ``Authorization: Bearer`` header for a Knuckles user.

    Args:
        user_id: UUID string of the user.
        app_client_id: ``aud`` to embed in the token.

    Returns:
        Header dict for the test client's ``headers`` kwarg.
    """
    token = issue_access_token(user_id=user_id, app_client_id=app_client_id)
    return {"Authorization": f"Bearer {token}"}


def test_passkey_register_begin_requires_bearer(client: FlaskClient) -> None:
    """Calling /register/begin without a bearer token yields 401."""
    response = client.post("/v1/auth/passkey/register/begin")
    assert response.status_code == 401


def test_passkey_register_begin_returns_options_and_state(
    client: FlaskClient,
    db_session: Session,
    app_client_creds: tuple[str, str],
) -> None:
    """Happy path: 200 with options + state for the signed-in user."""
    user = repo.create_user(db_session, email="user@example.com")
    headers = _bearer_for(str(user.id), app_client_creds[0])

    response = client.post("/v1/auth/passkey/register/begin", headers=headers)
    assert response.status_code == 200
    data = response.get_json()["data"]
    assert data["options"]["rp"]["id"] == "localhost"
    assert data["options"]["challenge"]
    assert data["state"]


def test_passkey_register_complete_persists_credential(
    client: FlaskClient,
    db_session: Session,
    app_client_creds: tuple[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End-to-end: begin then complete persists a passkey row."""
    user = repo.create_user(db_session, email="user@example.com")
    headers = _bearer_for(str(user.id), app_client_creds[0])
    _stub_register(monkeypatch)

    begin = client.post("/v1/auth/passkey/register/begin", headers=headers)
    state = begin.get_json()["data"]["state"]

    response = client.post(
        "/v1/auth/passkey/register/complete",
        headers=headers,
        json={
            "credential": {
                "id": "cred-id-bytes",
                "response": {"transports": ["internal"]},
            },
            "state": state,
            "name": "MacBook",
        },
    )
    assert response.status_code == 201
    assert response.get_json()["data"]["credential_id"]

    rows = repo.list_passkeys_for_user(db_session, user.id)
    assert len(rows) == 1
    assert rows[0].name == "MacBook"
    assert rows[0].transports == "internal"


def test_passkey_register_complete_validates_credential_field(
    client: FlaskClient,
    db_session: Session,
    app_client_creds: tuple[str, str],
) -> None:
    """Missing ``credential`` yields 422 ``VALIDATION_ERROR``."""
    user = repo.create_user(db_session, email="user@example.com")
    headers = _bearer_for(str(user.id), app_client_creds[0])

    response = client.post(
        "/v1/auth/passkey/register/complete",
        headers=headers,
        json={"state": "anything"},
    )
    assert response.status_code == 422
    assert response.get_json()["error"]["code"] == "VALIDATION_ERROR"


def test_passkey_signin_begin_requires_app_client_auth(client: FlaskClient) -> None:
    """Calling /sign-in/begin without app-client headers yields 401."""
    response = client.post("/v1/auth/passkey/sign-in/begin")
    assert response.status_code == 401


def test_passkey_signin_returns_token_pair(
    client: FlaskClient,
    db_session: Session,
    app_client_creds: tuple[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End-to-end: sign-in begin → complete returns an access+refresh pair."""
    user = repo.create_user(db_session, email="user@example.com")
    repo.create_passkey(
        db_session,
        user_id=user.id,
        credential_id="known-cred",
        public_key="cHVibGljLWtleQ",
        sign_count=0,
    )
    _stub_authenticate(monkeypatch)

    begin = client.post(
        "/v1/auth/passkey/sign-in/begin",
        headers=_auth_headers(app_client_creds),
    )
    state = begin.get_json()["data"]["state"]

    response = client.post(
        "/v1/auth/passkey/sign-in/complete",
        headers=_auth_headers(app_client_creds),
        json={
            "credential": {"id": "known-cred", "response": {}},
            "state": state,
        },
    )
    assert response.status_code == 200
    data = response.get_json()["data"]
    assert data["access_token"]
    assert data["refresh_token"]
    assert data["token_type"] == "Bearer"


def test_passkey_signin_complete_validates_required_fields(
    client: FlaskClient,
    app_client_creds: tuple[str, str],
) -> None:
    """Missing ``credential`` or ``state`` yields 422 ``VALIDATION_ERROR``."""
    response = client.post(
        "/v1/auth/passkey/sign-in/complete",
        headers=_auth_headers(app_client_creds),
        json={"state": "anything"},
    )
    assert response.status_code == 422
    assert response.get_json()["error"]["code"] == "VALIDATION_ERROR"


def test_passkey_signin_complete_rejects_unknown_credential(
    client: FlaskClient,
    db_session: Session,
    app_client_creds: tuple[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unknown credential id yields 400 ``PASSKEY_AUTH_FAILED``."""
    _stub_authenticate(monkeypatch)
    begin = client.post(
        "/v1/auth/passkey/sign-in/begin",
        headers=_auth_headers(app_client_creds),
    )
    state = begin.get_json()["data"]["state"]

    response = client.post(
        "/v1/auth/passkey/sign-in/complete",
        headers=_auth_headers(app_client_creds),
        json={
            "credential": {"id": "ghost", "response": {}},
            "state": state,
        },
    )
    assert response.status_code == 400
    assert response.get_json()["error"]["code"] == "PASSKEY_AUTH_FAILED"

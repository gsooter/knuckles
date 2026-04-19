"""Tests for :mod:`knuckles.services.passkey`.

WebAuthn assertions need real cryptographic signatures the test env
can't produce, so the two ``verify_*`` calls are monkeypatched at the
import sites inside the service module. The ``generate_*`` calls run
for real — they emit deterministic-shape options dicts and a fresh
challenge per ceremony, which is enough to exercise the state JWT
round-trip and the persistence side-effects.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

import pytest
from sqlalchemy.orm import Session

from knuckles.core.exceptions import (
    PASSKEY_AUTH_FAILED,
    PASSKEY_REGISTRATION_FAILED,
    AppError,
)
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


def _stub_register_verifier(
    monkeypatch: pytest.MonkeyPatch,
    *,
    credential_id: bytes = b"cred-id-bytes",
    public_key: bytes = b"public-key-bytes",
    sign_count: int = 0,
) -> None:
    """Force ``verify_registration_response`` to a fixed result.

    Args:
        monkeypatch: pytest's monkeypatch helper.
        credential_id: Raw credential id bytes the verifier returns.
        public_key: Raw COSE public-key bytes the verifier returns.
        sign_count: Sign count the verifier reports.
    """
    monkeypatch.setattr(
        passkey,
        "verify_registration_response",
        lambda **_kw: _FakeRegistration(
            credential_id=credential_id,
            credential_public_key=public_key,
            sign_count=sign_count,
        ),
    )


def _stub_authenticate_verifier(
    monkeypatch: pytest.MonkeyPatch,
    *,
    new_sign_count: int = 1,
) -> None:
    """Force ``verify_authentication_response`` to a fixed result.

    Args:
        monkeypatch: pytest's monkeypatch helper.
        new_sign_count: Sign count the verifier reports.
    """
    monkeypatch.setattr(
        passkey,
        "verify_authentication_response",
        lambda **_kw: _FakeAuthentication(new_sign_count=new_sign_count),
    )


def _register_app_client(db_session: Session) -> str:
    """Insert a minimal app-client row and return its id.

    Args:
        db_session: Active SQLAlchemy session.

    Returns:
        The new ``app_clients.client_id``.
    """
    repo.create_app_client(
        db_session,
        client_id="greenroom-prod",
        app_name="Greenroom",
        client_secret_hash="hash",
        allowed_origins=["http://localhost:3000"],
    )
    return "greenroom-prod"


def test_register_begin_returns_options_and_state(db_session: Session) -> None:
    """Options carry challenge + rp + user; state JWT decodes back."""
    user = repo.create_user(db_session, email="user@example.com")

    started = passkey.register_begin(db_session, user_id=str(user.id))

    assert started.options["rp"]["id"] == "localhost"
    assert started.options["user"]["name"] == "user@example.com"
    assert started.options["challenge"]
    assert started.state

    from knuckles.core.state_jwt import verify_state

    claims = verify_state(started.state, purpose="passkey_register")
    assert claims["user_id"] == str(user.id)
    assert claims["challenge"] == started.options["challenge"]


def test_register_begin_rejects_unknown_user(db_session: Session) -> None:
    """A user_id that doesn't resolve raises ``PASSKEY_REGISTRATION_FAILED``."""
    with pytest.raises(AppError) as exc:
        passkey.register_begin(db_session, user_id=str(uuid.uuid4()))
    assert exc.value.code == PASSKEY_REGISTRATION_FAILED


def test_register_complete_persists_credential(
    db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Happy path stores a passkey row and returns the credential id."""
    user = repo.create_user(db_session, email="user@example.com")
    _stub_register_verifier(monkeypatch)
    started = passkey.register_begin(db_session, user_id=str(user.id))

    cred_id = passkey.register_complete(
        db_session,
        user_id=str(user.id),
        credential={
            "id": "cred-id-bytes",
            "response": {"transports": ["internal", "hybrid"]},
        },
        state=started.state,
        name="MacBook",
    )

    assert cred_id
    rows = repo.list_passkeys_for_user(db_session, user.id)
    assert len(rows) == 1
    assert rows[0].name == "MacBook"
    assert rows[0].transports == "internal,hybrid"
    assert rows[0].credential_id == cred_id


def test_register_complete_rejects_state_for_different_user(
    db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A state minted for user A cannot be redeemed by user B."""
    user_a = repo.create_user(db_session, email="a@example.com")
    user_b = repo.create_user(db_session, email="b@example.com")
    _stub_register_verifier(monkeypatch)
    started = passkey.register_begin(db_session, user_id=str(user_a.id))

    with pytest.raises(AppError) as exc:
        passkey.register_complete(
            db_session,
            user_id=str(user_b.id),
            credential={"id": "cred", "response": {}},
            state=started.state,
        )
    assert exc.value.code == PASSKEY_REGISTRATION_FAILED


def test_register_complete_rejects_invalid_state(
    db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A garbage state JWT raises ``PASSKEY_REGISTRATION_FAILED``."""
    user = repo.create_user(db_session, email="user@example.com")
    _stub_register_verifier(monkeypatch)

    with pytest.raises(AppError) as exc:
        passkey.register_complete(
            db_session,
            user_id=str(user.id),
            credential={"id": "cred", "response": {}},
            state="not.a.jwt",
        )
    assert exc.value.code == PASSKEY_REGISTRATION_FAILED


def test_register_complete_propagates_attestation_failure(
    db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If the verifier raises, the service maps it to the registration code."""
    user = repo.create_user(db_session, email="user@example.com")

    def _boom(**_kw: Any) -> _FakeRegistration:
        raise RuntimeError("attestation rejected")

    monkeypatch.setattr(passkey, "verify_registration_response", _boom)
    started = passkey.register_begin(db_session, user_id=str(user.id))

    with pytest.raises(AppError) as exc:
        passkey.register_complete(
            db_session,
            user_id=str(user.id),
            credential={"id": "cred", "response": {}},
            state=started.state,
        )
    assert exc.value.code == PASSKEY_REGISTRATION_FAILED


def test_authenticate_begin_returns_options_and_state(db_session: Session) -> None:
    """Sign-in options carry rp_id + challenge; state binds the app_client."""
    client_id = _register_app_client(db_session)

    started = passkey.authenticate_begin(app_client_id=client_id)

    assert started.options["rpId"] == "localhost"
    assert started.options["challenge"]
    assert started.state

    from knuckles.core.state_jwt import verify_state

    claims = verify_state(started.state, purpose="passkey_auth")
    assert claims["app_client_id"] == client_id
    assert claims["challenge"] == started.options["challenge"]


def test_authenticate_complete_returns_token_pair(
    db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Happy path: assertion verifies, sign count bumps, tokens issued."""
    client_id = _register_app_client(db_session)
    user = repo.create_user(db_session, email="user@example.com")
    repo.create_passkey(
        db_session,
        user_id=user.id,
        credential_id="known-cred",
        public_key="cHVibGljLWtleQ",
        sign_count=0,
    )
    _stub_authenticate_verifier(monkeypatch, new_sign_count=5)

    started = passkey.authenticate_begin(app_client_id=client_id)

    pair = passkey.authenticate_complete(
        db_session,
        credential={"id": "known-cred", "response": {}},
        state=started.state,
        app_client_id=client_id,
    )
    assert pair.access_token
    assert pair.refresh_token

    refreshed = repo.get_passkey_by_credential_id(db_session, "known-cred")
    assert refreshed is not None
    assert refreshed.sign_count == 5


def test_authenticate_complete_rejects_unknown_credential(
    db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A credential id with no matching row raises ``PASSKEY_AUTH_FAILED``."""
    client_id = _register_app_client(db_session)
    _stub_authenticate_verifier(monkeypatch)
    started = passkey.authenticate_begin(app_client_id=client_id)

    with pytest.raises(AppError) as exc:
        passkey.authenticate_complete(
            db_session,
            credential={"id": "nope", "response": {}},
            state=started.state,
            app_client_id=client_id,
        )
    assert exc.value.code == PASSKEY_AUTH_FAILED


def test_authenticate_complete_rejects_state_for_wrong_app_client(
    db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A state issued for app A cannot be redeemed by app B."""
    client_id = _register_app_client(db_session)
    repo.create_app_client(
        db_session,
        client_id="other-app",
        app_name="Other",
        client_secret_hash="hash",
        allowed_origins=["http://other.test"],
    )
    _stub_authenticate_verifier(monkeypatch)
    started = passkey.authenticate_begin(app_client_id=client_id)

    with pytest.raises(AppError) as exc:
        passkey.authenticate_complete(
            db_session,
            credential={"id": "any", "response": {}},
            state=started.state,
            app_client_id="other-app",
        )
    assert exc.value.code == PASSKEY_AUTH_FAILED


def test_authenticate_complete_rejects_inactive_user(
    db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Owner of the credential being deactivated yields ``PASSKEY_AUTH_FAILED``."""
    client_id = _register_app_client(db_session)
    user = repo.create_user(db_session, email="user@example.com")
    user.is_active = False
    db_session.flush()
    repo.create_passkey(
        db_session,
        user_id=user.id,
        credential_id="known-cred",
        public_key="cHVibGljLWtleQ",
        sign_count=0,
    )
    _stub_authenticate_verifier(monkeypatch)
    started = passkey.authenticate_begin(app_client_id=client_id)

    with pytest.raises(AppError) as exc:
        passkey.authenticate_complete(
            db_session,
            credential={"id": "known-cred", "response": {}},
            state=started.state,
            app_client_id=client_id,
        )
    assert exc.value.code == PASSKEY_AUTH_FAILED


def test_authenticate_complete_propagates_assertion_failure(
    db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A verifier exception maps to ``PASSKEY_AUTH_FAILED``."""
    client_id = _register_app_client(db_session)
    user = repo.create_user(db_session, email="user@example.com")
    repo.create_passkey(
        db_session,
        user_id=user.id,
        credential_id="known-cred",
        public_key="cHVibGljLWtleQ",
        sign_count=0,
    )

    def _boom(**_kw: Any) -> _FakeAuthentication:
        raise RuntimeError("signature mismatch")

    monkeypatch.setattr(passkey, "verify_authentication_response", _boom)
    started = passkey.authenticate_begin(app_client_id=client_id)

    with pytest.raises(AppError) as exc:
        passkey.authenticate_complete(
            db_session,
            credential={"id": "known-cred", "response": {}},
            state=started.state,
            app_client_id=client_id,
        )
    assert exc.value.code == PASSKEY_AUTH_FAILED

"""Tests for :mod:`knuckles.services.app_clients`.

Focuses on the validation and guardrail edges that sit below the HTTP
layer: client_id format rules, duplicate detection, origin
normalization, the ``webauthn_rp_id`` immutability guardrail, and the
redaction contract of :func:`serialize`.
"""

from __future__ import annotations

import hashlib

import pytest
from sqlalchemy.orm import Session

from knuckles.core.exceptions import NotFoundError, ValidationError
from knuckles.data.models import AppClient
from knuckles.data.repositories import auth as repo
from knuckles.services import app_clients as service


def _register(session: Session, client_id: str = "acme-prod") -> AppClient:
    """Register a baseline app client through the service.

    Args:
        session: Active SQLAlchemy session.
        client_id: Client id for the new tenant.

    Returns:
        The created ``AppClient`` row.
    """
    client, _secret = service.register(
        session,
        client_id=client_id,
        app_name=f"App {client_id}",
        allowed_origins=["http://localhost:3000"],
    )
    return client


def _add_passkey(session: Session) -> None:
    """Insert a user with one passkey credential.

    Args:
        session: Active SQLAlchemy session.
    """
    user = repo.create_user(session, email="owner@acme.test")
    repo.create_passkey(
        session,
        user_id=user.id,
        credential_id="cred-1",
        public_key="pk-1",
        sign_count=0,
    )


# ---------------------------------------------------------------------------
# register
# ---------------------------------------------------------------------------


def test_register_stores_hash_of_returned_secret(db_session: Session) -> None:
    """The returned plaintext hashes to the stored digest."""
    client, secret = service.register(
        db_session,
        client_id="acme-prod",
        app_name="Acme",
        allowed_origins=[],
    )

    assert client.client_id == "acme-prod"
    expected = hashlib.sha256(secret.encode("ascii")).hexdigest()
    assert client.client_secret_hash == expected


def test_register_normalizes_origins(db_session: Session) -> None:
    """Origins are canonicalized (default ports dropped, paths stripped)."""
    client, _secret = service.register(
        db_session,
        client_id="acme-prod",
        app_name="Acme",
        allowed_origins=["https://app.acme.test:443/some/path"],
    )

    assert client.allowed_origins == ["https://app.acme.test"]


@pytest.mark.parametrize(
    "bad_id", ["", "ab", "UPPER", "-lead", "trail-", "has space", "a" * 65]
)
def test_register_rejects_bad_client_id(db_session: Session, bad_id: str) -> None:
    """Client ids outside the slug grammar raise ``ValidationError``."""
    with pytest.raises(ValidationError):
        service.register(
            db_session, client_id=bad_id, app_name="Acme", allowed_origins=[]
        )


def test_register_rejects_blank_app_name(db_session: Session) -> None:
    """Empty / whitespace-only app names raise ``ValidationError``."""
    with pytest.raises(ValidationError):
        service.register(
            db_session, client_id="acme-prod", app_name="   ", allowed_origins=[]
        )


def test_register_rejects_duplicate_client_id(db_session: Session) -> None:
    """A second registration of the same client_id is refused."""
    _register(db_session)
    with pytest.raises(ValidationError):
        service.register(
            db_session, client_id="acme-prod", app_name="Other", allowed_origins=[]
        )


def test_register_rejects_duplicate_app_name(db_session: Session) -> None:
    """A second registration of the same app_name is refused."""
    _register(db_session)
    with pytest.raises(ValidationError):
        service.register(
            db_session,
            client_id="acme-staging",
            app_name="App acme-prod",
            allowed_origins=[],
        )


def test_register_rejects_invalid_origin(db_session: Session) -> None:
    """Non-http(s) origins raise ``ValidationError`` at registration."""
    with pytest.raises(ValidationError):
        service.register(
            db_session,
            client_id="acme-prod",
            app_name="Acme",
            allowed_origins=["javascript:alert(1)"],
        )


# ---------------------------------------------------------------------------
# rotate_secret
# ---------------------------------------------------------------------------


def test_rotate_secret_replaces_hash(db_session: Session) -> None:
    """Rotation stores the hash of a freshly returned plaintext."""
    client = _register(db_session)
    old_hash = client.client_secret_hash

    new_secret = service.rotate_secret(db_session, client_id="acme-prod")

    refreshed = repo.get_app_client(db_session, "acme-prod")
    assert refreshed is not None
    assert refreshed.client_secret_hash != old_hash
    expected = hashlib.sha256(new_secret.encode("ascii")).hexdigest()
    assert refreshed.client_secret_hash == expected


def test_rotate_secret_unknown_client(db_session: Session) -> None:
    """Rotating an unknown client raises ``NotFoundError``."""
    with pytest.raises(NotFoundError):
        service.rotate_secret(db_session, client_id="nope")


# ---------------------------------------------------------------------------
# set_origins
# ---------------------------------------------------------------------------


def test_set_origins_replaces_and_normalizes(db_session: Session) -> None:
    """The whole list is replaced and each origin canonicalized."""
    _register(db_session)

    client = service.set_origins(
        db_session,
        client_id="acme-prod",
        allowed_origins=["http://localhost:80/x", "https://app.acme.test"],
    )

    assert client.allowed_origins == ["http://localhost", "https://app.acme.test"]


def test_set_origins_rejects_invalid(db_session: Session) -> None:
    """A non-parsing origin raises ``ValidationError``."""
    _register(db_session)
    with pytest.raises(ValidationError):
        service.set_origins(
            db_session, client_id="acme-prod", allowed_origins=["not a url"]
        )


def test_set_origins_unknown_client(db_session: Session) -> None:
    """Setting origins on an unknown client raises ``NotFoundError``."""
    with pytest.raises(NotFoundError):
        service.set_origins(db_session, client_id="nope", allowed_origins=[])


# ---------------------------------------------------------------------------
# update_config + rp_id guardrail
# ---------------------------------------------------------------------------


def test_update_config_unknown_client(db_session: Session) -> None:
    """Updating an unknown client raises ``NotFoundError``."""
    with pytest.raises(NotFoundError):
        service.update_config(
            db_session, client_id="nope", updates={"resend_from_email": "x@y.test"}
        )


def test_update_config_unknown_field(db_session: Session) -> None:
    """Allow-list violations surface as ``ValidationError``, not 500s."""
    _register(db_session)
    with pytest.raises(ValidationError):
        service.update_config(
            db_session, client_id="acme-prod", updates={"client_secret_hash": "x"}
        )


def test_rp_id_first_set_allowed_even_with_passkeys(db_session: Session) -> None:
    """Setting rp_id when the current value is NULL is always allowed."""
    _register(db_session)
    _add_passkey(db_session)

    client = service.update_config(
        db_session, client_id="acme-prod", updates={"webauthn_rp_id": "acme.test"}
    )

    assert client.webauthn_rp_id == "acme.test"


def test_rp_id_change_allowed_without_passkeys(db_session: Session) -> None:
    """With zero passkeys the rp_id may change freely."""
    _register(db_session)
    service.update_config(
        db_session, client_id="acme-prod", updates={"webauthn_rp_id": "acme.test"}
    )

    client = service.update_config(
        db_session, client_id="acme-prod", updates={"webauthn_rp_id": "other.test"}
    )

    assert client.webauthn_rp_id == "other.test"


def test_rp_id_same_value_allowed_with_passkeys(db_session: Session) -> None:
    """Re-sending the current rp_id is a no-op, not a guardrail trip."""
    _register(db_session)
    service.update_config(
        db_session, client_id="acme-prod", updates={"webauthn_rp_id": "acme.test"}
    )
    _add_passkey(db_session)

    client = service.update_config(
        db_session, client_id="acme-prod", updates={"webauthn_rp_id": "acme.test"}
    )

    assert client.webauthn_rp_id == "acme.test"


def test_rp_id_change_blocked_with_passkeys(db_session: Session) -> None:
    """Changing a set rp_id with passkeys present raises without force."""
    _register(db_session)
    service.update_config(
        db_session, client_id="acme-prod", updates={"webauthn_rp_id": "acme.test"}
    )
    _add_passkey(db_session)

    with pytest.raises(ValidationError):
        service.update_config(
            db_session,
            client_id="acme-prod",
            updates={"webauthn_rp_id": "other.test"},
        )


def test_rp_id_clear_blocked_with_passkeys(db_session: Session) -> None:
    """Clearing rp_id to NULL counts as a change and is also blocked."""
    _register(db_session)
    service.update_config(
        db_session, client_id="acme-prod", updates={"webauthn_rp_id": "acme.test"}
    )
    _add_passkey(db_session)

    with pytest.raises(ValidationError):
        service.update_config(
            db_session, client_id="acme-prod", updates={"webauthn_rp_id": None}
        )


def test_rp_id_change_allowed_with_force(db_session: Session) -> None:
    """``force_webauthn_rp_id=True`` overrides the guardrail."""
    _register(db_session)
    service.update_config(
        db_session, client_id="acme-prod", updates={"webauthn_rp_id": "acme.test"}
    )
    _add_passkey(db_session)

    client = service.update_config(
        db_session,
        client_id="acme-prod",
        updates={"webauthn_rp_id": "other.test"},
        force_webauthn_rp_id=True,
    )

    assert client.webauthn_rp_id == "other.test"


# ---------------------------------------------------------------------------
# serialize
# ---------------------------------------------------------------------------


def test_serialize_redacts_encrypted_columns(db_session: Session) -> None:
    """Encrypted columns appear only as ``*_configured`` booleans."""
    _register(db_session)
    service.update_config(
        db_session,
        client_id="acme-prod",
        updates={
            "resend_api_key": "rk_secret",
            "google_oauth_client_id": "g-client-id",
        },
    )
    client = repo.get_app_client(db_session, "acme-prod")
    assert client is not None

    data = service.serialize(client)

    assert data["client_id"] == "acme-prod"
    assert data["google_oauth_client_id"] == "g-client-id"
    assert data["resend_api_key_configured"] is True
    assert data["google_oauth_client_secret_configured"] is False
    assert data["apple_oauth_private_key_configured"] is False
    assert "resend_api_key" not in data
    assert "google_oauth_client_secret" not in data
    assert "apple_oauth_private_key" not in data
    assert "client_secret_hash" not in data
    assert "rk_secret" not in repr(data)
    assert isinstance(data["created_at"], str)

"""Tests for the per-tenant secrets encryption seam (Decision #017).

Covers the Fernet singleton's failure modes, the encrypt/decrypt
roundtrip, and the ``EncryptedText`` type decorator end-to-end —
including the at-rest representation, which must be ciphertext, never
plaintext.
"""

from __future__ import annotations

import uuid

import pytest
from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy.exc import StatementError
from sqlalchemy.orm import Session

from knuckles.core import secrets
from knuckles.data.models.auth import AppClient


def _make_app_client(**overrides: object) -> AppClient:
    """Build an unsaved ``AppClient`` row with sane defaults.

    Args:
        overrides: Column values to override on the constructed row.

    Returns:
        An ``AppClient`` instance ready to be added to a session.
    """
    defaults: dict[str, object] = {
        "client_id": f"client-{uuid.uuid4().hex[:8]}",
        "app_name": f"App {uuid.uuid4().hex[:8]}",
        "client_secret_hash": "0" * 64,
        "allowed_origins": ["http://localhost:3000"],
    }
    defaults.update(overrides)
    return AppClient(**defaults)


class TestGetFernet:
    """Behavior of the cached Fernet singleton."""

    def test_returns_fernet_with_configured_key(self) -> None:
        """A configured key yields a working Fernet instance.

        The suite-wide conftest key is valid, so construction must
        succeed and roundtrip a value.
        """
        fernet = secrets.get_fernet()
        token = fernet.encrypt(b"hello")
        assert fernet.decrypt(token) == b"hello"

    def test_empty_key_raises_loudly(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """An empty ``KNUCKLES_SECRETS_KEY`` refuses to operate.

        Loud failure is the documented dev-mode invariant — never
        silent plaintext.
        """
        monkeypatch.setenv("KNUCKLES_SECRETS_KEY", "")
        secrets.get_fernet.cache_clear()
        with pytest.raises(secrets.SecretsKeyNotConfiguredError):
            secrets.get_fernet()

    def test_invalid_key_raises_value_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A malformed key fails Fernet construction."""
        monkeypatch.setenv("KNUCKLES_SECRETS_KEY", "not-a-fernet-key")
        secrets.get_fernet.cache_clear()
        with pytest.raises(ValueError):
            secrets.get_fernet()


class TestEncryptDecrypt:
    """The module-level encrypt/decrypt helpers."""

    def test_roundtrip(self) -> None:
        """Encrypting then decrypting returns the original plaintext."""
        ciphertext = secrets.encrypt("re_live_abc123")
        assert ciphertext != "re_live_abc123"
        assert secrets.decrypt(ciphertext) == "re_live_abc123"

    def test_roundtrip_preserves_unicode(self) -> None:
        """Non-ASCII plaintext survives the roundtrip."""
        ciphertext = secrets.encrypt("clé-secrète-ñ")
        assert secrets.decrypt(ciphertext) == "clé-secrète-ñ"

    def test_decrypt_with_wrong_key_raises_invalid_token(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Ciphertext written under another key fails loudly."""
        ciphertext = secrets.encrypt("value-under-key-one")
        monkeypatch.setenv(
            "KNUCKLES_SECRETS_KEY", Fernet.generate_key().decode("ascii")
        )
        secrets.get_fernet.cache_clear()
        with pytest.raises(InvalidToken):
            secrets.decrypt(ciphertext)

    def test_encrypt_without_key_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """encrypt() inherits the missing-key failure mode."""
        monkeypatch.setenv("KNUCKLES_SECRETS_KEY", "")
        secrets.get_fernet.cache_clear()
        with pytest.raises(secrets.SecretsKeyNotConfiguredError):
            secrets.encrypt("anything")


class TestEncryptedTextColumn:
    """``EncryptedText`` end-to-end through the ORM."""

    def test_orm_roundtrip_reads_back_plaintext(self, db_session: Session) -> None:
        """A value written through the ORM reads back as plaintext."""
        client = _make_app_client(resend_api_key="re_live_secret")
        db_session.add(client)
        db_session.flush()
        db_session.expire(client)
        assert client.resend_api_key == "re_live_secret"

    def test_at_rest_value_is_ciphertext(self, db_session: Session) -> None:
        """The raw stored column value is Fernet ciphertext.

        This is the load-bearing property of Decision #017: a
        database-only compromise must not yield usable credentials.
        """
        client = _make_app_client(resend_api_key="re_live_secret")
        db_session.add(client)
        db_session.flush()

        raw = (
            db_session.connection()
            .exec_driver_sql(
                "SELECT resend_api_key FROM app_clients WHERE client_id = ?",
                (client.client_id,),
            )
            .scalar_one()
        )
        assert raw != "re_live_secret"
        assert secrets.decrypt(raw) == "re_live_secret"

    def test_null_passes_through(self, db_session: Session) -> None:
        """A NULL column reads back as ``None`` without decryption."""
        client = _make_app_client()
        db_session.add(client)
        db_session.flush()
        db_session.expire(client)
        assert client.resend_api_key is None

    def test_empty_string_passes_through_unencrypted(self, db_session: Session) -> None:
        """Empty strings bypass encryption in both directions."""
        client = _make_app_client(resend_api_key="")
        db_session.add(client)
        db_session.flush()

        raw = (
            db_session.connection()
            .exec_driver_sql(
                "SELECT resend_api_key FROM app_clients WHERE client_id = ?",
                (client.client_id,),
            )
            .scalar_one()
        )
        assert raw == ""
        db_session.expire(client)
        assert client.resend_api_key == ""

    def test_write_without_key_raises(
        self, db_session: Session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Writing an encrypted column with no key fails loudly.

        SQLAlchemy wraps bind-parameter failures in
        ``StatementError``; the original cause must be the loud
        missing-key error, never a silent plaintext write.
        """
        monkeypatch.setenv("KNUCKLES_SECRETS_KEY", "")
        secrets.get_fernet.cache_clear()
        client = _make_app_client(google_oauth_client_secret="gocspx-secret")
        db_session.add(client)
        with pytest.raises(StatementError) as excinfo:
            db_session.flush()
        assert isinstance(excinfo.value.orig, secrets.SecretsKeyNotConfiguredError)

"""Symmetric encryption for per-tenant secret-bearing columns.

Per Decision #017, secret-bearing columns on ``app_clients`` —
``resend_api_key``, ``google_oauth_client_secret``,
``apple_oauth_private_key`` — hold Fernet ciphertext rather than
plaintext. The symmetric key lives in the ``KNUCKLES_SECRETS_KEY``
env var so a database-only compromise (rogue backup, replica read
access, stale ``pg_dump``) doesn't yield usable credentials.

Two pieces:

* :func:`get_fernet` — lazy singleton wrapping
  ``cryptography.fernet.Fernet`` with the key from settings. Raises
  :class:`SecretsKeyNotConfiguredError` when the key is missing so the
  failure mode is loud rather than silently-write-plaintext.
* :class:`EncryptedText` — SQLAlchemy ``TypeDecorator`` that
  transparently encrypts on write and decrypts on read. The service
  layer treats encrypted columns as plain ``str`` values; the seam
  for Fernet (or a future swap to AES-GCM or to an external secrets
  manager) sits entirely inside this module.

NULL is passed through unchanged on both directions so an empty
column reads as ``None`` rather than triggering a decrypt of empty
bytes.
"""

from __future__ import annotations

from functools import lru_cache
from typing import TYPE_CHECKING

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import String, TypeDecorator

from knuckles.core.config import get_settings

if TYPE_CHECKING:
    from sqlalchemy.engine.interfaces import Dialect


class SecretsKeyNotConfiguredError(RuntimeError):
    """Raised when an encrypted column is touched without a configured key.

    Loud failure preserves the dev-mode invariant that an empty
    ``KNUCKLES_SECRETS_KEY`` means "this deployment does not handle
    encrypted tenant config." Without this guard a misconfigured
    production deploy would silently write plaintext into the
    encrypted columns, defeating the whole point of the column-level
    seam.
    """


@lru_cache(maxsize=1)
def get_fernet() -> Fernet:
    """Return a process-singleton :class:`Fernet` for tenant secrets.

    Cached because Fernet construction validates the key on every
    call, and the key is stable for the process lifetime. Use
    ``get_fernet.cache_clear()`` in tests that intentionally swap the
    key.

    Returns:
        A :class:`Fernet` instance built from the configured
        ``KNUCKLES_SECRETS_KEY``.

    Raises:
        SecretsKeyNotConfiguredError: If the env var is empty.
        ValueError: If the key is set but is not a valid Fernet key
            (wrong length, wrong base64 alphabet).
    """
    key = get_settings().knuckles_secrets_key
    if not key:
        raise SecretsKeyNotConfiguredError(
            "KNUCKLES_SECRETS_KEY is not configured. "
            "Generate one with `cryptography.fernet.Fernet.generate_key()` "
            "and set it in the deployment environment."
        )
    return Fernet(key.encode("ascii"))


def encrypt(plaintext: str) -> str:
    """Encrypt a plaintext string for storage in an encrypted column.

    Args:
        plaintext: The value to encrypt. Must be a non-empty string;
            empty values should be persisted as SQL NULL via the
            column itself rather than encrypting an empty string.

    Returns:
        Fernet ciphertext as a URL-safe base64 string.

    Raises:
        SecretsKeyNotConfiguredError: If ``KNUCKLES_SECRETS_KEY`` is empty.
    """
    return get_fernet().encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt(ciphertext: str) -> str:
    """Decrypt a Fernet ciphertext string back to plaintext.

    Args:
        ciphertext: The encrypted value, as produced by
            :func:`encrypt` or persisted by :class:`EncryptedText`.

    Returns:
        The original plaintext string.

    Raises:
        SecretsKeyNotConfiguredError: If ``KNUCKLES_SECRETS_KEY`` is empty.
        cryptography.fernet.InvalidToken: If the ciphertext is
            malformed or was encrypted with a different key (key
            rotation event that hasn't been completed).
    """
    return get_fernet().decrypt(ciphertext.encode("ascii")).decode("utf-8")


class EncryptedText(TypeDecorator[str]):
    """SQLAlchemy column type that transparently encrypts on write.

    Wraps :class:`sqlalchemy.String` (no length cap — the underlying
    column is ``TEXT`` in Postgres) and pipes every bind value
    through :func:`encrypt`, every result value through
    :func:`decrypt`. Service-layer code sees plaintext on both ends;
    only the on-disk representation is ciphertext.

    NULL is passed through unchanged so a column with no value reads
    back as ``None``. Empty strings are passed through unencrypted on
    write (and back as empty strings on read) — the column should be
    NULL-able and callers should use ``None`` to mean "unset," not
    the empty string, but this guard avoids a spurious encrypt of an
    empty placeholder.
    """

    impl = String
    cache_ok = True

    def process_bind_param(self, value: str | None, dialect: Dialect) -> str | None:
        """Encrypt the value before writing it to the database.

        Args:
            value: The plaintext string, ``None``, or empty string.
            dialect: The SQLAlchemy dialect handling the bind (unused
                here — the encryption format is dialect-agnostic).

        Returns:
            The Fernet ciphertext for the input, ``None`` if input
            was ``None``, or the empty string if input was empty.

        Raises:
            SecretsKeyNotConfiguredError: If the secrets key is missing.
        """
        if value is None:
            return None
        if value == "":
            return ""
        return encrypt(value)

    def process_result_value(self, value: str | None, dialect: Dialect) -> str | None:
        """Decrypt the value when reading it back from the database.

        Args:
            value: The ciphertext, ``None``, or empty string.
            dialect: The SQLAlchemy dialect handling the result row.

        Returns:
            The original plaintext string, ``None`` if the column was
            NULL, or the empty string if the column was empty (legacy
            row that predates encryption).

        Raises:
            SecretsKeyNotConfiguredError: If the secrets key is missing.
            cryptography.fernet.InvalidToken: If the column's
                ciphertext was written under a different key.
        """
        if value is None:
            return None
        if value == "":
            return ""
        try:
            return decrypt(value)
        except InvalidToken:
            # Surface key-mismatch / corrupt-ciphertext as a loud
            # error; the alternative (returning the raw ciphertext)
            # would silently leak Fernet output to OAuth providers.
            raise

"""Shared test fixtures for the Knuckles test suite.

The test env stubs a base64-encoded RS256 private key generated once
per test session, so every test that issues or verifies a JWT uses
a real signing key without needing OpenSSL on the dev box.

Repository-layer and service-layer tests reuse the ``db_session``
fixture defined here against an in-memory SQLite database so tests
stay hermetic and fast. Knuckles' models use cross-dialect types
(``sa.Uuid``, ``sa.JSON``) so the same schema works against Postgres
in production without a second definition.
"""

from __future__ import annotations

import base64
import os
from collections.abc import Iterator

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy.orm import Session


def _generate_test_private_key_b64() -> str:
    """Mint a throwaway 2048-bit RSA key and return base64-encoded PEM.

    Returns:
        The PEM bytes of a freshly generated private key, base64
        encoded (no newlines), suitable for use as
        ``KNUCKLES_JWT_PRIVATE_KEY``.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return base64.b64encode(pem).decode("ascii")


_TEST_ENV = {
    "DATABASE_URL": "postgresql://localhost/knuckles_test",
    "KNUCKLES_BASE_URL": "http://localhost:5001",
    "FRONTEND_BASE_URL": "http://localhost:3000",
    "KNUCKLES_JWT_PRIVATE_KEY": _generate_test_private_key_b64(),
    "KNUCKLES_JWT_KEY_ID": "test-key-1",
    "KNUCKLES_ACCESS_TOKEN_TTL_SECONDS": "3600",
    "KNUCKLES_REFRESH_TOKEN_TTL_SECONDS": "2592000",
    "KNUCKLES_STATE_SECRET": "test-state-secret-with-enough-entropy-12345",
    "MAGIC_LINK_TTL_SECONDS": "900",
    "SENDGRID_API_KEY": "test-sendgrid",
    "SENDGRID_FROM_EMAIL": "test@knuckles.test",
    "GOOGLE_OAUTH_CLIENT_ID": "test-google-client-id",
    "GOOGLE_OAUTH_CLIENT_SECRET": "test-google-client-secret",
    "APPLE_OAUTH_CLIENT_ID": "com.knuckles.test",
    "APPLE_OAUTH_TEAM_ID": "TESTTEAM01",
    "APPLE_OAUTH_KEY_ID": "TESTKEY001",
    "APPLE_OAUTH_PRIVATE_KEY": "test-apple-key-placeholder",
    "WEBAUTHN_RP_ID": "localhost",
    "WEBAUTHN_RP_NAME": "Knuckles Test",
    "WEBAUTHN_ORIGIN": "http://localhost:3000",
}

for _key, _value in _TEST_ENV.items():
    os.environ.setdefault(_key, _value)


@pytest.fixture(autouse=True)
def _reset_signing_key_cache() -> Iterator[None]:
    """Clear the cached RS256 signing key between tests.

    Tests that monkeypatch ``KNUCKLES_JWT_PRIVATE_KEY`` or
    ``KNUCKLES_JWT_KEY_ID`` would otherwise see the first-loaded key.

    Yields:
        None; teardown clears the cache again.
    """
    from knuckles.core.jwt import reset_key_cache

    reset_key_cache()
    yield
    reset_key_cache()


@pytest.fixture()
def db_session() -> Iterator[Session]:
    """Yield a fresh SQLite-backed SQLAlchemy session per test.

    The schema is created from the ORM metadata at the start of every
    test and the engine is disposed at teardown, giving each test a
    pristine database.

    Yields:
        An active ``Session`` bound to an in-memory SQLite engine.
    """
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from knuckles.core.database import Base
    from knuckles.data import models  # noqa: F401 — register on metadata

    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    session = factory()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()

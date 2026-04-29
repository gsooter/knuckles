"""Tests for the JWKS-cached access-token verifier.

We mint a real RS256 JWT with a freshly-generated key and inject the
matching public key into the verifier's internal :class:`PyJWKClient`
via monkeypatch. ``responses`` cannot intercept the JWKS fetch
because :class:`PyJWKClient` uses ``urllib`` directly.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from knuckles_client import KnucklesClient, KnucklesTokenError
from knuckles_client._jwks import JwksVerifier

from .conftest import BASE_URL, CLIENT_ID, CLIENT_SECRET


@dataclass
class _FakeSigningKey:
    """Stand-in for :class:`jwt.PyJWK` carrying the public key.

    Attributes:
        key: The cryptography public-key object.
    """

    key: rsa.RSAPublicKey


class _FakeJWKClient:
    """Drop-in for :class:`jwt.PyJWKClient` that returns a fixed key.

    Sidesteps the urllib JWKS fetch in tests.
    """

    def __init__(self, public_key: rsa.RSAPublicKey) -> None:
        """Wrap a single public key.

        Args:
            public_key: The RSA public key the verifier should trust.
        """
        self._public_key = public_key

    def get_signing_key_from_jwt(self, _token: str) -> _FakeSigningKey:
        """Return the wrapped public key regardless of the token's ``kid``.

        Args:
            _token: Ignored — single-key fake.

        Returns:
            A :class:`_FakeSigningKey` bound to the wrapped key.
        """
        return _FakeSigningKey(key=self._public_key)


def _make_key() -> rsa.RSAPrivateKey:
    """Generate a fresh RSA-2048 keypair for test use.

    Returns:
        The private key (the public half is derived as needed).
    """
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _mint_token(
    *,
    private_key: rsa.RSAPrivateKey,
    issuer: str,
    audience: str,
    sub: str = "user-1",
    expires_in: int = 3600,
) -> str:
    """Mint an RS256 JWT for the verifier tests.

    Args:
        private_key: The RSA signing key.
        issuer: ``iss`` claim.
        audience: ``aud`` claim.
        sub: ``sub`` claim.
        expires_in: Seconds until ``exp``.

    Returns:
        A signed JWT string.
    """
    now = int(time.time())
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return jwt.encode(
        {
            "iss": issuer,
            "aud": audience,
            "sub": sub,
            "iat": now,
            "exp": now + expires_in,
            "jti": str(uuid.uuid4()),
        },
        pem,
        algorithm="RS256",
        headers={"kid": "test-key"},
    )


def _client_with_key(public_key: rsa.RSAPublicKey) -> KnucklesClient:
    """Build a client whose verifier trusts exactly one public key.

    Args:
        public_key: The key the verifier should accept.

    Returns:
        A :class:`KnucklesClient` ready to call ``verify_access_token``.
    """
    client = KnucklesClient(
        base_url=BASE_URL, client_id=CLIENT_ID, client_secret=CLIENT_SECRET
    )
    verifier = JwksVerifier(
        jwks_uri=f"{BASE_URL}/.well-known/jwks.json",
        issuer=BASE_URL,
        audience=CLIENT_ID,
    )
    verifier._jwks = _FakeJWKClient(public_key)  # type: ignore[attr-defined]
    client._verifier = verifier  # type: ignore[attr-defined]
    return client


def test_verify_accepts_token_signed_by_trusted_key() -> None:
    """A token signed by a key in the JWKS verifies successfully."""
    private = _make_key()
    client = _client_with_key(private.public_key())
    token = _mint_token(private_key=private, issuer=BASE_URL, audience=CLIENT_ID)
    claims = client.verify_access_token(token)
    assert claims["sub"] == "user-1"
    assert claims["aud"] == CLIENT_ID


def test_verify_rejects_wrong_audience() -> None:
    """A token minted for a different ``aud`` is rejected."""
    private = _make_key()
    client = _client_with_key(private.public_key())
    token = _mint_token(private_key=private, issuer=BASE_URL, audience="different-app")
    with pytest.raises(KnucklesTokenError):
        client.verify_access_token(token)


def test_verify_rejects_expired_token() -> None:
    """A token whose ``exp`` is in the past is rejected."""
    private = _make_key()
    client = _client_with_key(private.public_key())
    token = _mint_token(
        private_key=private,
        issuer=BASE_URL,
        audience=CLIENT_ID,
        expires_in=-10,
    )
    with pytest.raises(KnucklesTokenError):
        client.verify_access_token(token)


def test_verify_rejects_token_signed_by_unknown_key() -> None:
    """A token signed with a key NOT in the JWKS is rejected."""
    trusted = _make_key()
    intruder = _make_key()
    client = _client_with_key(trusted.public_key())
    token = _mint_token(private_key=intruder, issuer=BASE_URL, audience=CLIENT_ID)
    with pytest.raises(KnucklesTokenError):
        client.verify_access_token(token)


def test_serialization_import_keeps_pem_helpers_available() -> None:
    """``cryptography`` PEM helpers stay importable for downstream use."""
    private = _make_key()
    pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    assert pem.startswith(b"-----BEGIN PRIVATE KEY-----")

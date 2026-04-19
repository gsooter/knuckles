"""Tests for ``knuckles.core.jwt``.

These tests exercise the RS256 signing path end-to-end using the real
key material stubbed by conftest. They don't mock PyJWT — correctness
of the audience, issuer, and expiration handling is the whole feature.
"""

from __future__ import annotations

import base64
import time
import uuid

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from knuckles.core.exceptions import INVALID_TOKEN, TOKEN_EXPIRED, UnauthorizedError
from knuckles.core.jwt import (
    get_jwks,
    get_public_key,
    get_signing_key,
    issue_access_token,
    verify_access_token,
)


def test_get_signing_key_loads_rsa_private_key() -> None:
    key = get_signing_key()
    assert isinstance(key, RSAPrivateKey)


def test_get_public_key_derives_from_signing_key() -> None:
    assert isinstance(get_public_key(), RSAPublicKey)


def test_issue_and_verify_access_token_roundtrip() -> None:
    user_id = uuid.uuid4()
    token = issue_access_token(
        user_id=user_id,
        app_client_id="greenroom",
        scopes=["openid", "profile"],
        email="a@example.com",
    )
    claims = verify_access_token(token)
    assert claims["sub"] == str(user_id)
    assert claims["aud"] == "greenroom"
    assert claims["iss"] == "http://localhost:5001"
    assert claims["scope"] == "openid profile"
    assert claims["email"] == "a@example.com"
    assert "jti" in claims
    assert claims["exp"] > claims["iat"]


def test_issue_access_token_includes_kid_header() -> None:
    token = issue_access_token(user_id=uuid.uuid4(), app_client_id="greenroom")
    header = pyjwt.get_unverified_header(token)
    assert header["alg"] == "RS256"
    assert header["kid"] == "test-key-1"


def test_issue_access_token_without_optional_fields() -> None:
    token = issue_access_token(user_id=uuid.uuid4(), app_client_id="greenroom")
    claims = verify_access_token(token)
    assert "scope" not in claims
    assert "email" not in claims


def test_verify_rejects_expired_token(monkeypatch: pytest.MonkeyPatch) -> None:
    # Move clock back by TTL + 60s so the freshly issued token is expired.
    real_time = time.time
    monkeypatch.setattr("knuckles.core.jwt.time.time", lambda: real_time() - 3660)
    token = issue_access_token(user_id=uuid.uuid4(), app_client_id="greenroom")
    monkeypatch.setattr("knuckles.core.jwt.time.time", real_time)

    with pytest.raises(UnauthorizedError) as excinfo:
        verify_access_token(token)
    assert excinfo.value.code == TOKEN_EXPIRED


def test_verify_rejects_garbage_token() -> None:
    with pytest.raises(UnauthorizedError) as excinfo:
        verify_access_token("not-a-jwt")
    assert excinfo.value.code == INVALID_TOKEN


def test_verify_rejects_token_signed_by_other_key() -> None:
    # Manually sign a valid-shaped token with a different key.
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other_pem = other_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    now = int(time.time())
    token = pyjwt.encode(
        {
            "iss": "http://localhost:5001",
            "sub": str(uuid.uuid4()),
            "aud": "greenroom",
            "iat": now,
            "exp": now + 3600,
        },
        other_pem,
        algorithm="RS256",
    )
    with pytest.raises(UnauthorizedError) as excinfo:
        verify_access_token(token)
    assert excinfo.value.code == INVALID_TOKEN


def test_verify_rejects_token_with_wrong_issuer() -> None:
    now = int(time.time())
    token = pyjwt.encode(
        {
            "iss": "http://evil.test",
            "sub": str(uuid.uuid4()),
            "aud": "greenroom",
            "iat": now,
            "exp": now + 3600,
        },
        get_signing_key(),
        algorithm="RS256",
        headers={"kid": "test-key-1"},
    )
    with pytest.raises(UnauthorizedError) as excinfo:
        verify_access_token(token)
    assert excinfo.value.code == INVALID_TOKEN


def test_jwks_shape_matches_public_key() -> None:
    jwks = get_jwks()
    assert set(jwks.keys()) == {"keys"}
    assert len(jwks["keys"]) == 1
    jwk = jwks["keys"][0]
    assert jwk["kty"] == "RSA"
    assert jwk["use"] == "sig"
    assert jwk["alg"] == "RS256"
    assert jwk["kid"] == "test-key-1"

    # n and e must be unpadded base64url and decode to the public numbers.
    public_numbers = get_public_key().public_numbers()
    assert "=" not in jwk["n"]
    assert "=" not in jwk["e"]
    n_bytes = base64.urlsafe_b64decode(jwk["n"] + "=" * (-len(jwk["n"]) % 4))
    e_bytes = base64.urlsafe_b64decode(jwk["e"] + "=" * (-len(jwk["e"]) % 4))
    assert int.from_bytes(n_bytes, "big") == public_numbers.n
    assert int.from_bytes(e_bytes, "big") == public_numbers.e


def test_jwks_key_validates_issued_token() -> None:
    """A consuming app can validate a Knuckles token using only the JWKS."""
    token = issue_access_token(user_id=uuid.uuid4(), app_client_id="greenroom")

    # Reconstruct the public key from the JWK as a consuming app would.
    jwk = get_jwks()["keys"][0]
    public_key = pyjwt.algorithms.RSAAlgorithm.from_jwk(jwk)

    claims = pyjwt.decode(
        token,
        public_key,
        algorithms=["RS256"],
        audience="greenroom",
        issuer="http://localhost:5001",
    )
    assert claims["aud"] == "greenroom"

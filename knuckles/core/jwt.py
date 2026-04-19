"""RS256 access-token signing, verification, and JWKS export.

Knuckles is the sole issuer of access tokens for every consuming app.
Tokens are signed with an RSA private key held only by this service;
every app validates tokens locally against the JWKS published at
``GET /.well-known/jwks.json``. Apps never call Knuckles to validate —
they fetch the JWKS once and verify per request against the cached
public key. That is the whole point of the RS256 + JWKS pattern.

Claim shape:
    iss  — ``knuckles_base_url``
    sub  — Knuckles ``users.id`` (UUID string)
    aud  — ``app_clients.client_id`` (every consuming app has exactly
           one; the consuming app rejects tokens whose ``aud`` is not its
           own)
    iat  — issued-at (unix seconds)
    exp  — expires-at (unix seconds)
    jti  — unique token id (useful for logging/audit; not tracked for
           revocation — access tokens are short-lived and any revocation
           flow goes through the refresh-token table instead)
    scope — space-separated strings granted to this token
    email — optional, present when the consuming app requests it
"""

from __future__ import annotations

import base64
import functools
import time
import uuid
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from knuckles.core.config import get_settings
from knuckles.core.exceptions import (
    INVALID_TOKEN,
    TOKEN_EXPIRED,
    UnauthorizedError,
)

_ALGORITHM = "RS256"


@functools.lru_cache(maxsize=1)
def get_signing_key() -> rsa.RSAPrivateKey:
    """Load and cache the RS256 private key from configuration.

    The key is expected to be a base64-encoded PEM (PKCS#8). Base64
    wrapping avoids newline headaches when pasting a PEM into a Railway
    env var.

    Returns:
        The RSA private key instance.

    Raises:
        RuntimeError: If the configured value is not a valid RSA
            private key in PEM format.
    """
    settings = get_settings()
    pem_bytes = base64.b64decode(settings.knuckles_jwt_private_key)
    key = serialization.load_pem_private_key(pem_bytes, password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise RuntimeError(
            "KNUCKLES_JWT_PRIVATE_KEY must be an RSA private key in PEM format.",
        )
    return key


def get_public_key() -> rsa.RSAPublicKey:
    """Derive the public key corresponding to the signing key.

    Returns:
        The RSA public key used by consuming apps to validate tokens.
    """
    return get_signing_key().public_key()


def reset_key_cache() -> None:
    """Drop the cached signing key.

    Tests call this after monkeypatching the environment so the next
    ``get_signing_key`` call re-reads the new settings.
    """
    get_signing_key.cache_clear()


def issue_access_token(
    *,
    user_id: uuid.UUID | str,
    app_client_id: str,
    scopes: list[str] | None = None,
    email: str | None = None,
) -> str:
    """Mint an RS256 access token for a given user and consuming app.

    Args:
        user_id: Knuckles ``users.id`` to embed as the ``sub`` claim.
        app_client_id: ``app_clients.client_id`` to embed as ``aud``.
        scopes: Optional list of scope strings. Joined into the
            space-separated ``scope`` claim.
        email: Optional email address to embed in the token.

    Returns:
        A signed JWT string.
    """
    settings = get_settings()
    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": settings.knuckles_base_url,
        "sub": str(user_id),
        "aud": app_client_id,
        "iat": now,
        "exp": now + settings.knuckles_access_token_ttl_seconds,
        "jti": str(uuid.uuid4()),
    }
    if scopes:
        claims["scope"] = " ".join(scopes)
    if email is not None:
        claims["email"] = email

    return jwt.encode(
        claims,
        get_signing_key(),
        algorithm=_ALGORITHM,
        headers={"kid": settings.knuckles_jwt_key_id},
    )


def verify_access_token(token: str) -> dict[str, Any]:
    """Verify a Knuckles-issued access token and return its claims.

    Knuckles accepts tokens issued for any registered ``app_client``
    (audience check is deferred to the route handler which knows what
    audience it wants).

    Args:
        token: The bearer token value from an ``Authorization`` header.

    Returns:
        The decoded claims dictionary.

    Raises:
        UnauthorizedError: If the token is expired, malformed, or fails
            signature verification. The ``code`` on the exception
            distinguishes the three cases.
    """
    settings = get_settings()
    try:
        claims: dict[str, Any] = jwt.decode(
            token,
            get_public_key(),
            algorithms=[_ALGORITHM],
            issuer=settings.knuckles_base_url,
            options={
                "require": ["iss", "sub", "aud", "iat", "exp"],
                "verify_aud": False,
            },
        )
    except jwt.ExpiredSignatureError as exc:
        raise UnauthorizedError(
            message="Access token has expired.", code=TOKEN_EXPIRED
        ) from exc
    except jwt.InvalidTokenError as exc:
        raise UnauthorizedError(
            message="Access token is invalid.", code=INVALID_TOKEN
        ) from exc
    return claims


def _int_to_base64url(value: int) -> str:
    """Encode a non-negative integer as unpadded base64url (JWK spec).

    Args:
        value: The non-negative integer (RSA modulus or exponent).

    Returns:
        The big-endian byte representation, base64url-encoded without
        padding, as required by RFC 7518.
    """
    length = (value.bit_length() + 7) // 8
    raw = value.to_bytes(length, byteorder="big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def get_jwks() -> dict[str, list[dict[str, str]]]:
    """Return the JWKS document consuming apps use to validate tokens.

    The document contains the Knuckles public key in JWK form with its
    stable ``kid``. Adding a new key (for rotation) is an append-only
    change to this function plus a config update.

    Returns:
        A dict of the shape ``{"keys": [...]}``. Each key entry
        includes ``kty``, ``use``, ``alg``, ``kid``, ``n``, and ``e``.
    """
    settings = get_settings()
    public_numbers = get_public_key().public_numbers()
    jwk: dict[str, str] = {
        "kty": "RSA",
        "use": "sig",
        "alg": _ALGORITHM,
        "kid": settings.knuckles_jwt_key_id,
        "n": _int_to_base64url(public_numbers.n),
        "e": _int_to_base64url(public_numbers.e),
    }
    return {"keys": [jwk]}

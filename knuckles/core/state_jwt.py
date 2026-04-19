"""Short-lived HS256 JWTs used as ceremony state.

OAuth flows and WebAuthn ceremonies need to carry state across the
browser roundtrip. Using a signed JWT instead of server-side storage
(Redis, DB) keeps Knuckles stateless for these flows: the state token
bounces through the user's browser and back, and we verify the HMAC
to prove it's ours and still within its short TTL.

The HMAC secret is ``KNUCKLES_STATE_SECRET`` — deliberately separate
from the RS256 signing key because state tokens never leave Knuckles
and rotating the secret doesn't require touching any consuming app.
"""

from __future__ import annotations

import time
from typing import Any

import jwt

from knuckles.core.config import get_settings

_ALGORITHM = "HS256"


def issue_state(
    *,
    purpose: str,
    payload: dict[str, Any],
    ttl_seconds: int = 5 * 60,
) -> str:
    """Issue a short-lived HS256 state JWT.

    Args:
        purpose: Discriminator string (e.g. ``"google_oauth"``,
            ``"passkey_register"``). Verified on the return leg so a
            state token for one flow can't be replayed into another.
        payload: Application-specific claims to embed.
        ttl_seconds: Lifetime of the token. Defaults to 5 minutes.

    Returns:
        A signed JWT string suitable for use as the OAuth ``state``
        parameter or the ``state`` field of a WebAuthn options payload.
    """
    settings = get_settings()
    now = int(time.time())
    claims: dict[str, Any] = {
        **payload,
        "purpose": purpose,
        "iat": now,
        "exp": now + ttl_seconds,
    }
    return jwt.encode(claims, settings.knuckles_state_secret, algorithm=_ALGORITHM)


def verify_state(token: str, *, purpose: str) -> dict[str, Any]:
    """Verify a state JWT and return its payload.

    Args:
        token: The state string bounced back by the browser.
        purpose: Expected discriminator. Raises if the token's purpose
            does not match.

    Returns:
        The decoded claims dictionary (still includes ``purpose``,
        ``iat``, ``exp``).

    Raises:
        ValueError: If the token is expired, malformed, signed with the
            wrong secret, or carries a mismatched ``purpose`` claim.
    """
    settings = get_settings()
    try:
        claims: dict[str, Any] = jwt.decode(
            token,
            settings.knuckles_state_secret,
            algorithms=[_ALGORITHM],
            options={"require": ["exp", "iat", "purpose"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise ValueError("State token expired.") from exc
    except jwt.InvalidTokenError as exc:
        raise ValueError("State token invalid.") from exc

    if claims.get("purpose") != purpose:
        raise ValueError("State token purpose mismatch.")
    return claims

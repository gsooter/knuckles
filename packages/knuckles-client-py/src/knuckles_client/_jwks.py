"""JWKS-cached access-token verifier for the Knuckles SDK.

Wraps :class:`jwt.PyJWKClient` so every call to
:func:`KnucklesClient.verify_access_token` reuses one cached key set
across requests. The cache is in-memory; the first verify on a fresh
process fetches the JWKS, subsequent verifies are local.

If you want graceful degradation when Knuckles is briefly unreachable,
persist the JWKS to disk in your application and feed it back via
:class:`jwt.PyJWKClient` directly — the SDK does not own that policy.
"""

from __future__ import annotations

from typing import Any

import jwt

from .exceptions import KnucklesTokenError


class JwksVerifier:
    """RS256 verifier backed by a long-lived JWKS cache.

    Attributes:
        jwks_uri: Fully-qualified JWKS URL.
        issuer: Expected ``iss`` claim (the Knuckles base URL).
        audience: Expected ``aud`` claim (the consuming app's
            ``client_id``).
    """

    def __init__(
        self,
        *,
        jwks_uri: str,
        issuer: str,
        audience: str,
        cache_keys: bool = True,
    ) -> None:
        """Initialize the verifier.

        Args:
            jwks_uri: Fully-qualified JWKS URL.
            issuer: Expected ``iss`` claim.
            audience: Expected ``aud`` claim.
            cache_keys: Forwarded to :class:`jwt.PyJWKClient`. Off only
                in tests that swap keys mid-suite.
        """
        self.jwks_uri = jwks_uri
        self.issuer = issuer
        self.audience = audience
        self._jwks = jwt.PyJWKClient(jwks_uri, cache_keys=cache_keys)

    def verify(self, token: str) -> dict[str, Any]:
        """Verify a Knuckles access token and return its claims.

        Args:
            token: The bearer access token.

        Returns:
            The decoded claims dict.

        Raises:
            KnucklesTokenError: For any signature, audience, issuer,
                or expiry failure.
        """
        try:
            signing_key = self._jwks.get_signing_key_from_jwt(token).key
            return dict(
                jwt.decode(
                    token,
                    signing_key,
                    algorithms=["RS256"],
                    issuer=self.issuer,
                    audience=self.audience,
                    options={"require": ["iss", "sub", "aud", "iat", "exp"]},
                )
            )
        except jwt.PyJWTError as exc:
            raise KnucklesTokenError(str(exc)) from exc
        except Exception as exc:  # JWKS fetch network errors etc.
            raise KnucklesTokenError(f"Could not verify token: {exc}") from exc

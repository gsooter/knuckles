"""Exception hierarchy for the Knuckles Python SDK.

Every Knuckles error response carries a machine-readable ``code``.
The SDK maps the common ones to typed exceptions so consuming code
can ``except KnucklesAuthError`` instead of pattern-matching strings.
Codes the SDK does not have a dedicated class for surface as the
generic :class:`KnucklesAPIError`.
"""

from __future__ import annotations


class KnucklesError(Exception):
    """Base class for every error the SDK raises."""


class KnucklesNetworkError(KnucklesError):
    """Knuckles was unreachable or returned an unparseable response."""


class KnucklesAPIError(KnucklesError):
    """Knuckles returned an error envelope.

    Attributes:
        code: The ``error.code`` string from the response body.
        message: The human-readable ``error.message``.
        status_code: HTTP status from Knuckles.
    """

    def __init__(self, *, code: str, message: str, status_code: int) -> None:
        """Initialize with the parsed error envelope.

        Args:
            code: ``error.code`` from the response.
            message: ``error.message`` from the response.
            status_code: HTTP status code.
        """
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.status_code = status_code


class KnucklesAuthError(KnucklesAPIError):
    """A 401/403 from Knuckles.

    Includes ``INVALID_CLIENT``, ``UNAUTHORIZED``, ``INVALID_TOKEN``,
    ``TOKEN_EXPIRED``, and the refresh-token error family
    (``REFRESH_TOKEN_INVALID``, ``REFRESH_TOKEN_EXPIRED``,
    ``REFRESH_TOKEN_REUSED``). Catch this class to handle the broad
    "user must re-authenticate" outcome.
    """


class KnucklesValidationError(KnucklesAPIError):
    """A 422 from Knuckles — the SDK or caller passed bad input."""


class KnucklesRateLimitError(KnucklesAPIError):
    """A 429 from Knuckles — back off and retry later."""


class KnucklesTokenError(KnucklesError):
    """An access token failed local JWKS verification.

    Raised by :func:`KnucklesClient.verify_access_token` for any
    signature, audience, issuer, or expiry failure. The wrapped
    cause is the underlying :mod:`jwt` exception.
    """

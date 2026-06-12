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
        request_id: The Knuckles ``meta.request_id`` value, if the
            server returned one. Quote this value when reporting the
            issue to the operator — they can grep their logs for it
            and find the matching server-side context. ``None`` only
            for older Knuckles servers that don't emit it.
    """

    def __init__(
        self,
        *,
        code: str,
        message: str,
        status_code: int,
        request_id: str | None = None,
    ) -> None:
        """Initialize with the parsed error envelope.

        Args:
            code: ``error.code`` from the response.
            message: ``error.message`` from the response.
            status_code: HTTP status code.
            request_id: Optional ``meta.request_id`` from the response
                body, for cross-system correlation.
        """
        suffix = f" (request_id={request_id})" if request_id else ""
        super().__init__(f"{code}: {message}{suffix}")
        self.code = code
        self.message = message
        self.status_code = status_code
        self.request_id = request_id


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
    """A 429 from Knuckles — back off and retry later.

    Attributes:
        retry_after: Seconds to wait before retrying, parsed from the
            ``Retry-After`` response header. ``None`` when the server
            did not send the header (older Knuckles servers) or sent
            an HTTP-date form the SDK does not parse.
    """

    def __init__(
        self,
        *,
        code: str,
        message: str,
        status_code: int,
        request_id: str | None = None,
        retry_after: int | None = None,
    ) -> None:
        """Initialize with the parsed error envelope plus the retry hint.

        Args:
            code: ``error.code`` from the response.
            message: ``error.message`` from the response.
            status_code: HTTP status code.
            request_id: Optional ``meta.request_id`` from the response
                body, for cross-system correlation.
            retry_after: Optional whole-second delay parsed from the
                ``Retry-After`` response header.
        """
        super().__init__(
            code=code,
            message=message,
            status_code=status_code,
            request_id=request_id,
        )
        self.retry_after = retry_after


class KnucklesTokenError(KnucklesError):
    """An access token failed local JWKS verification.

    Raised by :func:`KnucklesClient.verify_access_token` for any
    signature, audience, issuer, or expiry failure. The wrapped
    cause is the underlying :mod:`jwt` exception.
    """


class KnucklesTokenExpiredError(KnucklesTokenError):
    """An access token failed local verification *because it expired*.

    Subclass of :class:`KnucklesTokenError`, so existing
    ``except KnucklesTokenError`` handlers keep working. Catch this
    class specifically when expiry should trigger a refresh attempt
    while every other verification failure stays a hard error.

    The ``__cause__`` chain is part of the contract: this exception is
    always raised ``from`` the underlying
    :class:`jwt.ExpiredSignatureError`, so callers may inspect
    ``exc.__cause__`` for PyJWT-level detail.
    """

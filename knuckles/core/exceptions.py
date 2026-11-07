"""Custom exception classes and error codes for Knuckles.

Every public error returned by the HTTP layer maps to a code defined
here. Route handlers catch these and emit standardized JSON error
responses. Raw exception messages are never exposed to clients.
"""


class AppError(Exception):
    """Base exception for Knuckles-level errors with a public code.

    Attributes:
        code: Machine-readable error code string.
        message: Human-readable error description.
        status_code: HTTP status code for the error response.
        headers: Optional extra HTTP headers the error handler should
            attach to the response (e.g. ``Retry-After`` on a 429).
    """

    def __init__(
        self,
        code: str,
        message: str,
        status_code: int = 400,
        headers: dict[str, str] | None = None,
    ) -> None:
        """Initialize an ``AppError``.

        Args:
            code: Machine-readable error code string.
            message: Human-readable error description.
            status_code: HTTP status code. Defaults to 400.
            headers: Optional extra response headers.
        """
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
        self.headers = headers or {}


class NotFoundError(AppError):
    """Raised when a requested resource does not exist."""

    def __init__(self, code: str, message: str) -> None:
        """Initialize a ``NotFoundError``.

        Args:
            code: Machine-readable error code string.
            message: Human-readable error description.
        """
        super().__init__(code=code, message=message, status_code=404)


class UnauthorizedError(AppError):
    """Raised when authentication is missing or invalid."""

    def __init__(
        self, message: str = "Authentication required.", code: str = "UNAUTHORIZED"
    ) -> None:
        """Initialize an ``UnauthorizedError``.

        Args:
            message: Human-readable error description.
            code: Specific machine-readable code (defaults to
                ``UNAUTHORIZED``).
        """
        super().__init__(code=code, message=message, status_code=401)


class ForbiddenError(AppError):
    """Raised when the caller lacks permission for the action."""

    def __init__(self, message: str = "Forbidden.") -> None:
        """Initialize a ``ForbiddenError``.

        Args:
            message: Human-readable error description.
        """
        super().__init__(code="FORBIDDEN", message=message, status_code=403)


class ValidationError(AppError):
    """Raised when request input fails validation."""

    def __init__(self, message: str) -> None:
        """Initialize a ``ValidationError``.

        Args:
            message: Human-readable validation error description.
        """
        super().__init__(code="VALIDATION_ERROR", message=message, status_code=422)


# Error code constants — the full public vocabulary of Knuckles errors.
INVALID_TOKEN = "INVALID_TOKEN"
TOKEN_EXPIRED = "TOKEN_EXPIRED"
INVALID_CLIENT = "INVALID_CLIENT"
INVALID_SCOPE = "INVALID_SCOPE"
USER_NOT_FOUND = "USER_NOT_FOUND"
MAGIC_LINK_INVALID = "MAGIC_LINK_INVALID"
MAGIC_LINK_EXPIRED = "MAGIC_LINK_EXPIRED"
MAGIC_LINK_ALREADY_USED = "MAGIC_LINK_ALREADY_USED"
GOOGLE_AUTH_FAILED = "GOOGLE_AUTH_FAILED"
APPLE_AUTH_FAILED = "APPLE_AUTH_FAILED"
PASSKEY_AUTH_FAILED = "PASSKEY_AUTH_FAILED"
PASSKEY_REGISTRATION_FAILED = "PASSKEY_REGISTRATION_FAILED"
EMAIL_DELIVERY_FAILED = "EMAIL_DELIVERY_FAILED"
REFRESH_TOKEN_INVALID = "REFRESH_TOKEN_INVALID"
REFRESH_TOKEN_EXPIRED = "REFRESH_TOKEN_EXPIRED"
REFRESH_TOKEN_REUSED = "REFRESH_TOKEN_REUSED"
RATE_LIMITED = "RATE_LIMITED"
TENANT_CONFIG_INCOMPLETE = "TENANT_CONFIG_INCOMPLETE"
SESSION_NOT_FOUND = "SESSION_NOT_FOUND"
PROVIDER_NOT_FOUND = "PROVIDER_NOT_FOUND"
EMAIL_IN_USE = "EMAIL_IN_USE"
NOT_FOUND = "NOT_FOUND"
APP_CLIENT_NOT_FOUND = "APP_CLIENT_NOT_FOUND"

"""The CLI's single error type.

Every failure the CLI reports — a Knuckles API error passed through
verbatim, a network failure, or a local validation problem — is a
:class:`CliError` carrying a machine-readable ``code``. ``--json``
output renders it as the same ``{"error": {"code", "message"}}``
envelope the Knuckles API uses, so agents parse one shape everywhere.
"""

from __future__ import annotations

# Local (non-server) error codes.
NOT_LOGGED_IN = "NOT_LOGGED_IN"
NETWORK_ERROR = "NETWORK_ERROR"
INVALID_INPUT = "INVALID_INPUT"
ADMIN_API_DISABLED = "ADMIN_API_DISABLED"
ENV_FILE_CONFLICT = "ENV_FILE_CONFLICT"
HTTP_ERROR = "HTTP_ERROR"
EMAIL_DOMAIN_UNVERIFIED = "EMAIL_DOMAIN_UNVERIFIED"


class CliError(Exception):
    """A reportable CLI failure.

    Attributes:
        code: Machine-readable error code (a Knuckles API code or one
            of the local constants in this module).
        message: Human-readable explanation, safe to print.
        status_code: HTTP status when the error came from Knuckles.
    """

    def __init__(self, code: str, message: str, *, status_code: int | None = None):
        """Initialize the error.

        Args:
            code: Machine-readable error code.
            message: Human-readable explanation.
            status_code: Optional HTTP status from the server.
        """
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.status_code = status_code

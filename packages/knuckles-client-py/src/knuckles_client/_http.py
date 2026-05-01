"""Internal HTTP transport for the Knuckles SDK.

Wraps :mod:`requests` so every call goes through one place that
handles: client-secret header injection, JSON encoding, error-envelope
parsing, and exception mapping. Consumers never see ``requests``
directly.
"""

from __future__ import annotations

from typing import Any

import requests

from .exceptions import (
    KnucklesAPIError,
    KnucklesAuthError,
    KnucklesNetworkError,
    KnucklesRateLimitError,
    KnucklesValidationError,
)

_DEFAULT_TIMEOUT_SECONDS = 10


def _map_error(
    *,
    code: str,
    message: str,
    status_code: int,
    request_id: str | None = None,
) -> KnucklesAPIError:
    """Promote an error envelope to the matching SDK exception class.

    Args:
        code: ``error.code`` from the response body.
        message: ``error.message`` from the response body.
        status_code: HTTP status from Knuckles.
        request_id: Optional ``meta.request_id`` from the response,
            propagated onto the exception for log correlation.

    Returns:
        A :class:`KnucklesAPIError` (or one of its subclasses).
    """
    if status_code in (401, 403):
        return KnucklesAuthError(
            code=code,
            message=message,
            status_code=status_code,
            request_id=request_id,
        )
    if status_code == 422:
        return KnucklesValidationError(
            code=code,
            message=message,
            status_code=status_code,
            request_id=request_id,
        )
    if status_code == 429:
        return KnucklesRateLimitError(
            code=code,
            message=message,
            status_code=status_code,
            request_id=request_id,
        )
    return KnucklesAPIError(
        code=code,
        message=message,
        status_code=status_code,
        request_id=request_id,
    )


class HttpTransport:
    """Tiny wrapper around :class:`requests.Session` for the Knuckles API.

    Holds the configured base URL and (when supplied) the app-client
    headers, and surfaces every non-2xx response as a typed exception.

    Attributes:
        base_url: Knuckles base URL with no trailing slash.
        timeout: Per-request timeout in seconds.
    """

    def __init__(
        self,
        *,
        base_url: str,
        client_id: str | None,
        client_secret: str | None,
        timeout: float = _DEFAULT_TIMEOUT_SECONDS,
        session: requests.Session | None = None,
    ) -> None:
        """Initialize the transport.

        Args:
            base_url: Knuckles base URL (e.g. ``https://auth.example.com``).
            client_id: Optional app-client id sent on every request.
            client_secret: Optional app-client secret sent on every
                request. Required if ``client_id`` is set.
            timeout: Per-request timeout in seconds.
            session: Optional pre-built :class:`requests.Session` for
                connection pooling / proxying. A new one is created if
                not supplied.
        """
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._session = session or requests.Session()
        self._client_headers: dict[str, str] = {}
        if client_id and client_secret:
            self._client_headers = {
                "X-Client-Id": client_id,
                "X-Client-Secret": client_secret,
            }

    def request(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, Any] | None = None,
        bearer: str | None = None,
        send_client_headers: bool = True,
        expect_json: bool = True,
    ) -> dict[str, Any]:
        """Issue one HTTP call and return the parsed JSON body.

        Args:
            method: HTTP verb (``"GET"``, ``"POST"``, ``"DELETE"``).
            path: Path under the base URL, leading slash included.
            json: Optional JSON body.
            bearer: Optional access-token to send as
                ``Authorization: Bearer``.
            send_client_headers: If ``False``, omit
                ``X-Client-Id``/``X-Client-Secret`` even when configured
                — used by the JWKS fetcher and other unauthenticated
                routes.
            expect_json: If ``False``, treat an empty body as success
                and return ``{}``. Used by 204 responses (logout).

        Returns:
            The parsed JSON body, or ``{}`` for a successful 204.

        Raises:
            KnucklesNetworkError: On connection failure or invalid
                JSON in a 2xx response.
            KnucklesAPIError: On any non-2xx response carrying a
                Knuckles error envelope. Subclass varies by status.
        """
        url = f"{self.base_url}{path}"
        headers: dict[str, str] = {}
        if send_client_headers:
            headers.update(self._client_headers)
        if bearer:
            headers["Authorization"] = f"Bearer {bearer}"
        try:
            response = self._session.request(
                method,
                url,
                json=json,
                headers=headers,
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise KnucklesNetworkError(f"Knuckles call failed: {exc}") from exc

        if response.status_code == 204 or (
            not expect_json and 200 <= response.status_code < 300
        ):
            return {}

        try:
            body = response.json()
        except ValueError as exc:
            if 200 <= response.status_code < 300:
                raise KnucklesNetworkError(
                    "Knuckles returned a non-JSON success response."
                ) from exc
            raise KnucklesAPIError(
                code="UNPARSEABLE_RESPONSE",
                message=f"Knuckles returned non-JSON HTTP {response.status_code}.",
                status_code=response.status_code,
            ) from exc

        if 200 <= response.status_code < 300:
            assert isinstance(body, dict)
            return body

        error = body.get("error", {}) if isinstance(body, dict) else {}
        meta = body.get("meta", {}) if isinstance(body, dict) else {}
        request_id_raw = meta.get("request_id") if isinstance(meta, dict) else None
        # Fall back to the response header — older error responses
        # without a body still emit ``X-Request-Id``.
        request_id = (
            request_id_raw
            if isinstance(request_id_raw, str)
            else response.headers.get("X-Request-Id")
        )
        raise _map_error(
            code=str(error.get("code", "UNKNOWN")),
            message=str(error.get("message", "")),
            status_code=response.status_code,
            request_id=request_id,
        )

    def get_json(self, path: str) -> dict[str, Any]:
        """Convenience wrapper for unauthenticated GET requests.

        Args:
            path: Path under the base URL, leading slash included.

        Returns:
            The parsed JSON body.
        """
        return self.request("GET", path, send_client_headers=False)

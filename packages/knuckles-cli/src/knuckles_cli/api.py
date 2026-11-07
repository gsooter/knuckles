"""Thin HTTP client for the Knuckles public and admin endpoints.

Deliberately independent of the ``knuckles-client`` SDK (Decision
#025): the operator has an admin token, not app-client credentials,
and ``doctor`` needs raw status codes from the discovery endpoints.
"""

from __future__ import annotations

from typing import Any

import requests

from knuckles_cli import __version__
from knuckles_cli.errors import (
    ADMIN_API_DISABLED,
    HTTP_ERROR,
    NETWORK_ERROR,
    NOT_LOGGED_IN,
    CliError,
)

_ADMIN_BASE = "/v1/admin/app-clients"


class KnucklesAPI:
    """Calls one Knuckles deployment.

    Attributes:
        base_url: Knuckles base URL, no trailing slash.
    """

    def __init__(
        self,
        base_url: str,
        *,
        admin_token: str | None = None,
        timeout: float = 10.0,
        session: requests.Session | None = None,
    ) -> None:
        """Initialize the client.

        Args:
            base_url: Knuckles base URL.
            admin_token: Operator admin token for ``/v1/admin/*``.
            timeout: Per-request timeout in seconds.
            session: Optional pre-built session.
        """
        self.base_url = base_url.rstrip("/")
        self._admin_token = admin_token
        self._timeout = timeout
        self._session = session or requests.Session()
        self._session.headers["User-Agent"] = f"knuckles-cli/{__version__}"

    @property
    def has_admin_token(self) -> bool:
        """Whether admin calls can be made.

        Returns:
            ``True`` when an admin token is configured.
        """
        return self._admin_token is not None

    def _send(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> requests.Response:
        """Send one request, converting transport failures.

        Args:
            method: HTTP verb.
            path: Path under the base URL, leading slash included.
            json: Optional JSON body.
            headers: Optional extra headers.

        Returns:
            The raw response.

        Raises:
            CliError: ``NETWORK_ERROR`` if the server is unreachable.
        """
        try:
            return self._session.request(
                method,
                f"{self.base_url}{path}",
                json=json,
                headers=headers,
                timeout=self._timeout,
            )
        except requests.RequestException as exc:
            raise CliError(
                NETWORK_ERROR, f"Could not reach {self.base_url}: {exc}"
            ) from exc

    def get_public(self, path: str) -> tuple[int, Any]:
        """GET an unauthenticated endpoint, returning status and body.

        Args:
            path: Path under the base URL.

        Returns:
            Tuple of HTTP status and parsed JSON (``None`` when the body
            is not JSON).

        Raises:
            CliError: ``NETWORK_ERROR`` if the server is unreachable.
        """
        response = self._send("GET", path)
        try:
            return response.status_code, response.json()
        except ValueError:
            return response.status_code, None

    def admin(
        self, method: str, path: str = "", *, json: dict[str, Any] | None = None
    ) -> Any:
        """Call an admin route and return its ``data`` payload.

        Args:
            method: HTTP verb.
            path: Path under ``/v1/admin/app-clients``.
            json: Optional JSON body.

        Returns:
            The response's ``data`` value.

        Raises:
            CliError: ``NOT_LOGGED_IN`` without a token,
                ``ADMIN_API_DISABLED`` when the server's admin surface
                is off, or the server's own error code otherwise.
        """
        if self._admin_token is None:
            raise CliError(
                NOT_LOGGED_IN,
                "No admin token. Run `knuckles login` or set KNUCKLES_ADMIN_TOKEN.",
            )
        response = self._send(
            method,
            f"{_ADMIN_BASE}{path}",
            json=json,
            headers={"X-Admin-Token": self._admin_token},
        )
        try:
            body = response.json()
        except ValueError:
            body = None
        if response.ok and isinstance(body, dict) and "data" in body:
            return body["data"]

        error = body.get("error") if isinstance(body, dict) else None
        if isinstance(error, dict) and isinstance(error.get("code"), str):
            code = error["code"]
            message = str(error.get("message", ""))
        else:
            code = HTTP_ERROR
            message = f"Unexpected HTTP {response.status_code} from {self.base_url}."
        # Every admin route exists when the surface is on, so a bare
        # NOT_FOUND (not APP_CLIENT_NOT_FOUND) means it is switched off.
        if response.status_code == 404 and code == "NOT_FOUND":
            code = ADMIN_API_DISABLED
            message = (
                "The admin API is disabled on this server. Set "
                "KNUCKLES_ADMIN_TOKEN in the Knuckles environment and redeploy."
            )
        raise CliError(code, message, status_code=response.status_code)

    def list_apps(self) -> list[dict[str, Any]]:
        """List every tenant.

        Returns:
            Redacted app-client rows.
        """
        data = self.admin("GET")
        return list(data)

    def get_app(self, client_id: str) -> dict[str, Any]:
        """Fetch one tenant.

        Args:
            client_id: The tenant's ``client_id``.

        Returns:
            The redacted app-client row.
        """
        return dict(self.admin("GET", f"/{client_id}"))

    def create_app(
        self, *, client_id: str, app_name: str, allowed_origins: list[str]
    ) -> dict[str, Any]:
        """Register a tenant.

        Args:
            client_id: New ``client_id`` slug.
            app_name: Human-facing name.
            allowed_origins: Origins permitted in redirect URLs.

        Returns:
            The row plus the one-time ``client_secret``.
        """
        return dict(
            self.admin(
                "POST",
                json={
                    "client_id": client_id,
                    "app_name": app_name,
                    "allowed_origins": allowed_origins,
                },
            )
        )

    def update_app(self, client_id: str, fields: dict[str, Any]) -> dict[str, Any]:
        """Patch tenant-config columns.

        Args:
            client_id: The tenant's ``client_id``.
            fields: Column values; ``None`` clears to env fallback.

        Returns:
            The updated redacted row.
        """
        return dict(self.admin("PATCH", f"/{client_id}", json=fields))

    def rotate_secret(self, client_id: str) -> dict[str, Any]:
        """Mint a new client secret.

        Args:
            client_id: The tenant's ``client_id``.

        Returns:
            ``{"client_id", "client_secret"}``.
        """
        return dict(self.admin("POST", f"/{client_id}/rotate-secret"))

    def set_origins(self, client_id: str, origins: list[str]) -> dict[str, Any]:
        """Replace a tenant's allowed origins.

        Args:
            client_id: The tenant's ``client_id``.
            origins: The full new origin list.

        Returns:
            The updated redacted row.
        """
        return dict(
            self.admin(
                "PUT", f"/{client_id}/origins", json={"allowed_origins": origins}
            )
        )

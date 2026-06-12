"""High-level Knuckles client.

The :class:`KnucklesClient` exposes one method per public Knuckles
endpoint, plus a :func:`verify_access_token` shortcut that uses a
JWKS-cached verifier so consuming apps validate tokens locally.

Sub-clients group related ceremonies:

* ``client.magic_link`` — email magic-link flow.
* ``client.google`` — Google Sign-In.
* ``client.apple`` — Sign in with Apple.
* ``client.passkey`` — WebAuthn registration + sign-in + management.
* ``client.me`` — profile + account management (callable for the
  classic ``client.me(access_token=...)`` profile fetch).
* ``client.sessions`` — refresh-session listing + revocation.
* ``client.admin`` — operator-only app-client management; active only
  when the client is constructed with ``admin_token=...``.

Every ceremony method returns a typed dataclass from :mod:`models` and
raises a typed exception from :mod:`exceptions` on failure. The
account-management, session, and admin methods return the server's
``data`` payload as plain dicts — those endpoint shapes are newer and
pass through verbatim.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Final

import requests

from ._http import HttpTransport
from ._jwks import JwksVerifier
from .models import (
    CeremonyStart,
    PasskeyChallenge,
    PasskeyDescriptor,
    TokenPair,
    UserProfile,
)


class _Unset:
    """Sentinel type marking an argument as "not provided".

    Lets :func:`_MeClient.update_profile` distinguish an omitted field
    (leave it untouched server-side) from an explicit ``None`` (clear
    the field).
    """

    def __repr__(self) -> str:
        """Return a debugging-friendly marker.

        Returns:
            The literal string ``"<UNSET>"``.
        """
        return "<UNSET>"


_UNSET: Final[_Unset] = _Unset()


def _parse_token_pair(data: dict[str, Any]) -> TokenPair:
    """Map a Knuckles ``TokenPair`` JSON body to the typed dataclass.

    Args:
        data: The ``data`` block from a Knuckles success response.

    Returns:
        A populated :class:`TokenPair`.
    """
    return TokenPair(
        access_token=data["access_token"],
        access_token_expires_at=datetime.fromisoformat(data["access_token_expires_at"]),
        refresh_token=data["refresh_token"],
        refresh_token_expires_at=datetime.fromisoformat(
            data["refresh_token_expires_at"]
        ),
        token_type=data.get("token_type", "Bearer"),
    )


class _MagicLinkClient:
    """Email magic-link sub-client.

    Attributes:
        _http: Shared transport.
    """

    def __init__(self, http: HttpTransport) -> None:
        """Initialize with the shared transport.

        Args:
            http: The :class:`HttpTransport` from the parent client.
        """
        self._http = http

    def start(self, *, email: str, redirect_url: str) -> None:
        """Send a magic-link email to ``email``.

        Args:
            email: Recipient address.
            redirect_url: Verify endpoint on the consuming app. Must
                lie under one of the app-client's ``allowed_origins``.

        Raises:
            KnucklesValidationError: On bad input.
            KnucklesRateLimitError: Per-email throttle exceeded.
        """
        self._http.request(
            "POST",
            "/v1/auth/magic-link/start",
            json={"email": email, "redirect_url": redirect_url},
            expect_json=False,
        )

    def verify(self, token: str) -> TokenPair:
        """Redeem a magic-link token for a session.

        Args:
            token: The raw token from the email URL's ``token=`` param.

        Returns:
            The minted :class:`TokenPair`.

        Raises:
            KnucklesAPIError: ``MAGIC_LINK_INVALID``, ``MAGIC_LINK_EXPIRED``,
                or ``MAGIC_LINK_ALREADY_USED``.
        """
        body = self._http.request(
            "POST",
            "/v1/auth/magic-link/verify",
            json={"token": token},
        )
        return _parse_token_pair(body["data"])


class _OAuthClient:
    """Shared shape for Google/Apple OAuth sub-clients.

    Attributes:
        _http: Shared transport.
        _start_path: ``/v1/auth/<provider>/start``.
        _complete_path: ``/v1/auth/<provider>/complete``.
    """

    def __init__(
        self,
        http: HttpTransport,
        *,
        start_path: str,
        complete_path: str,
    ) -> None:
        """Initialize with the shared transport and provider paths.

        Args:
            http: Transport from the parent client.
            start_path: API path for the ``start`` step.
            complete_path: API path for the ``complete`` step.
        """
        self._http = http
        self._start_path = start_path
        self._complete_path = complete_path

    def start(self, *, redirect_url: str) -> CeremonyStart:
        """Get the consent URL and the matching state JWT.

        Args:
            redirect_url: Where the provider should send the user
                after consent.

        Returns:
            A :class:`CeremonyStart` with ``authorize_url`` + ``state``.
        """
        body = self._http.request(
            "POST", self._start_path, json={"redirect_url": redirect_url}
        )
        data = body["data"]
        return CeremonyStart(authorize_url=data["authorize_url"], state=data["state"])


class _GoogleClient(_OAuthClient):
    """Google Sign-In sub-client."""

    def __init__(self, http: HttpTransport) -> None:
        """Initialize with the shared transport.

        Args:
            http: Transport from the parent client.
        """
        super().__init__(
            http,
            start_path="/v1/auth/google/start",
            complete_path="/v1/auth/google/complete",
        )

    def complete(self, *, code: str, state: str) -> TokenPair:
        """Finish the Google ceremony and mint a session.

        Args:
            code: Authorization code from Google's redirect.
            state: State JWT from the matching :func:`start` call.

        Returns:
            The minted :class:`TokenPair`.

        Raises:
            KnucklesAPIError: ``GOOGLE_AUTH_FAILED`` for any step that
                fails server-side (state, code exchange, profile fetch).
        """
        body = self._http.request(
            "POST", self._complete_path, json={"code": code, "state": state}
        )
        return _parse_token_pair(body["data"])


class _AppleClient(_OAuthClient):
    """Apple Sign-In sub-client."""

    def __init__(self, http: HttpTransport) -> None:
        """Initialize with the shared transport.

        Args:
            http: Transport from the parent client.
        """
        super().__init__(
            http,
            start_path="/v1/auth/apple/start",
            complete_path="/v1/auth/apple/complete",
        )

    def complete(
        self,
        *,
        code: str,
        state: str,
        user: dict[str, Any] | None = None,
    ) -> TokenPair:
        """Finish the Apple ceremony and mint a session.

        Args:
            code: Authorization code from Apple's POST callback.
            state: State JWT from the matching :func:`start` call.
            user: Optional Apple ``user`` payload (only present on
                first sign-in for an Apple ID). Pass it through
                verbatim when present.

        Returns:
            The minted :class:`TokenPair`.

        Raises:
            KnucklesAPIError: ``APPLE_AUTH_FAILED`` on any failure.
        """
        payload: dict[str, Any] = {"code": code, "state": state}
        if user is not None:
            payload["user"] = user
        body = self._http.request("POST", self._complete_path, json=payload)
        return _parse_token_pair(body["data"])


class _PasskeyClient:
    """WebAuthn passkey sub-client.

    Splits responsibilities by who is authenticated:

    * sign-in calls (``sign_in_begin``, ``sign_in_complete``) take no
      bearer — the user is anonymous; passkey *is* the proof.
    * registration and management calls (``register_begin``,
      ``register_complete``, ``list``, ``delete``) require an access
      token — the user is enrolling on their existing account.

    Attributes:
        _http: Shared transport.
    """

    def __init__(self, http: HttpTransport) -> None:
        """Initialize with the shared transport.

        Args:
            http: Transport from the parent client.
        """
        self._http = http

    def sign_in_begin(self) -> PasskeyChallenge:
        """Get discoverable-credential authentication options.

        Returns:
            A :class:`PasskeyChallenge` to hand to
            ``navigator.credentials.get()``.
        """
        body = self._http.request("POST", "/v1/auth/passkey/sign-in/begin")
        data = body["data"]
        return PasskeyChallenge(options=data["options"], state=data["state"])

    def sign_in_complete(self, *, credential: dict[str, Any], state: str) -> TokenPair:
        """Verify the assertion and mint a session.

        Args:
            credential: The ``PublicKeyCredential`` JSON the browser
                produced.
            state: State JWT from :func:`sign_in_begin`.

        Returns:
            The minted :class:`TokenPair`.

        Raises:
            KnucklesAPIError: ``PASSKEY_AUTH_FAILED`` on any failure.
        """
        body = self._http.request(
            "POST",
            "/v1/auth/passkey/sign-in/complete",
            json={"credential": credential, "state": state},
        )
        return _parse_token_pair(body["data"])

    def register_begin(self, *, access_token: str) -> PasskeyChallenge:
        """Get registration options for the signed-in user.

        Args:
            access_token: Bearer access token of the user enrolling
                a passkey.

        Returns:
            A :class:`PasskeyChallenge` to hand to
            ``navigator.credentials.create()``.
        """
        body = self._http.request(
            "POST", "/v1/auth/passkey/register/begin", bearer=access_token
        )
        data = body["data"]
        return PasskeyChallenge(options=data["options"], state=data["state"])

    def register_complete(
        self,
        *,
        access_token: str,
        credential: dict[str, Any],
        state: str,
        name: str | None = None,
    ) -> str:
        """Verify an attestation and persist the credential.

        Args:
            access_token: Bearer access token of the signed-in user.
            credential: The ``PublicKeyCredential`` JSON from the
                browser.
            state: State JWT from :func:`register_begin`.
            name: Optional human-facing label.

        Returns:
            The persisted credential id (base64url).
        """
        payload: dict[str, Any] = {"credential": credential, "state": state}
        if name is not None:
            payload["name"] = name
        body = self._http.request(
            "POST",
            "/v1/auth/passkey/register/complete",
            json=payload,
            bearer=access_token,
        )
        credential_id = body["data"]["credential_id"]
        assert isinstance(credential_id, str)
        return credential_id

    def list(self, *, access_token: str) -> list[PasskeyDescriptor]:
        """Return the user's registered passkeys.

        Args:
            access_token: Bearer access token of the signed-in user.

        Returns:
            A possibly-empty list of :class:`PasskeyDescriptor`.
        """
        body = self._http.request("GET", "/v1/auth/passkey", bearer=access_token)
        return [
            PasskeyDescriptor(
                credential_id=item["credential_id"],
                name=item.get("name"),
                transports=item.get("transports"),
                created_at=datetime.fromisoformat(item["created_at"]),
                last_used_at=(
                    datetime.fromisoformat(item["last_used_at"])
                    if item.get("last_used_at")
                    else None
                ),
            )
            for item in body["data"]
        ]

    def delete(self, *, access_token: str, credential_id: str) -> None:
        """Delete one of the user's passkeys.

        Args:
            access_token: Bearer access token of the signed-in user.
            credential_id: WebAuthn credential id to delete.

        Raises:
            KnucklesAPIError: ``PASSKEY_AUTH_FAILED`` if no matching
                credential is registered to this user.
        """
        self._http.request(
            "DELETE",
            f"/v1/auth/passkey/{credential_id}",
            bearer=access_token,
            expect_json=False,
        )


class _MeClient:
    """Profile + account-management sub-client.

    Callable for backwards compatibility: ``client.me(access_token=...)``
    behaves exactly like the pre-0.1.2 ``me()`` method and returns a
    :class:`UserProfile`. The newer account-management endpoints hang
    off attributes (``client.me.update_profile(...)`` etc.) and return
    the server's ``data`` payload as plain dicts.

    Attributes:
        _http: Shared transport.
    """

    def __init__(self, http: HttpTransport) -> None:
        """Initialize with the shared transport.

        Args:
            http: Transport from the parent client.
        """
        self._http = http

    def __call__(self, *, access_token: str) -> UserProfile:
        """Return the signed-in user's profile.

        Args:
            access_token: Bearer access token of the signed-in user.

        Returns:
            A :class:`UserProfile`.
        """
        body = self._http.request("GET", "/v1/me", bearer=access_token)
        data = body["data"]
        return UserProfile(
            id=data["id"],
            email=data["email"],
            display_name=data.get("display_name"),
            avatar_url=data.get("avatar_url"),
            app_client_id=data["app_client_id"],
        )

    def update_profile(
        self,
        *,
        access_token: str,
        display_name: str | None | _Unset = _UNSET,
        avatar_url: str | None | _Unset = _UNSET,
    ) -> dict[str, Any]:
        """Partially update the signed-in user's profile.

        Only the fields you pass are sent. An omitted field is left
        untouched server-side; an explicit ``None`` clears it.

        Args:
            access_token: Bearer access token of the signed-in user.
            display_name: New display name, or ``None`` to clear it.
                Omit to leave unchanged.
            avatar_url: New avatar URL, or ``None`` to clear it. Omit
                to leave unchanged.

        Returns:
            The updated profile dict from the response ``data``.
        """
        payload: dict[str, Any] = {}
        if not isinstance(display_name, _Unset):
            payload["display_name"] = display_name
        if not isinstance(avatar_url, _Unset):
            payload["avatar_url"] = avatar_url
        body = self._http.request("PATCH", "/v1/me", json=payload, bearer=access_token)
        data = body["data"]
        assert isinstance(data, dict)
        return data

    def delete_account(self, *, access_token: str) -> None:
        """Permanently delete the signed-in user's account.

        Args:
            access_token: Bearer access token of the signed-in user.
        """
        self._http.request("DELETE", "/v1/me", bearer=access_token, expect_json=False)

    def list_providers(self, *, access_token: str) -> list[dict[str, Any]]:
        """List the OAuth providers linked to the signed-in user.

        Args:
            access_token: Bearer access token of the signed-in user.

        Returns:
            A possibly-empty list of dicts, each carrying ``provider``,
            ``created_at``, and ``scopes``.
        """
        body = self._http.request("GET", "/v1/me/providers", bearer=access_token)
        data = body["data"]
        assert isinstance(data, list)
        return data

    def unlink_provider(self, *, access_token: str, provider: str) -> None:
        """Unlink one OAuth provider from the signed-in user.

        Args:
            access_token: Bearer access token of the signed-in user.
            provider: Provider name to unlink (``"google"`` or
                ``"apple"``).
        """
        self._http.request(
            "DELETE",
            f"/v1/me/providers/{provider}",
            bearer=access_token,
            expect_json=False,
        )

    def start_email_change(
        self,
        *,
        access_token: str,
        new_email: str,
        redirect_url: str,
    ) -> None:
        """Start an email-change ceremony for the signed-in user.

        Knuckles emails a confirmation link to ``new_email``; the
        change only applies once :func:`verify_email_change` redeems
        the token from that link.

        Args:
            access_token: Bearer access token of the signed-in user.
            new_email: The address to change to.
            redirect_url: Verify endpoint on the consuming app. Must
                lie under one of the app-client's ``allowed_origins``.
        """
        self._http.request(
            "POST",
            "/v1/me/email/start",
            json={"new_email": new_email, "redirect_url": redirect_url},
            bearer=access_token,
            expect_json=False,
        )

    def verify_email_change(self, token: str) -> dict[str, Any]:
        """Redeem an email-change token and apply the new address.

        Client-headers-only call — no bearer needed; the token itself
        proves the ceremony.

        Args:
            token: The raw token from the confirmation email's
                ``token=`` param.

        Returns:
            The response ``data`` dict carrying the new ``email``.
        """
        body = self._http.request("POST", "/v1/me/email/verify", json={"token": token})
        data = body["data"]
        assert isinstance(data, dict)
        return data


class _SessionsClient:
    """Refresh-session listing + revocation sub-client.

    Attributes:
        _http: Shared transport.
    """

    def __init__(self, http: HttpTransport) -> None:
        """Initialize with the shared transport.

        Args:
            http: Transport from the parent client.
        """
        self._http = http

    def list(self, *, access_token: str) -> list[dict[str, Any]]:
        """List the signed-in user's active sessions.

        Args:
            access_token: Bearer access token of the signed-in user.

        Returns:
            A possibly-empty list of dicts, each carrying ``id``,
            ``created_at``, and ``expires_at``.
        """
        body = self._http.request("GET", "/v1/sessions", bearer=access_token)
        data = body["data"]
        assert isinstance(data, list)
        return data

    def revoke(self, *, access_token: str, session_id: str) -> None:
        """Revoke one of the signed-in user's sessions.

        Args:
            access_token: Bearer access token of the signed-in user.
            session_id: The session id to revoke (from :func:`list`).
        """
        self._http.request(
            "DELETE",
            f"/v1/sessions/{session_id}",
            bearer=access_token,
            expect_json=False,
        )


class _AdminClient:
    """Operator-only app-client management sub-client.

    Active only when the parent :class:`KnucklesClient` was constructed
    with ``admin_token=...``. Admin routes authenticate with the
    ``X-Admin-Token`` header alone — the app-client headers are not
    sent. Every method returns the server's ``data`` payload verbatim.

    Attributes:
        _http: Shared transport.
        _admin_token: The operator admin token, or ``None`` when the
            admin API is not configured.
    """

    def __init__(self, http: HttpTransport, *, admin_token: str | None) -> None:
        """Initialize with the shared transport and optional token.

        Args:
            http: Transport from the parent client.
            admin_token: Operator admin token, or ``None`` to leave the
                admin API inactive.
        """
        self._http = http
        self._admin_token = admin_token

    def _request(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Issue one admin call with ``X-Admin-Token`` auth.

        Args:
            method: HTTP verb.
            path: Path under the base URL, leading slash included.
            json: Optional JSON body.

        Returns:
            The parsed JSON body.

        Raises:
            RuntimeError: If the parent client was constructed without
                ``admin_token``.
        """
        if self._admin_token is None:
            raise RuntimeError(
                "Admin API is not configured: construct KnucklesClient with "
                "admin_token=... to use client.admin."
            )
        return self._http.request(
            method,
            path,
            json=json,
            send_client_headers=False,
            extra_headers={"X-Admin-Token": self._admin_token},
        )

    def create_app_client(
        self,
        *,
        client_id: str,
        app_name: str,
        allowed_origins: list[str] | None = None,
    ) -> dict[str, Any]:
        """Register a new app-client (tenant).

        Args:
            client_id: The new tenant's ``client_id``.
            app_name: Human-facing application name.
            allowed_origins: Optional list of origins permitted in
                ceremony ``redirect_url`` values.

        Returns:
            The created app-client dict, including the one-time
            plaintext ``client_secret`` — store it now; it is never
            shown again.
        """
        payload: dict[str, Any] = {"client_id": client_id, "app_name": app_name}
        if allowed_origins is not None:
            payload["allowed_origins"] = allowed_origins
        body = self._request("POST", "/v1/admin/app-clients", json=payload)
        data = body["data"]
        assert isinstance(data, dict)
        return data

    def list_app_clients(self) -> list[dict[str, Any]]:
        """List every registered app-client.

        Returns:
            A possibly-empty list of app-client dicts (no secrets).
        """
        body = self._request("GET", "/v1/admin/app-clients")
        data = body["data"]
        assert isinstance(data, list)
        return data

    def get_app_client(self, client_id: str) -> dict[str, Any]:
        """Fetch one app-client by id.

        Args:
            client_id: The tenant's ``client_id``.

        Returns:
            The app-client dict (no secrets).
        """
        body = self._request("GET", f"/v1/admin/app-clients/{client_id}")
        data = body["data"]
        assert isinstance(data, dict)
        return data

    def update_app_client(self, client_id: str, **fields: Any) -> dict[str, Any]:
        """Partially update an app-client's configuration.

        Args:
            client_id: The tenant's ``client_id``.
            **fields: Column/value pairs passed through verbatim as the
                PATCH body (e.g. ``app_name=...``,
                ``resend_from_email=...``).

        Returns:
            The updated app-client dict.
        """
        body = self._request(
            "PATCH", f"/v1/admin/app-clients/{client_id}", json=dict(fields)
        )
        data = body["data"]
        assert isinstance(data, dict)
        return data

    def rotate_secret(self, client_id: str) -> dict[str, Any]:
        """Rotate an app-client's secret.

        Args:
            client_id: The tenant's ``client_id``.

        Returns:
            A dict including the new one-time plaintext
            ``client_secret`` — store it now; it is never shown again.
        """
        body = self._request("POST", f"/v1/admin/app-clients/{client_id}/rotate-secret")
        data = body["data"]
        assert isinstance(data, dict)
        return data

    def set_origins(self, client_id: str, allowed_origins: list[str]) -> dict[str, Any]:
        """Replace an app-client's allowed origins.

        Args:
            client_id: The tenant's ``client_id``.
            allowed_origins: The complete new list of origins permitted
                in ceremony ``redirect_url`` values.

        Returns:
            The updated app-client dict.
        """
        body = self._request(
            "PUT",
            f"/v1/admin/app-clients/{client_id}/origins",
            json={"allowed_origins": allowed_origins},
        )
        data = body["data"]
        assert isinstance(data, dict)
        return data


class KnucklesClient:
    """Top-level Knuckles SDK client.

    Construct one per process and share it. The transport is thread-
    safe via :class:`requests.Session`'s connection pool, and the
    JWKS verifier caches keys in-memory for the process lifetime.

    Attributes:
        magic_link: Magic-link sub-client.
        google: Google OAuth sub-client.
        apple: Apple OAuth sub-client.
        passkey: WebAuthn passkey sub-client.
        me: Profile + account-management sub-client. Callable —
            ``client.me(access_token=...)`` returns the
            :class:`UserProfile` exactly as before.
        sessions: Session listing + revocation sub-client.
        admin: Operator app-client management sub-client. Raises
            :class:`RuntimeError` from every method unless the client
            was constructed with ``admin_token=...``.
    """

    def __init__(
        self,
        *,
        base_url: str,
        client_id: str,
        client_secret: str,
        timeout: float = 10,
        session: requests.Session | None = None,
        jwks_headers: dict[str, str] | None = None,
        admin_token: str | None = None,
    ) -> None:
        """Initialize the client.

        Args:
            base_url: Knuckles base URL (e.g.
                ``https://auth.example.com``). Used as the JWT ``iss``
                claim and as the JWKS host.
            client_id: This consuming app's ``client_id``.
            client_secret: This consuming app's ``client_secret``.
            timeout: Per-request timeout in seconds.
            session: Optional pre-built :class:`requests.Session`.
            jwks_headers: Optional HTTP headers for the JWKS fetch.
                When no ``User-Agent`` is supplied the SDK defaults it
                to ``knuckles-client-py/<version>`` (urllib's stock
                User-Agent is blocked by common WAF rules).
            admin_token: Optional operator admin token. When set,
                ``client.admin`` methods authenticate via
                ``X-Admin-Token``.
        """
        self._http = HttpTransport(
            base_url=base_url,
            client_id=client_id,
            client_secret=client_secret,
            timeout=timeout,
            session=session,
        )
        self._verifier = JwksVerifier(
            jwks_uri=f"{self._http.base_url}/.well-known/jwks.json",
            issuer=self._http.base_url,
            audience=client_id,
            headers=jwks_headers,
        )
        self.magic_link = _MagicLinkClient(self._http)
        self.google = _GoogleClient(self._http)
        self.apple = _AppleClient(self._http)
        self.passkey = _PasskeyClient(self._http)
        self.me = _MeClient(self._http)
        self.sessions = _SessionsClient(self._http)
        self.admin = _AdminClient(self._http, admin_token=admin_token)

    def verify_access_token(self, token: str) -> dict[str, Any]:
        """Validate a Knuckles access token locally via the cached JWKS.

        No network call after the first token verification on a fresh
        process.

        Args:
            token: The bearer access token.

        Returns:
            The decoded claims dict.

        Raises:
            KnucklesTokenExpiredError: The token is valid except its
                ``exp`` is in the past (raised ``from`` the underlying
                :class:`jwt.ExpiredSignatureError`).
            KnucklesTokenError: For any other signature/audience/issuer
                failure.
        """
        return self._verifier.verify(token)

    def refresh(self, refresh_token: str) -> TokenPair:
        """Rotate a refresh token into a new access + refresh pair.

        Args:
            refresh_token: The refresh-token plaintext stored from a
                previous ceremony or refresh.

        Returns:
            The new :class:`TokenPair`. **Always store the new
            refresh token** — the presented one is now consumed.

        Raises:
            KnucklesAuthError: ``REFRESH_TOKEN_INVALID`` (unknown),
                ``REFRESH_TOKEN_EXPIRED``, ``REFRESH_TOKEN_REUSED``
                (catastrophic — every refresh for this user has been
                revoked, force re-authentication), or ``INVALID_CLIENT``
                (token issued for another app-client).
        """
        body = self._http.request(
            "POST",
            "/v1/token/refresh",
            json={"refresh_token": refresh_token},
        )
        return _parse_token_pair(body["data"])

    def logout(self, refresh_token: str) -> None:
        """Revoke a single refresh token.

        Idempotent: unknown or already-used tokens succeed silently.

        Args:
            refresh_token: The refresh-token plaintext to revoke.
        """
        self._http.request(
            "POST",
            "/v1/logout",
            json={"refresh_token": refresh_token},
            expect_json=False,
        )

    def logout_all(self, *, access_token: str) -> int:
        """Revoke every active refresh token for the signed-in user.

        Args:
            access_token: Bearer access token of the user whose
                sessions should be revoked.

        Returns:
            The count of revoked refresh-token rows.
        """
        body = self._http.request("POST", "/v1/logout/all", bearer=access_token)
        revoked = body["data"]["revoked"]
        assert isinstance(revoked, int)
        return revoked

    def fetch_jwks(self) -> dict[str, Any]:
        """Return Knuckles' raw JWKS document.

        Useful for debugging or for warming a custom on-disk cache.

        Returns:
            The JWKS JSON body.
        """
        return self._http.get_json("/.well-known/jwks.json")

    def fetch_openid_configuration(self) -> dict[str, Any]:
        """Return Knuckles' OIDC discovery document.

        Returns:
            The discovery JSON body.
        """
        return self._http.get_json("/.well-known/openid-configuration")

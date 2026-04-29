"""High-level Knuckles client.

The :class:`KnucklesClient` exposes one method per public Knuckles
endpoint, plus a :func:`verify_access_token` shortcut that uses a
JWKS-cached verifier so consuming apps validate tokens locally.

Sub-clients group related ceremonies:

* ``client.magic_link`` — email magic-link flow.
* ``client.google`` — Google Sign-In.
* ``client.apple`` — Sign in with Apple.
* ``client.passkey`` — WebAuthn registration + sign-in + management.

Every method returns a typed dataclass from :mod:`models` and raises
a typed exception from :mod:`exceptions` on failure.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

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
    """

    def __init__(
        self,
        *,
        base_url: str,
        client_id: str,
        client_secret: str,
        timeout: float = 10,
        session: requests.Session | None = None,
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
        )
        self.magic_link = _MagicLinkClient(self._http)
        self.google = _GoogleClient(self._http)
        self.apple = _AppleClient(self._http)
        self.passkey = _PasskeyClient(self._http)

    def verify_access_token(self, token: str) -> dict[str, Any]:
        """Validate a Knuckles access token locally via the cached JWKS.

        No network call after the first token verification on a fresh
        process.

        Args:
            token: The bearer access token.

        Returns:
            The decoded claims dict.

        Raises:
            KnucklesTokenError: For any signature/audience/issuer/expiry
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

    def me(self, *, access_token: str) -> UserProfile:
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

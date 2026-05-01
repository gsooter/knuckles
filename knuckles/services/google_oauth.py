"""Google OAuth 2.0 + OIDC sign-in for Knuckles.

Two service entrypoints:

* :func:`build_authorize_url` mints a state JWT that binds the consuming
  app's chosen ``redirect_uri`` and ``app_client_id`` to the ceremony,
  then returns Google's consent URL with that state embedded.
* :func:`complete` verifies the state, exchanges Google's authorization
  code for tokens, fetches the userinfo profile, upserts the
  ``users`` + ``user_oauth_providers`` rows, and mints a Knuckles
  :class:`~knuckles.services.tokens.TokenPair` for the calling app.

Network calls funnel through :func:`_post_token` and :func:`_get_profile`
so tests can monkeypatch a single seam per direction without touching
:mod:`requests` globals.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlencode

import requests
from sqlalchemy.orm import Session

from knuckles.core.config import get_settings
from knuckles.core.exceptions import GOOGLE_AUTH_FAILED, AppError
from knuckles.core.logging import get_logger
from knuckles.core.observability import log_and_raise
from knuckles.core.state_jwt import issue_state, verify_state
from knuckles.data.models import OAuthProvider
from knuckles.services import tokens
from knuckles.services._oauth_upsert import upsert_oauth_user

_logger = get_logger("services.google_oauth")

_AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/v2/auth"
_TOKEN_URL = "https://oauth2.googleapis.com/token"
_USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo"
_SCOPES = "openid email profile"
_STATE_PURPOSE = "google_oauth"
_STATE_TTL_SECONDS = 10 * 60
_HTTP_TIMEOUT_SECONDS = 10


@dataclass(frozen=True)
class GoogleAuthorizeStart:
    """Return value from :func:`build_authorize_url`.

    Attributes:
        authorize_url: The fully-qualified Google consent URL the
            browser must navigate to.
        state: The signed state JWT the frontend must echo back on the
            redirect callback.
    """

    authorize_url: str
    state: str


def build_authorize_url(
    *,
    redirect_uri: str,
    app_client_id: str,
) -> GoogleAuthorizeStart:
    """Mint a state JWT and assemble the Google consent URL.

    Args:
        redirect_uri: Where Google should send the browser after the
            consent screen. Must be pre-registered in the Google Cloud
            Console for the configured Knuckles client.
        app_client_id: The ``app_clients.client_id`` initiating the
            flow. Embedded in state so :func:`complete` can verify the
            same app is finishing the ceremony.

    Returns:
        A :class:`GoogleAuthorizeStart` carrying the consent URL and
        the state JWT.
    """
    settings = get_settings()
    state = issue_state(
        purpose=_STATE_PURPOSE,
        payload={
            "redirect_uri": redirect_uri,
            "app_client_id": app_client_id,
        },
        ttl_seconds=_STATE_TTL_SECONDS,
    )
    params = {
        "client_id": settings.google_oauth_client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": _SCOPES,
        "state": state,
        "access_type": "offline",
        "prompt": "consent",
    }
    return GoogleAuthorizeStart(
        authorize_url=f"{_AUTHORIZE_URL}?{urlencode(params)}",
        state=state,
    )


def complete(
    session: Session,
    *,
    code: str,
    state: str,
    app_client_id: str,
    scopes: list[str] | None = None,
) -> tokens.TokenPair:
    """Finish the Google OAuth flow and mint a Knuckles session.

    Args:
        session: Active SQLAlchemy session.
        code: Authorization code from Google's redirect query string.
        state: State JWT minted by :func:`build_authorize_url` and
            echoed back by Google.
        app_client_id: ``app_clients.client_id`` of the caller. Must
            match the ``app_client_id`` baked into ``state``.
        scopes: Optional Knuckles access-token scopes to embed.

    Returns:
        A :class:`~knuckles.services.tokens.TokenPair` for the user.

    Raises:
        AppError: With code ``GOOGLE_AUTH_FAILED`` for a forged or
            expired state, an app-client mismatch, an unverified email,
            a missing email/sub claim, or any failure exchanging the
            code or fetching the profile.
    """
    claims = _verify_state(state, app_client_id=app_client_id)
    redirect_uri = claims["redirect_uri"]

    google_tokens = _post_token(code, redirect_uri)
    access_token = google_tokens.get("access_token")
    if not isinstance(access_token, str) or not access_token:
        raise AppError(
            code=GOOGLE_AUTH_FAILED,
            message="Google did not return an access token.",
            status_code=400,
        )

    profile = _get_profile(access_token)
    if not profile.get("email_verified"):
        raise AppError(
            code=GOOGLE_AUTH_FAILED,
            message="Google reported this email as unverified.",
            status_code=400,
        )

    sub = profile.get("sub")
    email_raw = profile.get("email")
    if not isinstance(sub, str) or not sub:
        raise AppError(
            code=GOOGLE_AUTH_FAILED,
            message="Google did not return a stable user id.",
            status_code=400,
        )
    if not isinstance(email_raw, str) or not email_raw:
        raise AppError(
            code=GOOGLE_AUTH_FAILED,
            message="Google did not return an email address.",
            status_code=400,
        )

    expires_at: datetime | None = None
    expires_in = google_tokens.get("expires_in")
    if isinstance(expires_in, int):
        expires_at = datetime.now(tz=UTC) + timedelta(seconds=expires_in)

    user = upsert_oauth_user(
        session,
        provider=OAuthProvider.GOOGLE,
        provider_user_id=sub,
        email=email_raw.lower(),
        display_name=profile.get("name"),
        avatar_url=profile.get("picture"),
        access_token=access_token,
        refresh_token=google_tokens.get("refresh_token"),
        token_expires_at=expires_at,
        scopes=_SCOPES,
        raw_profile=profile,
        fail_code=GOOGLE_AUTH_FAILED,
    )

    return tokens.issue_session(
        session,
        user_id=user.id,
        app_client_id=app_client_id,
        scopes=scopes,
        email=user.email,
    )


def _verify_state(state: str, *, app_client_id: str) -> dict[str, Any]:
    """Decode and validate a Google-OAuth state JWT.

    Args:
        state: State token echoed back by Google.
        app_client_id: ``app_clients.client_id`` of the caller. Must
            match the ``app_client_id`` baked into the state payload.

    Returns:
        The decoded state claims dictionary.

    Raises:
        AppError: With code ``GOOGLE_AUTH_FAILED`` if the state is
            forged, expired, has the wrong purpose, or was minted for
            a different app-client.
    """
    try:
        claims = verify_state(state, purpose=_STATE_PURPOSE)
    except ValueError as exc:
        raise AppError(
            code=GOOGLE_AUTH_FAILED,
            message="Google OAuth state is invalid or expired.",
            status_code=400,
        ) from exc
    if claims.get("app_client_id") != app_client_id:
        raise AppError(
            code=GOOGLE_AUTH_FAILED,
            message="Google OAuth state was issued for a different app.",
            status_code=400,
        )
    if not isinstance(claims.get("redirect_uri"), str):
        raise AppError(
            code=GOOGLE_AUTH_FAILED,
            message="Google OAuth state is missing a redirect URI.",
            status_code=400,
        )
    return claims


def _post_token(code: str, redirect_uri: str) -> dict[str, Any]:
    """Exchange an authorization code for Google access + refresh tokens.

    Args:
        code: Authorization code from Google's redirect.
        redirect_uri: Same value passed to :func:`build_authorize_url`.

    Returns:
        Token JSON body returned by Google.

    Raises:
        AppError: With code ``GOOGLE_AUTH_FAILED`` on any non-200
            response or network failure.
    """
    settings = get_settings()
    try:
        response = requests.post(
            _TOKEN_URL,
            data={
                "code": code,
                "client_id": settings.google_oauth_client_id,
                "client_secret": settings.google_oauth_client_secret,
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code",
            },
            timeout=_HTTP_TIMEOUT_SECONDS,
        )
    except requests.RequestException as exc:  # pragma: no cover — network path
        log_and_raise(
            AppError(
                code=GOOGLE_AUTH_FAILED,
                message=f"Could not reach Google to exchange the code: {exc}",
                status_code=502,
            ),
            logger=_logger,
            detail="network_failure",
            redirect_uri=redirect_uri,
        )
    if response.status_code != 200:
        # Google's token endpoint surfaces a useful machine-readable
        # ``error`` plus a free-form ``error_description``. Pass them
        # through to the caller so a stale/already-redeemed code says
        # so instead of just "Google rejected".
        google_error, google_desc = _parse_oauth_error(response)
        log_and_raise(
            AppError(
                code=GOOGLE_AUTH_FAILED,
                message=(
                    f"Google rejected the authorization code: "
                    f"{google_error or 'unknown'}"
                    + (f" — {google_desc}" if google_desc else "")
                ),
                status_code=400,
            ),
            logger=_logger,
            detail=google_error or "unknown",
            google_status=response.status_code,
            google_description=google_desc,
            redirect_uri=redirect_uri,
        )
    return dict(response.json())


def _parse_oauth_error(response: requests.Response) -> tuple[str | None, str | None]:
    """Pull ``error`` and ``error_description`` from a Google error body.

    Google's OAuth 2.0 endpoints return JSON of the form
    ``{"error": "invalid_grant", "error_description": "Code was already
    redeemed."}`` on failure. We parse defensively because an upstream
    proxy or LB can intercept and return non-JSON.

    Args:
        response: The :class:`requests.Response` from Google.

    Returns:
        Tuple of ``(error, error_description)``. Either may be
        ``None`` if the body was not parseable JSON or did not carry
        the expected fields.
    """
    try:
        body = response.json()
    except ValueError:
        return None, None
    if not isinstance(body, dict):
        return None, None
    err = body.get("error")
    desc = body.get("error_description")
    return (
        err if isinstance(err, str) else None,
        desc if isinstance(desc, str) else None,
    )


def _get_profile(access_token: str) -> dict[str, Any]:
    """Fetch the Google userinfo payload for an access token.

    Args:
        access_token: Google OAuth access token.

    Returns:
        Userinfo JSON body returned by Google.

    Raises:
        AppError: With code ``GOOGLE_AUTH_FAILED`` on any non-200
            response or network failure.
    """
    try:
        response = requests.get(
            _USERINFO_URL,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=_HTTP_TIMEOUT_SECONDS,
        )
    except requests.RequestException as exc:  # pragma: no cover — network path
        log_and_raise(
            AppError(
                code=GOOGLE_AUTH_FAILED,
                message=f"Could not reach Google to load the profile: {exc}",
                status_code=502,
            ),
            logger=_logger,
            detail="network_failure",
        )
    if response.status_code != 200:
        google_error, google_desc = _parse_oauth_error(response)
        log_and_raise(
            AppError(
                code=GOOGLE_AUTH_FAILED,
                message=(
                    f"Could not load Google profile: "
                    f"HTTP {response.status_code}"
                    + (f" ({google_error})" if google_error else "")
                    + (f" — {google_desc}" if google_desc else "")
                ),
                status_code=400,
            ),
            logger=_logger,
            detail=google_error or f"http_{response.status_code}",
            google_status=response.status_code,
        )
    return dict(response.json())

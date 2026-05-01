"""Sign-in with Apple for Knuckles.

Mirror of :mod:`knuckles.services.google_oauth` with the Apple-specific
quirks Knuckles must handle on top of the standard OAuth+OIDC code flow:

* The ``client_secret`` is a short-lived ES256 JWT signed with the
  team's ``.p8`` private key (rotated server-side every call). See
  :func:`_mint_client_secret`.
* User identity is read from the ``id_token`` returned by
  ``/auth/token``; there is no userinfo endpoint. The id_token is
  verified against Apple's JWKS (see :func:`_verify_id_token`).
* Apple posts ``email_verified`` and ``is_private_email`` as STRINGS
  (``"true"`` / ``"false"``), not booleans, so they're coerced before
  comparison.
* The user's display name only arrives in the ``user`` payload Apple
  POSTs on the *first* sign-in. Subsequent sign-ins yield no name —
  callers must persist it on the first round trip.

Three monkeypatchable seams (:func:`_mint_client_secret`,
:func:`_post_token`, :func:`_verify_id_token`) keep tests hermetic
without touching :mod:`requests` or :mod:`jwt` globals.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlencode

import jwt
import requests
from sqlalchemy.orm import Session

from knuckles.core.config import get_settings
from knuckles.core.exceptions import APPLE_AUTH_FAILED, AppError
from knuckles.core.logging import get_logger
from knuckles.core.observability import log_and_raise
from knuckles.core.state_jwt import issue_state, verify_state
from knuckles.data.models import OAuthProvider
from knuckles.services import tokens
from knuckles.services._oauth_upsert import upsert_oauth_user

_logger = get_logger("services.apple_oauth")

_AUTHORIZE_URL = "https://appleid.apple.com/auth/authorize"
_TOKEN_URL = "https://appleid.apple.com/auth/token"
_JWKS_URL = "https://appleid.apple.com/auth/keys"
_ISSUER = "https://appleid.apple.com"
_SCOPES = "name email"
_STATE_PURPOSE = "apple_oauth"
_STATE_TTL_SECONDS = 10 * 60
_HTTP_TIMEOUT_SECONDS = 10
_CLIENT_SECRET_TTL_SECONDS = 180 * 24 * 60 * 60  # Apple caps at 6 months.


@dataclass(frozen=True)
class AppleAuthorizeStart:
    """Return value from :func:`build_authorize_url`.

    Attributes:
        authorize_url: Apple consent URL the browser must navigate to.
        state: Signed state JWT the frontend echoes back on callback.
    """

    authorize_url: str
    state: str


def build_authorize_url(
    *,
    redirect_uri: str,
    app_client_id: str,
) -> AppleAuthorizeStart:
    """Mint a state JWT and assemble the Apple consent URL.

    Args:
        redirect_uri: Callback URL Apple should POST back to. Must be
            pre-registered with the Apple Services ID for the
            configured Knuckles client.
        app_client_id: ``app_clients.client_id`` initiating the flow.
            Bound to the state JWT and re-checked on completion.

    Returns:
        An :class:`AppleAuthorizeStart` carrying the consent URL and
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
        "client_id": settings.apple_oauth_client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "response_mode": "form_post",
        "scope": _SCOPES,
        "state": state,
    }
    return AppleAuthorizeStart(
        authorize_url=f"{_AUTHORIZE_URL}?{urlencode(params)}",
        state=state,
    )


def complete(
    session: Session,
    *,
    code: str,
    state: str,
    app_client_id: str,
    user_data: dict[str, Any] | None = None,
    scopes: list[str] | None = None,
) -> tokens.TokenPair:
    """Finish the Apple OAuth flow and mint a Knuckles session.

    Args:
        session: Active SQLAlchemy session.
        code: Authorization code Apple POSTed back.
        state: State JWT minted by :func:`build_authorize_url`.
        app_client_id: Calling ``app_clients.client_id``. Must match
            the ``app_client_id`` baked into ``state``.
        user_data: Optional Apple ``user`` payload (only present on
            the first sign-in for an Apple ID). Used to extract a
            display name when the id_token has none.
        scopes: Optional Knuckles access-token scopes to embed.

    Returns:
        A :class:`~knuckles.services.tokens.TokenPair` for the user.

    Raises:
        AppError: With code ``APPLE_AUTH_FAILED`` for state issues,
            client-secret mint failure, token-exchange failure,
            id_token verification failure, missing email/sub, or an
            unverified non-relay email.
    """
    claims = _verify_state(state, app_client_id=app_client_id)
    redirect_uri = claims["redirect_uri"]

    client_secret = _mint_client_secret()
    apple_tokens = _post_token(code, redirect_uri, client_secret)

    id_token = apple_tokens.get("id_token")
    if not isinstance(id_token, str) or not id_token:
        raise AppError(
            code=APPLE_AUTH_FAILED,
            message="Apple did not return an id token.",
            status_code=400,
        )

    profile = _verify_id_token(id_token)

    email_verified = str(profile.get("email_verified", "")).lower() == "true"
    is_private_email = str(profile.get("is_private_email", "")).lower() == "true"
    if not email_verified and not is_private_email:
        raise AppError(
            code=APPLE_AUTH_FAILED,
            message="Apple reported this email as unverified.",
            status_code=400,
        )

    sub = profile.get("sub")
    email_raw = profile.get("email")
    if not isinstance(sub, str) or not sub:
        raise AppError(
            code=APPLE_AUTH_FAILED,
            message="Apple did not return a stable user id.",
            status_code=400,
        )
    if not isinstance(email_raw, str) or not email_raw:
        raise AppError(
            code=APPLE_AUTH_FAILED,
            message="Apple did not return an email address.",
            status_code=400,
        )

    expires_at: datetime | None = None
    expires_in = apple_tokens.get("expires_in")
    if isinstance(expires_in, int):
        expires_at = datetime.now(tz=UTC) + timedelta(seconds=expires_in)

    user = upsert_oauth_user(
        session,
        provider=OAuthProvider.APPLE,
        provider_user_id=sub,
        email=email_raw.lower(),
        display_name=_display_name(user_data),
        avatar_url=None,
        access_token=str(apple_tokens.get("access_token") or ""),
        refresh_token=apple_tokens.get("refresh_token"),
        token_expires_at=expires_at,
        scopes=_SCOPES,
        raw_profile=profile,
        fail_code=APPLE_AUTH_FAILED,
    )

    return tokens.issue_session(
        session,
        user_id=user.id,
        app_client_id=app_client_id,
        scopes=scopes,
        email=user.email,
    )


def _verify_state(state: str, *, app_client_id: str) -> dict[str, Any]:
    """Decode and validate an Apple-OAuth state JWT.

    Args:
        state: State token Apple echoed back.
        app_client_id: ``app_clients.client_id`` of the caller.

    Returns:
        Decoded state claims.

    Raises:
        AppError: With code ``APPLE_AUTH_FAILED`` on any signature,
            purpose, or app-client mismatch.
    """
    try:
        claims = verify_state(state, purpose=_STATE_PURPOSE)
    except ValueError as exc:
        raise AppError(
            code=APPLE_AUTH_FAILED,
            message="Apple OAuth state is invalid or expired.",
            status_code=400,
        ) from exc
    if claims.get("app_client_id") != app_client_id:
        raise AppError(
            code=APPLE_AUTH_FAILED,
            message="Apple OAuth state was issued for a different app.",
            status_code=400,
        )
    if not isinstance(claims.get("redirect_uri"), str):
        raise AppError(
            code=APPLE_AUTH_FAILED,
            message="Apple OAuth state is missing a redirect URI.",
            status_code=400,
        )
    return claims


def _display_name(user_data: dict[str, Any] | None) -> str | None:
    """Pull a display name from Apple's first-sign-in ``user`` payload.

    Args:
        user_data: Parsed Apple ``user`` form field or ``None``.

    Returns:
        Joined first/last name, or ``None`` if nothing usable was
        present.
    """
    if not isinstance(user_data, dict):
        return None
    name = user_data.get("name")
    if not isinstance(name, dict):
        return None
    parts = [
        str(name.get("firstName") or "").strip(),
        str(name.get("lastName") or "").strip(),
    ]
    joined = " ".join(p for p in parts if p)
    return joined or None


def _mint_client_secret() -> str:
    """Sign a short-lived ES256 client_secret JWT for Apple's token endpoint.

    Apple uses a rotating client secret signed with the team's
    private key (``.p8``). This helper signs the JWT with the
    configured ``apple_oauth_private_key`` so the caller can pass the
    result as the ``client_secret`` POST field.

    Returns:
        A signed JWT suitable as ``client_secret``.

    Raises:
        AppError: With code ``APPLE_AUTH_FAILED`` if the key material
            is missing or malformed.
    """
    settings = get_settings()
    now = datetime.now(tz=UTC)
    claims = {
        "iss": settings.apple_oauth_team_id,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=_CLIENT_SECRET_TTL_SECONDS)).timestamp()),
        "aud": _ISSUER,
        "sub": settings.apple_oauth_client_id,
    }
    headers = {"kid": settings.apple_oauth_key_id, "alg": "ES256"}
    try:
        return jwt.encode(
            claims,
            settings.apple_oauth_private_key,
            algorithm="ES256",
            headers=headers,
        )
    except Exception as exc:  # pragma: no cover — config path
        raise AppError(
            code=APPLE_AUTH_FAILED,
            message="Could not mint Apple client secret.",
            status_code=500,
        ) from exc


def _post_token(code: str, redirect_uri: str, client_secret: str) -> dict[str, Any]:
    """Exchange Apple's authorization code for tokens.

    Args:
        code: Authorization code from Apple's callback.
        redirect_uri: Same value passed to :func:`build_authorize_url`.
        client_secret: ES256 JWT from :func:`_mint_client_secret`.

    Returns:
        Token JSON body returned by Apple.

    Raises:
        AppError: With code ``APPLE_AUTH_FAILED`` on any non-200
            response or network failure.
    """
    settings = get_settings()
    try:
        response = requests.post(
            _TOKEN_URL,
            data={
                "client_id": settings.apple_oauth_client_id,
                "client_secret": client_secret,
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": redirect_uri,
            },
            timeout=_HTTP_TIMEOUT_SECONDS,
        )
    except requests.RequestException as exc:  # pragma: no cover — network path
        log_and_raise(
            AppError(
                code=APPLE_AUTH_FAILED,
                message=f"Could not reach Apple to exchange the code: {exc}",
                status_code=502,
            ),
            logger=_logger,
            detail="network_failure",
            redirect_uri=redirect_uri,
        )
    if response.status_code != 200:
        # Apple's token endpoint follows the OAuth 2.0 error envelope:
        # {"error": "invalid_grant", "error_description": "..."}.
        apple_error, apple_desc = _parse_oauth_error(response)
        log_and_raise(
            AppError(
                code=APPLE_AUTH_FAILED,
                message=(
                    f"Apple rejected the authorization code: "
                    f"{apple_error or 'unknown'}"
                    + (f" — {apple_desc}" if apple_desc else "")
                ),
                status_code=400,
            ),
            logger=_logger,
            detail=apple_error or "unknown",
            apple_status=response.status_code,
            apple_description=apple_desc,
            redirect_uri=redirect_uri,
        )
    return dict(response.json())


def _parse_oauth_error(response: requests.Response) -> tuple[str | None, str | None]:
    """Pull ``error`` and ``error_description`` from an Apple error body.

    Apple's token endpoint returns OAuth 2.0-shaped error envelopes
    on failure. Same shape as Google: ``{"error": "...",
    "error_description": "..."}``. Parse defensively because an
    upstream proxy can intercept and return non-JSON.

    Args:
        response: The :class:`requests.Response` from Apple.

    Returns:
        Tuple of ``(error, error_description)``. Either may be
        ``None`` if the body was not parseable JSON or did not
        carry the expected fields.
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


def _verify_id_token(id_token: str) -> dict[str, Any]:
    """Verify Apple's id_token signature, issuer, and audience.

    Uses :class:`jwt.PyJWKClient` to fetch and cache Apple's public
    keys from :data:`_JWKS_URL`.

    Args:
        id_token: Apple id_token string from the token-exchange response.

    Returns:
        Decoded claims dictionary.

    Raises:
        AppError: With code ``APPLE_AUTH_FAILED`` on any verification
            failure (signature, issuer, audience, or expiry).
    """
    settings = get_settings()
    try:
        jwks_client = jwt.PyJWKClient(_JWKS_URL)
        signing_key = jwks_client.get_signing_key_from_jwt(id_token)
        return dict(
            jwt.decode(
                id_token,
                signing_key.key,
                algorithms=["RS256"],
                audience=settings.apple_oauth_client_id,
                issuer=_ISSUER,
            )
        )
    except Exception as exc:  # pragma: no cover — network/crypto path
        log_and_raise(
            AppError(
                code=APPLE_AUTH_FAILED,
                message=f"Apple id token could not be verified: {exc}",
                status_code=400,
            ),
            logger=_logger,
            detail=type(exc).__name__,
        )

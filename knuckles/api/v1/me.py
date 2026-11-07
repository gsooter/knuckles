"""Self-service routes for the signed-in user under ``/v1/me``.

Six endpoints:

* ``PATCH  /v1/me`` — partial profile update (display name, avatar).
* ``DELETE /v1/me`` — permanent account deletion.
* ``GET    /v1/me/providers`` — list linked OAuth providers (safe
  fields only — provider tokens and raw profiles never leave the DB).
* ``DELETE /v1/me/providers/<provider>`` — unlink a provider.
* ``POST   /v1/me/email/start`` — begin the verified email change.
* ``POST   /v1/me/email/verify`` — complete it from the email link.

Every route except ``email/verify`` is dual-auth (client headers +
bearer) and pins the token audience to the calling client, exactly
like ``GET /v1/me``. The verify step is client-auth only because the
user arrives from an email link without a bearer in hand.

Every route is a thin adapter: it validates the request, calls a
service, and returns a shaped JSON body. No business logic runs here.
"""

from __future__ import annotations

from typing import Any

from flask import jsonify, request
from flask.wrappers import Response

from knuckles.api.v1 import api_v1
from knuckles.core import database
from knuckles.core.app_client_auth import (
    assert_redirect_allowed,
    get_current_app_client,
    require_app_client,
)
from knuckles.core.auth import (
    assert_token_audience,
    get_current_user_id,
    require_auth,
)
from knuckles.core.exceptions import RATE_LIMITED, AppError, ValidationError
from knuckles.core.rate_limit import magic_link_limiter
from knuckles.data.models import User
from knuckles.services import magic_link, users

_PROFILE_FIELDS = frozenset({"display_name", "avatar_url"})


def _require_string_field(field: str) -> str:
    """Pull a non-empty string field from the JSON body or raise.

    Args:
        field: The body key to require.

    Returns:
        The non-empty string value of ``field``.

    Raises:
        ValidationError: If the body is missing or the field is absent
            or not a non-empty string.
    """
    body = request.get_json(silent=True) or {}
    value = body.get(field)
    if not isinstance(value, str) or not value:
        raise ValidationError(f"'{field}' is required.")
    return value


def _me_payload(user: User, app_client_id: str) -> dict[str, Any]:
    """Shape a user row into the ``/v1/me`` response body.

    Args:
        user: The user row to serialize.
        app_client_id: The audience claim of the caller's token.

    Returns:
        The ``data`` dict mirroring ``GET /v1/me``.
    """
    return {
        "id": str(user.id),
        "email": user.email,
        "display_name": user.display_name,
        "avatar_url": user.avatar_url,
        "app_client_id": app_client_id,
    }


def _parse_profile_updates() -> dict[str, str | None]:
    """Validate the ``PATCH /v1/me`` body shape and extract updates.

    Returns:
        Mapping of present field name to its new value (``None``
        clears the field). Absent keys are absent from the mapping —
        the service layer's sentinel default keeps them untouched.

    Raises:
        ValidationError: If the body is not a JSON object, carries
            unknown keys, has no known keys, or a value is neither a
            string nor ``null``.
    """
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        raise ValidationError("Request body must be a JSON object.")
    unknown = set(body) - _PROFILE_FIELDS
    if unknown:
        raise ValidationError(f"Unknown fields: {', '.join(sorted(unknown))}.")
    if not body:
        raise ValidationError(
            "At least one of 'display_name' or 'avatar_url' is required."
        )
    updates: dict[str, str | None] = {}
    for field in _PROFILE_FIELDS:
        if field not in body:
            continue
        value = body[field]
        if value is not None and not isinstance(value, str):
            raise ValidationError(f"'{field}' must be a string or null.")
        updates[field] = value
    return updates


@api_v1.patch("/me")
@require_app_client
@require_auth
def patch_me_route() -> tuple[Response, int]:
    """Apply a partial profile update for the authenticated user.

    Returns:
        Tuple of JSON body (same shape as ``GET /v1/me``) and HTTP 200.

    Raises:
        ValidationError: On malformed bodies, unknown keys, missing
            keys, or values violating the length/URL constraints.
        NotFoundError: With code ``USER_NOT_FOUND`` if the token's
            subject no longer exists.
        UnauthorizedError: With code ``INVALID_TOKEN`` when the bearer
            token was minted for a different app client.
    """
    app_client = get_current_app_client()
    assert_token_audience(app_client.client_id)
    updates = _parse_profile_updates()
    session = database.get_db()
    user = users.update_profile(session, get_current_user_id(), **updates)
    return jsonify({"data": _me_payload(user, app_client.client_id)}), 200


@api_v1.delete("/me")
@require_app_client
@require_auth
def delete_me_route() -> tuple[Response, int]:
    """Permanently delete the authenticated user's account.

    Deletion is account-wide: sessions with every tenant are revoked
    and the user row is removed, so the still-valid access token maps
    to ``USER_NOT_FOUND`` on any subsequent call.

    Returns:
        Tuple of an empty JSON body and HTTP 204.

    Raises:
        NotFoundError: With code ``USER_NOT_FOUND`` if the token's
            subject no longer exists.
        UnauthorizedError: With code ``INVALID_TOKEN`` when the bearer
            token was minted for a different app client.
    """
    app_client = get_current_app_client()
    assert_token_audience(app_client.client_id)
    session = database.get_db()
    users.delete_account(
        session,
        get_current_user_id(),
        app_client_id=app_client.client_id,
    )
    return jsonify({}), 204


@api_v1.get("/me/providers")
@require_app_client
@require_auth
def list_providers_route() -> tuple[Response, int]:
    """List the authenticated user's linked OAuth providers.

    Only the provider name, link creation time, and granted scopes are
    serialized — provider access/refresh tokens, the raw profile, and
    the provider user id never leave the database.

    Returns:
        Tuple of JSON body and HTTP 200.

    Raises:
        NotFoundError: With code ``USER_NOT_FOUND`` if the token's
            subject no longer exists.
        UnauthorizedError: With code ``INVALID_TOKEN`` when the bearer
            token was minted for a different app client.
    """
    assert_token_audience(get_current_app_client().client_id)
    session = database.get_db()
    links = users.list_providers(session, get_current_user_id())
    body: dict[str, Any] = {
        "data": [
            {
                "provider": link.provider.value,
                "created_at": link.created_at.isoformat(),
                "scopes": link.scopes,
            }
            for link in links
        ]
    }
    return jsonify(body), 200


@api_v1.delete("/me/providers/<provider>")
@require_app_client
@require_auth
def delete_provider_route(provider: str) -> tuple[Response, int]:
    """Unlink an OAuth provider from the authenticated user's account.

    Args:
        provider: Provider name from the URL (``google`` or ``apple``).

    Returns:
        Tuple of an empty JSON body and HTTP 204.

    Raises:
        NotFoundError: With code ``PROVIDER_NOT_FOUND`` for unknown
            provider names or absent links, or ``USER_NOT_FOUND`` if
            the token's subject no longer exists.
        UnauthorizedError: With code ``INVALID_TOKEN`` when the bearer
            token was minted for a different app client.
    """
    assert_token_audience(get_current_app_client().client_id)
    session = database.get_db()
    users.remove_provider(session, get_current_user_id(), provider=provider)
    return jsonify({}), 204


@api_v1.post("/me/email/start")
@require_app_client
@require_auth
def email_change_start_route() -> tuple[Response, int]:
    """Begin a verified email change for the authenticated user.

    Returns:
        Tuple of an empty JSON body and HTTP 202 Accepted — identical
        regardless of whether the new address is already registered,
        so the start step leaks no account-existence signal.

    Raises:
        ValidationError: If ``new_email`` or ``redirect_url`` is
            missing, the email is malformed, or the redirect origin is
            not registered for this app-client.
        AppError: With code ``RATE_LIMITED`` (HTTP 429, Retry-After
            set) when the per-address send budget is exhausted.
        UnauthorizedError: With code ``INVALID_TOKEN`` when the bearer
            token was minted for a different app client.
    """
    app_client = get_current_app_client()
    assert_token_audience(app_client.client_id)
    new_email = _require_string_field("new_email")
    redirect_url = _require_string_field("redirect_url")
    if "@" not in new_email:
        raise ValidationError("'new_email' must be a valid email address.")
    assert_redirect_allowed(app_client, redirect_url)

    # Same per-address throttle as magic-link start: without it, valid
    # client credentials could weaponize Knuckles into an email bomb
    # against the target address.
    bucket_key = f"{app_client.client_id}:{new_email.lower()}"
    if not magic_link_limiter.allow(bucket_key):
        retry_after = magic_link_limiter.seconds_until_allowed(bucket_key)
        raise AppError(
            code=RATE_LIMITED,
            message="Too many email-change requests for this address. "
            "Try again later.",
            status_code=429,
            headers={"Retry-After": str(retry_after)},
        )

    session = database.get_db()
    magic_link.start_email_change(
        session,
        user_id=get_current_user_id(),
        new_email=new_email,
        app_client_id=app_client.client_id,
        redirect_url=redirect_url,
    )
    return jsonify({}), 202


@api_v1.post("/me/email/verify")
@require_app_client
def email_change_verify_route() -> tuple[Response, int]:
    """Complete an email change from the confirmation link.

    No bearer is required — the user arrives from an email link, and
    the one-time token (bound to the user at mint time) is the proof
    of identity.

    Returns:
        Tuple of JSON body carrying the new email and HTTP 200.

    Raises:
        ValidationError: If the request body is missing ``token``.
        AppError: Propagated from
            :func:`magic_link.verify_email_change` with code
            ``MAGIC_LINK_INVALID``, ``MAGIC_LINK_ALREADY_USED``,
            ``MAGIC_LINK_EXPIRED``, or ``EMAIL_IN_USE`` (HTTP 409).
    """
    token = _require_string_field("token")
    app_client = get_current_app_client()
    session = database.get_db()
    user = magic_link.verify_email_change(
        session,
        token=token,
        app_client_id=app_client.client_id,
    )
    return jsonify({"data": {"email": user.email}}), 200

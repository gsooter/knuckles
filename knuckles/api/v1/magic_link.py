"""Magic-link HTTP routes.

Two endpoints:

* ``POST /v1/auth/magic-link/start`` — accept an email and a redirect URL,
  mint a one-time token, persist its hash, send the link by email.
  Returns 202 Accepted with an empty body so the route works the same
  whether or not the email exists (no account-enumeration signal).
* ``POST /v1/auth/magic-link/verify`` — accept the raw token from the
  link, redeem it, and return the same access+refresh pair shape that
  :mod:`knuckles.api.v1.auth` returns from /token/refresh.

Both routes require app-client auth so Knuckles knows which app the
ceremony belongs to and (eventually) which redirect URLs to trust.
"""

from __future__ import annotations

from typing import Any

from flask import jsonify, request
from flask.wrappers import Response

from knuckles.api.v1 import api_v1
from knuckles.core import database
from knuckles.core.app_client_auth import get_current_app_client, require_app_client
from knuckles.core.exceptions import ValidationError
from knuckles.services import magic_link
from knuckles.services.email import get_default_sender


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


@api_v1.post("/auth/magic-link/start")
@require_app_client
def start_magic_link_route() -> tuple[Response, int]:
    """Mint a magic-link token and email it to the recipient.

    Returns:
        Tuple of an empty JSON body and HTTP 202 Accepted. The status
        is intentionally identical regardless of whether the email is
        already registered, to avoid leaking account existence.

    Raises:
        ValidationError: If the request body is missing ``email`` or
            ``redirect_url``.
    """
    email = _require_string_field("email")
    redirect_url = _require_string_field("redirect_url")
    app_client = get_current_app_client()
    session = database.get_db()

    magic_link.start_magic_link(
        session,
        email=email,
        app_client_id=app_client.client_id,
        redirect_url=redirect_url,
        sender=get_default_sender(),
    )
    return jsonify({}), 202


@api_v1.post("/auth/magic-link/verify")
@require_app_client
def verify_magic_link_route() -> tuple[Response, int]:
    """Redeem a magic-link token for an access+refresh pair.

    Returns:
        Tuple of JSON body and HTTP 200. The body shape mirrors
        ``/v1/token/refresh`` so consuming apps share one codepath
        for handling minted tokens.

    Raises:
        ValidationError: If the request body is missing ``token``.
        AppError: Propagated from :func:`magic_link.verify_magic_link`
            with code ``MAGIC_LINK_INVALID``, ``MAGIC_LINK_EXPIRED``,
            or ``MAGIC_LINK_ALREADY_USED``.
    """
    token = _require_string_field("token")
    app_client = get_current_app_client()
    session = database.get_db()

    pair = magic_link.verify_magic_link(
        session,
        token=token,
        app_client_id=app_client.client_id,
    )

    body: dict[str, Any] = {
        "data": {
            "access_token": pair.access_token,
            "access_token_expires_at": pair.access_token_expires_at.isoformat(),
            "refresh_token": pair.refresh_token,
            "refresh_token_expires_at": pair.refresh_token_expires_at.isoformat(),
            "token_type": "Bearer",
        }
    }
    return jsonify(body), 200

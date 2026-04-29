"""WebAuthn passkey HTTP routes.

Four endpoints — two ceremonies, two halves each:

* ``POST /v1/auth/passkey/register/begin`` — bearer-token auth.
  Returns ``PublicKeyCredentialCreationOptions`` plus a state JWT.
* ``POST /v1/auth/passkey/register/complete`` — bearer-token auth.
  Verifies the attestation and persists the credential.
* ``POST /v1/auth/passkey/sign-in/begin`` — app-client auth.
  Returns ``PublicKeyCredentialRequestOptions`` plus a state JWT.
* ``POST /v1/auth/passkey/sign-in/complete`` — app-client auth.
  Verifies the assertion and returns an access+refresh pair.

The split is deliberate: registration knows who the user is (bearer
token), sign-in does not (it's the moment we *learn* who they are).
"""

from __future__ import annotations

from typing import Any

from flask import jsonify, request
from flask.wrappers import Response

from knuckles.api.v1 import api_v1
from knuckles.core import database
from knuckles.core.app_client_auth import get_current_app_client, require_app_client
from knuckles.core.auth import get_current_user_id, require_auth
from knuckles.core.exceptions import (
    PASSKEY_AUTH_FAILED,
    NotFoundError,
    ValidationError,
)
from knuckles.data.repositories import auth as repo
from knuckles.services import passkey


def _require_dict_field(field: str) -> dict[str, Any]:
    """Pull a dict-shaped JSON body field or raise.

    Args:
        field: Body key to require.

    Returns:
        The dict value of ``field``.

    Raises:
        ValidationError: If the field is absent or not an object.
    """
    body = request.get_json(silent=True) or {}
    value = body.get(field)
    if not isinstance(value, dict):
        raise ValidationError(f"'{field}' is required and must be an object.")
    return value


def _require_string_field(field: str) -> str:
    """Pull a non-empty string field from the JSON body or raise.

    Args:
        field: Body key to require.

    Returns:
        The non-empty string value of ``field``.

    Raises:
        ValidationError: If the field is absent or not a non-empty string.
    """
    body = request.get_json(silent=True) or {}
    value = body.get(field)
    if not isinstance(value, str) or not value:
        raise ValidationError(f"'{field}' is required.")
    return value


@api_v1.post("/auth/passkey/register/begin")
@require_auth
def passkey_register_begin_route() -> tuple[Response, int]:
    """Return registration options for the signed-in user.

    Returns:
        Tuple of JSON body (``options``, ``state``) and HTTP 200.
    """
    user_id = str(get_current_user_id())
    session = database.get_db()
    started = passkey.register_begin(session, user_id=user_id)
    body: dict[str, Any] = {
        "data": {
            "options": started.options,
            "state": started.state,
        }
    }
    return jsonify(body), 200


@api_v1.post("/auth/passkey/register/complete")
@require_auth
def passkey_register_complete_route() -> tuple[Response, int]:
    """Verify the attestation and persist the new passkey.

    Returns:
        Tuple of JSON body (``credential_id``) and HTTP 201.

    Raises:
        ValidationError: If ``credential`` or ``state`` is missing.
        AppError: Propagated from :func:`passkey.register_complete`.
    """
    body = request.get_json(silent=True) or {}
    name_value = body.get("name")
    name = name_value if isinstance(name_value, str) and name_value else None

    credential = _require_dict_field("credential")
    state = _require_string_field("state")

    user_id = str(get_current_user_id())
    session = database.get_db()
    cred_id = passkey.register_complete(
        session,
        user_id=user_id,
        credential=credential,
        state=state,
        name=name,
    )
    return jsonify({"data": {"credential_id": cred_id}}), 201


@api_v1.get("/auth/passkey")
@require_auth
def passkey_list_route() -> tuple[Response, int]:
    """List every passkey registered to the authenticated user.

    Returns:
        Tuple of JSON body (``{"data": [{"credential_id", "name",
        "transports", "created_at", "last_used_at"}, ...]}``) and
        HTTP 200. Returns an empty list if the user has none.
    """
    user_id = get_current_user_id()
    session = database.get_db()
    creds = repo.list_passkeys_for_user(session, user_id)
    body: dict[str, Any] = {
        "data": [
            {
                "credential_id": cred.credential_id,
                "name": cred.name,
                "transports": cred.transports,
                "created_at": cred.created_at.isoformat(),
                "last_used_at": (
                    cred.last_used_at.isoformat() if cred.last_used_at else None
                ),
            }
            for cred in creds
        ]
    }
    return jsonify(body), 200


@api_v1.delete("/auth/passkey/<path:credential_id>")
@require_auth
def passkey_delete_route(credential_id: str) -> tuple[Response, int]:
    """Remove a passkey owned by the authenticated user.

    The ownership check is enforced in the repository — a user
    cannot delete another user's credential by guessing its id.

    Args:
        credential_id: Base64url-encoded credential id from the URL.

    Returns:
        Tuple of empty JSON body and HTTP 204.

    Raises:
        NotFoundError: With code ``PASSKEY_AUTH_FAILED`` if no matching
            passkey is registered to the current user.
    """
    user_id = get_current_user_id()
    session = database.get_db()
    deleted = repo.delete_passkey_for_user(
        session, user_id=user_id, credential_id=credential_id
    )
    if not deleted:
        raise NotFoundError(code=PASSKEY_AUTH_FAILED, message="Passkey not found.")
    return jsonify({}), 204


@api_v1.post("/auth/passkey/sign-in/begin")
@require_app_client
def passkey_signin_begin_route() -> tuple[Response, int]:
    """Return discoverable-credential authentication options.

    Returns:
        Tuple of JSON body (``options``, ``state``) and HTTP 200.
    """
    app_client = get_current_app_client()
    started = passkey.authenticate_begin(app_client_id=app_client.client_id)
    body: dict[str, Any] = {
        "data": {
            "options": started.options,
            "state": started.state,
        }
    }
    return jsonify(body), 200


@api_v1.post("/auth/passkey/sign-in/complete")
@require_app_client
def passkey_signin_complete_route() -> tuple[Response, int]:
    """Verify the assertion and return an access+refresh pair.

    Returns:
        Tuple of JSON body and HTTP 200. Body shape mirrors
        ``/v1/token/refresh``.

    Raises:
        ValidationError: If ``credential`` or ``state`` is missing.
        AppError: Propagated from :func:`passkey.authenticate_complete`.
    """
    credential = _require_dict_field("credential")
    state = _require_string_field("state")
    app_client = get_current_app_client()
    session = database.get_db()

    pair = passkey.authenticate_complete(
        session,
        credential=credential,
        state=state,
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

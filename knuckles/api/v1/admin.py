"""Admin provisioning routes for ``app_clients``.

Operator-facing surface for provisioning and configuring consuming
apps without shell access. Every route is gated by
:func:`knuckles.core.admin_auth.require_admin` — when
``KNUCKLES_ADMIN_TOKEN`` is unset these routes 404 as if they did not
exist.

Routes (all under ``/v1/admin/app-clients``):

* ``POST   /``                       — register a tenant; returns the
  plaintext client secret exactly once.
* ``GET    /``                       — list tenants (redacted).
* ``GET    /<client_id>``            — fetch one tenant (redacted).
* ``PATCH  /<client_id>``            — update tenant-config columns;
  ``""``/``null`` clear a column to env-var fallback.
* ``POST   /<client_id>/rotate-secret`` — mint a new client secret.
* ``PUT    /<client_id>/origins``    — replace allowed_origins.

Routes stay thin: validate body shape, call the service. No business
logic lives here.
"""

from __future__ import annotations

from typing import Any

from flask import jsonify, request
from flask.wrappers import Response

from knuckles.api.v1 import api_v1
from knuckles.core import database
from knuckles.core.admin_auth import require_admin
from knuckles.core.exceptions import ValidationError
from knuckles.services import app_clients as app_clients_service


def _json_object_body() -> dict[str, Any]:
    """Return the request body as a JSON object.

    Returns:
        The parsed JSON body, or an empty dict when no body was sent.

    Raises:
        ValidationError: If a body was sent but is not a JSON object.
    """
    body = request.get_json(silent=True)
    if body is None:
        return {}
    if not isinstance(body, dict):
        raise ValidationError("Request body must be a JSON object.")
    return body


def _require_string(body: dict[str, Any], field: str) -> str:
    """Pull a required non-empty string field from a parsed body.

    Args:
        body: The parsed JSON object.
        field: The key to require.

    Returns:
        The non-empty string value.

    Raises:
        ValidationError: If the field is absent or not a non-empty
            string.
    """
    value = body.get(field)
    if not isinstance(value, str) or not value:
        raise ValidationError(f"'{field}' is required.")
    return value


def _require_string_list(body: dict[str, Any], field: str) -> list[str]:
    """Pull a list-of-strings field from a parsed body.

    Args:
        body: The parsed JSON object.
        field: The key to read.

    Returns:
        The list of strings (the field must be present).

    Raises:
        ValidationError: If the field is missing, not a list, or
            contains non-string entries.
    """
    value = body.get(field)
    if not isinstance(value, list) or not all(isinstance(o, str) for o in value):
        raise ValidationError(f"'{field}' must be a list of strings.")
    return value


@api_v1.post("/admin/app-clients")
@require_admin
def create_app_client_route() -> tuple[Response, int]:
    """Register a new app client and return its secret exactly once.

    Returns:
        Tuple of JSON body (serialized row plus ``client_secret``)
        and HTTP 201.

    Raises:
        ValidationError: If the body is malformed or the service
            rejects the registration.
    """
    body = _json_object_body()
    client_id = _require_string(body, "client_id")
    app_name = _require_string(body, "app_name")
    if "allowed_origins" in body:
        allowed_origins = _require_string_list(body, "allowed_origins")
    else:
        allowed_origins = []

    session = database.get_db()
    client, secret = app_clients_service.register(
        session,
        client_id=client_id,
        app_name=app_name,
        allowed_origins=allowed_origins,
    )

    data = app_clients_service.serialize(client)
    data["client_secret"] = secret
    return jsonify({"data": data}), 201


@api_v1.get("/admin/app-clients")
@require_admin
def list_app_clients_route() -> tuple[Response, int]:
    """List every registered app client, redacted.

    Returns:
        Tuple of JSON body and HTTP 200.
    """
    session = database.get_db()
    clients = app_clients_service.list_clients(session)
    return jsonify({"data": [app_clients_service.serialize(c) for c in clients]}), 200


@api_v1.get("/admin/app-clients/<client_id>")
@require_admin
def get_app_client_route(client_id: str) -> tuple[Response, int]:
    """Fetch a single app client, redacted.

    Args:
        client_id: The ``app_clients.client_id`` from the URL.

    Returns:
        Tuple of JSON body and HTTP 200.

    Raises:
        NotFoundError: Propagated from the service when no row
            matches.
    """
    session = database.get_db()
    client = app_clients_service.get_client(session, client_id=client_id)
    return jsonify({"data": app_clients_service.serialize(client)}), 200


@api_v1.patch("/admin/app-clients/<client_id>")
@require_admin
def patch_app_client_route(client_id: str) -> tuple[Response, int]:
    """Update tenant-config columns on an app client.

    Body values of ``""`` or ``null`` clear the column back to NULL
    (env-var fallback), matching the configure CLI's convention.

    Args:
        client_id: The ``app_clients.client_id`` from the URL.

    Returns:
        Tuple of JSON body (serialized row) and HTTP 200.

    Raises:
        ValidationError: If the body is malformed, empty, names a
            field outside the tenant-config allow-list, or trips the
            ``webauthn_rp_id`` guardrail.
        NotFoundError: Propagated from the service when no row
            matches.
    """
    body = _json_object_body()

    force_value = body.pop("force_webauthn_rp_id", False)
    if not isinstance(force_value, bool):
        raise ValidationError("'force_webauthn_rp_id' must be a boolean.")

    updates: dict[str, str | None] = {}
    for key, value in body.items():
        if value is None or value == "":
            updates[key] = None
        elif isinstance(value, str):
            updates[key] = value
        else:
            raise ValidationError(f"'{key}' must be a string or null.")
    if not updates:
        raise ValidationError("No tenant-config fields supplied.")

    session = database.get_db()
    client = app_clients_service.update_config(
        session,
        client_id=client_id,
        updates=updates,
        force_webauthn_rp_id=force_value,
    )
    return jsonify({"data": app_clients_service.serialize(client)}), 200


@api_v1.post("/admin/app-clients/<client_id>/rotate-secret")
@require_admin
def rotate_app_client_secret_route(client_id: str) -> tuple[Response, int]:
    """Mint a new client secret, returning the plaintext exactly once.

    Args:
        client_id: The ``app_clients.client_id`` from the URL.

    Returns:
        Tuple of JSON body carrying the new plaintext secret and
        HTTP 200.

    Raises:
        NotFoundError: Propagated from the service when no row
            matches.
    """
    session = database.get_db()
    secret = app_clients_service.rotate_secret(session, client_id=client_id)
    return jsonify({"data": {"client_id": client_id, "client_secret": secret}}), 200


@api_v1.put("/admin/app-clients/<client_id>/origins")
@require_admin
def put_app_client_origins_route(client_id: str) -> tuple[Response, int]:
    """Replace the entire allowed-origins list for an app client.

    Args:
        client_id: The ``app_clients.client_id`` from the URL.

    Returns:
        Tuple of JSON body (serialized row) and HTTP 200.

    Raises:
        ValidationError: If the body is malformed or any origin fails
            validation.
        NotFoundError: Propagated from the service when no row
            matches.
    """
    body = _json_object_body()
    allowed_origins = _require_string_list(body, "allowed_origins")

    session = database.get_db()
    client = app_clients_service.set_origins(
        session, client_id=client_id, allowed_origins=allowed_origins
    )
    return jsonify({"data": app_clients_service.serialize(client)}), 200

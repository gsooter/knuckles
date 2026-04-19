"""App-client authentication for Knuckles' own HTTP API.

Every consuming app (Greenroom, future apps) authenticates itself to
Knuckles with an ``X-Client-Id`` + ``X-Client-Secret`` header pair on
routes that mutate session state — refresh-token rotation, logout,
ceremony completion. Browser-facing routes that a human *initiates*
(magic-link send, OAuth start) also carry the client pair so Knuckles
knows which app's redirect URLs to trust.

The stored secret is a SHA-256 hex digest; the comparison is done
with :func:`hmac.compare_digest` to avoid leaking equality timing.
Matching the row populates ``flask.g.app_client`` so route handlers can
read which app is making the call without re-querying the DB.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Callable
from functools import wraps
from typing import ParamSpec, TypeVar, cast

from flask import g, request

from knuckles.core import database
from knuckles.core.exceptions import INVALID_CLIENT, UnauthorizedError
from knuckles.data.models import AppClient
from knuckles.data.repositories import auth as repo

_P = ParamSpec("_P")
_T = TypeVar("_T")


def require_app_client(view: Callable[_P, _T]) -> Callable[_P, _T]:
    """Reject requests missing or carrying invalid app-client credentials.

    Populates ``g.app_client`` on success so the wrapped view can read
    the client row via :func:`get_current_app_client`.

    Args:
        view: The Flask view function to wrap.

    Returns:
        A wrapped view that enforces the app-client requirement.
    """

    @wraps(view)
    def wrapper(*args: _P.args, **kwargs: _P.kwargs) -> _T:
        """Validate ``X-Client-Id`` + ``X-Client-Secret`` and delegate.

        Raises:
            UnauthorizedError: If either header is missing, the client
                id is unknown, or the secret does not match.
        """
        client_id = request.headers.get("X-Client-Id", "").strip()
        client_secret = request.headers.get("X-Client-Secret", "").strip()
        if not client_id or not client_secret:
            raise UnauthorizedError(
                message="Missing app-client credentials.", code=INVALID_CLIENT
            )

        session = database.get_db()
        client = repo.get_app_client(session, client_id)
        if client is None:
            raise UnauthorizedError(message="Unknown app-client.", code=INVALID_CLIENT)

        expected = client.client_secret_hash
        provided = hashlib.sha256(client_secret.encode("ascii")).hexdigest()
        if not hmac.compare_digest(expected, provided):
            raise UnauthorizedError(
                message="Invalid app-client secret.", code=INVALID_CLIENT
            )

        g.app_client = client
        return view(*args, **kwargs)

    return cast("Callable[_P, _T]", wrapper)


def get_current_app_client() -> AppClient:
    """Return the app-client resolved by :func:`require_app_client`.

    Returns:
        The ``AppClient`` row populated on ``flask.g``.

    Raises:
        RuntimeError: If called outside a ``require_app_client``-wrapped
            view.
    """
    client = g.get("app_client") if "app_client" in g else None
    if client is None:
        raise RuntimeError(
            "get_current_app_client called outside a require_app_client view."
        )
    return cast("AppClient", client)

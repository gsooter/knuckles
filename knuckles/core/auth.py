"""Bearer-token auth decorator for Knuckles' own endpoints.

Knuckles issues access tokens; it also *consumes* them on its own first-
party endpoints (``/v1/me``, passkey registration, connected services).
This module is the verifier for those calls.

Every Knuckles access token carries ``aud = app_client_id``. When the
consuming app calls Knuckles with that token, Knuckles accepts any
``aud`` that resolves to a registered ``app_clients.client_id``. The
specific audience is surfaced via ``get_token_claims`` so route handlers
that care (e.g. scope checks) can consult it.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from functools import wraps
from typing import ParamSpec, TypeVar, cast

from flask import g, request

from knuckles.core.exceptions import INVALID_TOKEN, UnauthorizedError
from knuckles.core.jwt import verify_access_token

_P = ParamSpec("_P")
_T = TypeVar("_T")


def require_auth(view: Callable[_P, _T]) -> Callable[_P, _T]:
    """Reject requests missing or carrying an invalid bearer token.

    Populates ``g.current_user_id`` (``uuid.UUID``) and
    ``g.token_claims`` (``dict``) on success.

    Args:
        view: The Flask view function to wrap.

    Returns:
        A wrapped view that enforces the bearer requirement.
    """

    @wraps(view)
    def wrapper(*args: _P.args, **kwargs: _P.kwargs) -> _T:
        """Validate the bearer token and invoke the wrapped view.

        Raises:
            UnauthorizedError: If the header is missing, malformed, or
                the token fails verification.
        """
        header = request.headers.get("Authorization", "")
        if not header.lower().startswith("bearer "):
            raise UnauthorizedError(message="Missing bearer token.", code=INVALID_TOKEN)
        token = header.split(" ", 1)[1].strip()
        if not token:
            raise UnauthorizedError(message="Missing bearer token.", code=INVALID_TOKEN)

        claims = verify_access_token(token)
        try:
            user_id = uuid.UUID(claims["sub"])
        except (KeyError, ValueError) as exc:
            raise UnauthorizedError(
                message="Token missing valid subject.", code=INVALID_TOKEN
            ) from exc

        g.current_user_id = user_id
        g.token_claims = claims
        return view(*args, **kwargs)

    return cast("Callable[_P, _T]", wrapper)


def get_current_user_id() -> uuid.UUID:
    """Return the authenticated user's id within a ``require_auth`` view.

    Returns:
        The authenticated user's UUID.

    Raises:
        RuntimeError: If called outside a ``require_auth``-decorated view.
    """
    user_id = g.get("current_user_id") if "current_user_id" in g else None
    if user_id is None:
        raise RuntimeError(
            "get_current_user_id called outside a require_auth-decorated view."
        )
    return cast("uuid.UUID", user_id)


def get_token_claims() -> dict[str, object]:
    """Return the verified token claims for the current request.

    Returns:
        The decoded claims dictionary.

    Raises:
        RuntimeError: If called outside a ``require_auth``-decorated view.
    """
    claims = g.get("token_claims") if "token_claims" in g else None
    if claims is None:
        raise RuntimeError(
            "get_token_claims called outside a require_auth-decorated view."
        )
    return cast("dict[str, object]", claims)

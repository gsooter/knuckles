"""Flask middleware for validating Knuckles bearer tokens.

Drop this into any Flask app that wants to authenticate requests
against Knuckles. The SDK's JWKS verifier caches keys in-memory, so
after the first request on a fresh process every verification is
local — no per-request network hop to Knuckles.

Usage::

    from flask import Flask, g
    from middleware import build_knuckles_client, require_auth

    app = Flask(__name__)
    knuckles = build_knuckles_client()

    @app.route("/api/me")
    @require_auth(knuckles)
    def me():
        return {"user_id": g.user_id}
"""

from __future__ import annotations

import functools
import os
from typing import TYPE_CHECKING, Any, TypeVar

from flask import g, jsonify, request
from knuckles_client import KnucklesClient, KnucklesTokenError

if TYPE_CHECKING:
    from collections.abc import Callable

    from flask.wrappers import Response

_T = TypeVar("_T")


def build_knuckles_client() -> KnucklesClient:
    """Construct a configured client from required env vars.

    Returns:
        A :class:`KnucklesClient` ready to share across requests.

    Raises:
        RuntimeError: If any required env var is missing.
    """
    return KnucklesClient(
        base_url=_required("KNUCKLES_URL"),
        client_id=_required("KNUCKLES_CLIENT_ID"),
        client_secret=_required("KNUCKLES_CLIENT_SECRET"),
    )


def require_auth(
    client: KnucklesClient,
) -> Callable[[Callable[..., _T]], Callable[..., Response | _T]]:
    """Build a Flask decorator that validates the bearer token.

    Args:
        client: The shared :class:`KnucklesClient` to verify with.

    Returns:
        A decorator. The wrapped view receives a 401 JSON response
        if the token is missing or invalid; otherwise it runs with
        ``g.user_id`` and ``g.access_token_claims`` populated.
    """

    def decorator(view: Callable[..., _T]) -> Callable[..., Response | _T]:
        """Wrap ``view`` with bearer-token validation.

        Args:
            view: The Flask view function to protect.

        Returns:
            The wrapped view.
        """

        @functools.wraps(view)
        def wrapper(*args: Any, **kwargs: Any) -> Response | _T:
            """Run the validation and dispatch to the wrapped view.

            Returns:
                Either the wrapped view's return value, or a 401
                JSON response if validation failed.
            """
            header = request.headers.get("Authorization", "")
            if not header.lower().startswith("bearer "):
                return jsonify({"error": "missing_bearer"}), 401  # type: ignore[return-value]
            token = header.split(" ", 1)[1].strip()
            try:
                claims = client.verify_access_token(token)
            except KnucklesTokenError as exc:
                return jsonify({"error": "invalid_token", "detail": str(exc)}), 401  # type: ignore[return-value]
            g.user_id = claims["sub"]
            g.access_token_claims = claims
            return view(*args, **kwargs)

        return wrapper

    return decorator


def _required(name: str) -> str:
    """Read an env var or raise.

    Args:
        name: Env var name.

    Returns:
        The non-empty value.

    Raises:
        RuntimeError: If the var is missing or empty.
    """
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"Missing required env var: {name}")
    return value

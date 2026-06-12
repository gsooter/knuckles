"""Operator authentication for the Knuckles admin provisioning API.

The ``/v1/admin/*`` surface lets an operator provision and configure
``app_clients`` rows over HTTP instead of shell access. It is gated by
a single shared token from ``KNUCKLES_ADMIN_TOKEN``:

* When the env var is **empty** (the default), every admin route
  raises ``NOT_FOUND`` — the surface does not exist, so existing
  deployments keep a zero admin attack surface without any action.
* When set, requests must carry an exactly-matching ``X-Admin-Token``
  header. The comparison hashes both sides with SHA-256 and uses
  :func:`hmac.compare_digest` so neither token length nor prefix
  equality leaks through timing.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Callable
from functools import wraps
from typing import ParamSpec, TypeVar, cast

from flask import request

from knuckles.core.config import get_settings
from knuckles.core.exceptions import NotFoundError, UnauthorizedError

_P = ParamSpec("_P")
_T = TypeVar("_T")


def _hexdigest(value: str) -> str:
    """Return the SHA-256 hex digest of a UTF-8 encoded string.

    Args:
        value: The string to hash. UTF-8 (not ASCII) so an
            attacker-controlled non-ASCII header value hashes to a
            mismatch instead of crashing into a 500.

    Returns:
        The 64-character lowercase hex digest.
    """
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def require_admin(view: Callable[_P, _T]) -> Callable[_P, _T]:
    """Reject requests that do not carry the configured admin token.

    Args:
        view: The Flask view function to wrap.

    Returns:
        A wrapped view that enforces the admin-token requirement.
    """

    @wraps(view)
    def wrapper(*args: _P.args, **kwargs: _P.kwargs) -> _T:
        """Validate ``X-Admin-Token`` against settings and delegate.

        Raises:
            NotFoundError: When ``KNUCKLES_ADMIN_TOKEN`` is empty —
                the admin surface is disabled and must look
                nonexistent.
            UnauthorizedError: When the header is missing or does not
                match the configured token.
        """
        admin_token = get_settings().knuckles_admin_token
        if not admin_token:
            raise NotFoundError(code="NOT_FOUND", message="Not found.")

        provided = request.headers.get("X-Admin-Token", "").strip()
        if not provided or not hmac.compare_digest(
            _hexdigest(admin_token), _hexdigest(provided)
        ):
            raise UnauthorizedError(message="Invalid admin token.", code="UNAUTHORIZED")

        return view(*args, **kwargs)

    return cast("Callable[_P, _T]", wrapper)

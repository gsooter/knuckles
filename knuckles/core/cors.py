"""Origin allow-list lookup for the strict-CORS path.

The set of allowed origins is the union of every registered
``app_clients.allowed_origins`` list. App-clients are slow-changing
(operator-managed via the registration script), so we cache the union
in-process for ``_TTL_SECONDS`` to avoid querying on every response.

Public API:

* :func:`is_origin_allowed` — ``True`` iff ``origin`` is in the cached
  union. The first call after process start (or after the cache
  expires) refreshes from the DB.
* :func:`reset_cache` — drop the cache. Test helper.
"""

from __future__ import annotations

import threading
import time

from sqlalchemy import select

from knuckles.core import database
from knuckles.data.models import AppClient

_TTL_SECONDS = 60.0
_lock = threading.Lock()
_cached: frozenset[str] | None = None
_cache_expires_at = 0.0


def _normalize(origin: str) -> str:
    """Strip a trailing slash so comparisons match the helper in app_client_auth.

    Args:
        origin: An origin string from a registered app-client or from
            an incoming ``Origin`` request header.

    Returns:
        The origin with any trailing ``/`` removed.
    """
    return origin.rstrip("/")


def _load_allowed_origins() -> frozenset[str]:
    """Query every app-client's ``allowed_origins`` and union them.

    Returns:
        A frozenset of normalized origin strings. Empty if no
        app-clients are registered.
    """
    session = database.get_session_factory()()
    try:
        rows = session.execute(select(AppClient.allowed_origins)).scalars().all()
    finally:
        session.close()
    union: set[str] = set()
    for entry in rows:
        # JSON column — should be a list[str], but tolerate junk rather
        # than 500 the response.
        if not isinstance(entry, list):
            continue
        for origin in entry:
            if isinstance(origin, str) and origin:
                union.add(_normalize(origin))
    return frozenset(union)


def is_origin_allowed(origin: str) -> bool:
    """Return ``True`` iff ``origin`` is in the union of allowed origins.

    Args:
        origin: The value of an incoming ``Origin`` request header.

    Returns:
        Whether the origin matches any registered app-client.
    """
    global _cached, _cache_expires_at
    now = time.monotonic()
    with _lock:
        if _cached is None or now >= _cache_expires_at:
            _cached = _load_allowed_origins()
            _cache_expires_at = now + _TTL_SECONDS
        cached = _cached
    return _normalize(origin) in cached


def reset_cache() -> None:
    """Drop the cached allow-list.

    Test helper — production code never needs to call this.
    """
    global _cached, _cache_expires_at
    with _lock:
        _cached = None
        _cache_expires_at = 0.0

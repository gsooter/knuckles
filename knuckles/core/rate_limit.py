"""Per-key rate limiting for hot ceremony endpoints.

The first user of this module is the magic-link ``/start`` route,
which would otherwise let anyone with valid app-client credentials
loop a victim's address through Resend. The limit is *per email
address* — IPs are not useful here because consuming apps proxy the
request from a single backend IP.

The implementation is an in-process sliding-window counter. Each
gunicorn worker keeps its own state, so the *effective* limit is
``WEB_CONCURRENCY * MAX_REQUESTS_PER_WINDOW``. That ceiling is
intentional: if you need precise distributed limits, swap this module
for a Redis-backed implementation — the ``allow`` signature stays the
same so callers don't change.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable


class RateLimiter:
    """A fixed-budget sliding-window counter keyed by an arbitrary string.

    Attributes:
        max_requests: Max events permitted per key per window.
        window_seconds: Width of the sliding window.
    """

    def __init__(
        self,
        *,
        max_requests: int,
        window_seconds: int,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """Construct a limiter.

        Args:
            max_requests: Max events permitted per key per window.
            window_seconds: Window width in seconds.
            clock: Monotonic clock function. Tests override this.
        """
        self._max = max_requests
        self._window = window_seconds
        self._clock = clock
        self._events: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        """Record an attempt under ``key`` and report whether it is allowed.

        Args:
            key: Bucket key (e.g. an email address).

        Returns:
            ``True`` if the attempt fits within the per-key budget,
            ``False`` if it should be rejected.
        """
        now = self._clock()
        cutoff = now - self._window
        with self._lock:
            events = self._events.get(key)
            if events is None:
                events = deque()
                self._events[key] = events
            while events and events[0] < cutoff:
                events.popleft()
            if len(events) >= self._max:
                return False
            events.append(now)
            return True

    def reset(self) -> None:
        """Drop all recorded events.

        Test helper — production code never needs to call this.
        """
        with self._lock:
            self._events.clear()


# The magic-link sender is the only rate-limited path today. Default
# budget: 5 sends per email per hour. Override at process start by
# re-instantiating before the routes are imported (typically from
# tests).
magic_link_limiter = RateLimiter(max_requests=5, window_seconds=3600)

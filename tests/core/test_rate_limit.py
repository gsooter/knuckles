"""Tests for the in-process rate limiter."""

from __future__ import annotations

from knuckles.core.rate_limit import RateLimiter


def test_allows_up_to_budget_then_rejects() -> None:
    """The limiter accepts max_requests calls per key, then rejects."""
    limiter = RateLimiter(max_requests=3, window_seconds=10)
    assert limiter.allow("a") is True
    assert limiter.allow("a") is True
    assert limiter.allow("a") is True
    assert limiter.allow("a") is False


def test_keys_are_isolated() -> None:
    """One key's bucket does not exhaust another key's budget."""
    limiter = RateLimiter(max_requests=1, window_seconds=10)
    assert limiter.allow("a") is True
    assert limiter.allow("a") is False
    assert limiter.allow("b") is True


def test_window_slides_with_clock() -> None:
    """Old events drop off once the window has elapsed."""
    now = [1000.0]
    limiter = RateLimiter(
        max_requests=2,
        window_seconds=10,
        clock=lambda: now[0],
    )
    assert limiter.allow("k") is True
    assert limiter.allow("k") is True
    assert limiter.allow("k") is False
    now[0] += 11
    assert limiter.allow("k") is True


def test_reset_drops_all_state() -> None:
    """``reset`` makes a previously-exhausted key fresh again."""
    limiter = RateLimiter(max_requests=1, window_seconds=10)
    assert limiter.allow("k") is True
    assert limiter.allow("k") is False
    limiter.reset()
    assert limiter.allow("k") is True

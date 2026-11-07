"""Shared fixtures for the knuckles-client SDK test suite."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
import responses

from knuckles_client import KnucklesClient

BASE_URL = "https://auth.example.com"
CLIENT_ID = "my-app"
CLIENT_SECRET = "secret"
ADMIN_TOKEN = "admin-secret"


@pytest.fixture()
def mocked_responses() -> Iterator[responses.RequestsMock]:
    """Yield a fresh ``responses`` activated mock per test.

    Yields:
        An active :class:`responses.RequestsMock`.
    """
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        yield rsps


@pytest.fixture()
def client() -> KnucklesClient:
    """Return a configured SDK client pointed at the mocked base URL.

    Returns:
        A :class:`KnucklesClient`.
    """
    return KnucklesClient(
        base_url=BASE_URL, client_id=CLIENT_ID, client_secret=CLIENT_SECRET
    )


@pytest.fixture()
def admin_client() -> KnucklesClient:
    """Return an SDK client with the admin API configured.

    Returns:
        A :class:`KnucklesClient` constructed with ``admin_token``.
    """
    return KnucklesClient(
        base_url=BASE_URL,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        admin_token=ADMIN_TOKEN,
    )

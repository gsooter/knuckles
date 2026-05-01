"""HTTP-mocked tests for the Knuckles SDK client.

Every test mocks Knuckles' HTTP responses with ``responses`` so the
suite is hermetic. Coverage focuses on:

* Client headers are sent on authenticated routes.
* Bearer is sent on user-context routes.
* Each ceremony's success path returns the right typed shape.
* Error envelopes promote to the right exception subclass.
* Logout / delete tolerate 204 (no body).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
import responses

from knuckles_client import (
    KnucklesAuthError,
    KnucklesClient,
    KnucklesRateLimitError,
    KnucklesValidationError,
)

from .conftest import BASE_URL, CLIENT_ID, CLIENT_SECRET


def _token_pair_body() -> dict[str, object]:
    """Build a token-pair response body matching Knuckles' shape.

    Returns:
        A ``{"data": {...}}`` dict with ISO-formatted timestamps.
    """
    now = datetime.now(tz=UTC)
    return {
        "data": {
            "access_token": "access-jwt",
            "access_token_expires_at": (now + timedelta(hours=1)).isoformat(),
            "refresh_token": "refresh-opaque",
            "refresh_token_expires_at": (now + timedelta(days=30)).isoformat(),
            "token_type": "Bearer",
        }
    }


def _assert_client_headers(call: responses.Call) -> None:
    """Assert the call carries the configured client headers.

    Args:
        call: The captured request from ``responses.calls``.
    """
    assert call.request.headers["X-Client-Id"] == CLIENT_ID
    assert call.request.headers["X-Client-Secret"] == CLIENT_SECRET


# ---------------------------------------------------------------------------
# Magic-link
# ---------------------------------------------------------------------------


def test_magic_link_start_posts_headers_and_body(
    client: KnucklesClient, mocked_responses: responses.RequestsMock
) -> None:
    """``magic_link.start`` POSTs to the right path with the client headers."""
    mocked_responses.post(f"{BASE_URL}/v1/auth/magic-link/start", status=202)
    client.magic_link.start(
        email="user@example.com", redirect_url="https://app/callback"
    )
    _assert_client_headers(mocked_responses.calls[0])


def test_magic_link_verify_returns_token_pair(
    client: KnucklesClient, mocked_responses: responses.RequestsMock
) -> None:
    """``magic_link.verify`` parses the token-pair shape."""
    mocked_responses.post(
        f"{BASE_URL}/v1/auth/magic-link/verify",
        status=200,
        json=_token_pair_body(),
    )
    pair = client.magic_link.verify("raw-token")
    assert pair.access_token == "access-jwt"
    assert pair.refresh_token == "refresh-opaque"


def test_magic_link_start_429_raises_rate_limit_error(
    client: KnucklesClient, mocked_responses: responses.RequestsMock
) -> None:
    """A 429 response promotes to :class:`KnucklesRateLimitError`."""
    mocked_responses.post(
        f"{BASE_URL}/v1/auth/magic-link/start",
        status=429,
        json={"error": {"code": "RATE_LIMITED", "message": "slow down"}},
    )
    with pytest.raises(KnucklesRateLimitError) as exc_info:
        client.magic_link.start(email="x@y", redirect_url="https://app/cb")
    assert exc_info.value.code == "RATE_LIMITED"


def test_magic_link_start_422_raises_validation_error(
    client: KnucklesClient, mocked_responses: responses.RequestsMock
) -> None:
    """A 422 response promotes to :class:`KnucklesValidationError`."""
    mocked_responses.post(
        f"{BASE_URL}/v1/auth/magic-link/start",
        status=422,
        json={"error": {"code": "VALIDATION_ERROR", "message": "bad"}},
    )
    with pytest.raises(KnucklesValidationError):
        client.magic_link.start(email="x@y", redirect_url="not-a-url")


def test_error_carries_request_id_from_meta(
    client: KnucklesClient, mocked_responses: responses.RequestsMock
) -> None:
    """The SDK pulls ``meta.request_id`` onto the raised exception."""
    mocked_responses.post(
        f"{BASE_URL}/v1/auth/magic-link/start",
        status=429,
        json={
            "error": {"code": "RATE_LIMITED", "message": "slow down"},
            "meta": {"request_id": "abcd-1234"},
        },
    )
    with pytest.raises(KnucklesRateLimitError) as exc_info:
        client.magic_link.start(email="x@y", redirect_url="https://app/cb")
    assert exc_info.value.request_id == "abcd-1234"
    # Request id is appended to ``str(exc)`` for log-friendliness.
    assert "request_id=abcd-1234" in str(exc_info.value)


def test_error_falls_back_to_x_request_id_header(
    client: KnucklesClient, mocked_responses: responses.RequestsMock
) -> None:
    """When the body lacks ``meta.request_id`` we fall back to the header."""
    mocked_responses.post(
        f"{BASE_URL}/v1/auth/magic-link/start",
        status=422,
        json={"error": {"code": "VALIDATION_ERROR", "message": "bad"}},
        headers={"X-Request-Id": "header-only-7"},
    )
    with pytest.raises(KnucklesValidationError) as exc_info:
        client.magic_link.start(email="x@y", redirect_url="not-a-url")
    assert exc_info.value.request_id == "header-only-7"


def test_error_request_id_is_none_against_old_server(
    client: KnucklesClient, mocked_responses: responses.RequestsMock
) -> None:
    """Old Knuckles servers don't emit a request id; the field is ``None``."""
    mocked_responses.post(
        f"{BASE_URL}/v1/auth/magic-link/start",
        status=422,
        json={"error": {"code": "VALIDATION_ERROR", "message": "bad"}},
    )
    with pytest.raises(KnucklesValidationError) as exc_info:
        client.magic_link.start(email="x@y", redirect_url="not-a-url")
    assert exc_info.value.request_id is None
    # And the legacy ``str(exc)`` shape (no suffix) is preserved.
    assert "request_id=" not in str(exc_info.value)


# ---------------------------------------------------------------------------
# OAuth (Google + Apple)
# ---------------------------------------------------------------------------


def test_google_start_returns_authorize_url_and_state(
    client: KnucklesClient, mocked_responses: responses.RequestsMock
) -> None:
    """Google ``start`` parses the consent URL + state."""
    mocked_responses.post(
        f"{BASE_URL}/v1/auth/google/start",
        status=200,
        json={
            "data": {
                "authorize_url": "https://accounts.google.com/x?...",
                "state": "google-state-jwt",
            }
        },
    )
    out = client.google.start(redirect_url="https://app/cb")
    assert out.authorize_url.startswith("https://accounts.google.com")
    assert out.state == "google-state-jwt"


def test_google_complete_returns_token_pair(
    client: KnucklesClient, mocked_responses: responses.RequestsMock
) -> None:
    """Google ``complete`` returns a :class:`TokenPair`."""
    mocked_responses.post(
        f"{BASE_URL}/v1/auth/google/complete",
        status=200,
        json=_token_pair_body(),
    )
    pair = client.google.complete(code="g-code", state="g-state")
    assert pair.access_token == "access-jwt"


def test_apple_complete_passes_user_payload_when_present(
    client: KnucklesClient, mocked_responses: responses.RequestsMock
) -> None:
    """Apple ``complete`` forwards the ``user`` payload verbatim."""
    mocked_responses.post(
        f"{BASE_URL}/v1/auth/apple/complete",
        status=200,
        json=_token_pair_body(),
    )
    user_payload = {"name": {"firstName": "Ada", "lastName": "Lovelace"}}
    client.apple.complete(code="c", state="s", user=user_payload)
    body = mocked_responses.calls[0].request.body
    assert body is not None
    assert b"firstName" in body


# ---------------------------------------------------------------------------
# Refresh, logout, /me
# ---------------------------------------------------------------------------


def test_refresh_returns_new_pair(
    client: KnucklesClient, mocked_responses: responses.RequestsMock
) -> None:
    """``refresh`` returns the new access+refresh pair."""
    mocked_responses.post(
        f"{BASE_URL}/v1/token/refresh", status=200, json=_token_pair_body()
    )
    pair = client.refresh("old-refresh")
    assert pair.refresh_token == "refresh-opaque"


def test_refresh_reused_token_raises_auth_error(
    client: KnucklesClient, mocked_responses: responses.RequestsMock
) -> None:
    """``REFRESH_TOKEN_REUSED`` becomes :class:`KnucklesAuthError`."""
    mocked_responses.post(
        f"{BASE_URL}/v1/token/refresh",
        status=401,
        json={"error": {"code": "REFRESH_TOKEN_REUSED", "message": "reused"}},
    )
    with pytest.raises(KnucklesAuthError) as exc_info:
        client.refresh("compromised-refresh")
    assert exc_info.value.code == "REFRESH_TOKEN_REUSED"


def test_logout_handles_204(
    client: KnucklesClient, mocked_responses: responses.RequestsMock
) -> None:
    """``logout`` accepts a 204 with no body."""
    mocked_responses.post(f"{BASE_URL}/v1/logout", status=204)
    client.logout("any-refresh")  # does not raise


def test_logout_all_returns_revoked_count(
    client: KnucklesClient, mocked_responses: responses.RequestsMock
) -> None:
    """``logout_all`` returns the integer ``revoked`` from the body."""
    mocked_responses.post(
        f"{BASE_URL}/v1/logout/all",
        status=200,
        json={"data": {"revoked": 3}},
    )
    assert client.logout_all(access_token="bearer") == 3
    auth = mocked_responses.calls[0].request.headers["Authorization"]
    assert auth == "Bearer bearer"


def test_me_returns_user_profile(
    client: KnucklesClient, mocked_responses: responses.RequestsMock
) -> None:
    """``me`` parses the user-profile shape."""
    mocked_responses.get(
        f"{BASE_URL}/v1/me",
        status=200,
        json={
            "data": {
                "id": "u-1",
                "email": "me@example.com",
                "display_name": "Me",
                "avatar_url": None,
                "app_client_id": CLIENT_ID,
            }
        },
    )
    profile = client.me(access_token="bearer")
    assert profile.id == "u-1"
    assert profile.app_client_id == CLIENT_ID


# ---------------------------------------------------------------------------
# Passkey
# ---------------------------------------------------------------------------


def test_passkey_register_begin_sends_bearer(
    client: KnucklesClient, mocked_responses: responses.RequestsMock
) -> None:
    """``register_begin`` carries the access token."""
    mocked_responses.post(
        f"{BASE_URL}/v1/auth/passkey/register/begin",
        status=200,
        json={"data": {"options": {"rp": {"id": "x"}}, "state": "s"}},
    )
    client.passkey.register_begin(access_token="bearer")
    auth = mocked_responses.calls[0].request.headers["Authorization"]
    assert auth == "Bearer bearer"


def test_passkey_register_complete_returns_credential_id(
    client: KnucklesClient, mocked_responses: responses.RequestsMock
) -> None:
    """``register_complete`` returns the persisted credential id."""
    mocked_responses.post(
        f"{BASE_URL}/v1/auth/passkey/register/complete",
        status=201,
        json={"data": {"credential_id": "cred-xyz"}},
    )
    cred_id = client.passkey.register_complete(
        access_token="bearer",
        credential={"id": "x"},
        state="s",
        name="MacBook",
    )
    assert cred_id == "cred-xyz"


def test_passkey_list_parses_descriptors(
    client: KnucklesClient, mocked_responses: responses.RequestsMock
) -> None:
    """``passkey.list`` parses each row into a :class:`PasskeyDescriptor`."""
    mocked_responses.get(
        f"{BASE_URL}/v1/auth/passkey",
        status=200,
        json={
            "data": [
                {
                    "credential_id": "c1",
                    "name": "Phone",
                    "transports": "internal",
                    "created_at": "2026-04-26T12:00:00+00:00",
                    "last_used_at": None,
                }
            ]
        },
    )
    rows = client.passkey.list(access_token="bearer")
    assert len(rows) == 1
    assert rows[0].name == "Phone"
    assert rows[0].last_used_at is None


def test_passkey_delete_handles_204(
    client: KnucklesClient, mocked_responses: responses.RequestsMock
) -> None:
    """``passkey.delete`` accepts a 204 with no body."""
    mocked_responses.delete(f"{BASE_URL}/v1/auth/passkey/cred-xyz", status=204)
    client.passkey.delete(access_token="bearer", credential_id="cred-xyz")


def test_passkey_sign_in_complete_returns_token_pair(
    client: KnucklesClient, mocked_responses: responses.RequestsMock
) -> None:
    """``passkey.sign_in_complete`` returns the new pair."""
    mocked_responses.post(
        f"{BASE_URL}/v1/auth/passkey/sign-in/complete",
        status=200,
        json=_token_pair_body(),
    )
    pair = client.passkey.sign_in_complete(credential={"id": "c"}, state="s")
    assert pair.access_token == "access-jwt"


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def test_fetch_jwks_does_not_send_client_headers(
    client: KnucklesClient, mocked_responses: responses.RequestsMock
) -> None:
    """JWKS is unauthenticated — no client headers leak on that path."""
    mocked_responses.get(
        f"{BASE_URL}/.well-known/jwks.json", status=200, json={"keys": []}
    )
    client.fetch_jwks()
    assert "X-Client-Id" not in mocked_responses.calls[0].request.headers


def test_fetch_openid_configuration_parses_body(
    client: KnucklesClient, mocked_responses: responses.RequestsMock
) -> None:
    """OIDC discovery returns the body as-is."""
    mocked_responses.get(
        f"{BASE_URL}/.well-known/openid-configuration",
        status=200,
        json={"issuer": BASE_URL, "jwks_uri": f"{BASE_URL}/jwks.json"},
    )
    body = client.fetch_openid_configuration()
    assert body["issuer"] == BASE_URL

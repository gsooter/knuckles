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

import json
from datetime import UTC, datetime, timedelta

import pytest
import responses

from knuckles_client import (
    KnucklesAuthError,
    KnucklesClient,
    KnucklesRateLimitError,
    KnucklesValidationError,
)

from .conftest import ADMIN_TOKEN, BASE_URL, CLIENT_ID, CLIENT_SECRET


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


def _request_json(call: responses.Call) -> dict[str, object]:
    """Decode a captured request's JSON body.

    Args:
        call: The captured request from ``responses.calls``.

    Returns:
        The parsed JSON body as a dict.
    """
    body = call.request.body
    assert body is not None
    parsed = json.loads(body)
    assert isinstance(parsed, dict)
    return parsed


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


def test_rate_limit_error_parses_retry_after_header(
    client: KnucklesClient, mocked_responses: responses.RequestsMock
) -> None:
    """A 429 with ``Retry-After: <seconds>`` populates ``retry_after``."""
    mocked_responses.post(
        f"{BASE_URL}/v1/auth/magic-link/start",
        status=429,
        json={"error": {"code": "RATE_LIMITED", "message": "slow down"}},
        headers={"Retry-After": "30"},
    )
    with pytest.raises(KnucklesRateLimitError) as exc_info:
        client.magic_link.start(email="x@y", redirect_url="https://app/cb")
    assert exc_info.value.retry_after == 30


def test_rate_limit_error_retry_after_none_when_header_absent(
    client: KnucklesClient, mocked_responses: responses.RequestsMock
) -> None:
    """A 429 without ``Retry-After`` leaves ``retry_after`` as ``None``."""
    mocked_responses.post(
        f"{BASE_URL}/v1/auth/magic-link/start",
        status=429,
        json={"error": {"code": "RATE_LIMITED", "message": "slow down"}},
    )
    with pytest.raises(KnucklesRateLimitError) as exc_info:
        client.magic_link.start(email="x@y", redirect_url="https://app/cb")
    assert exc_info.value.retry_after is None


def test_rate_limit_error_retry_after_none_for_http_date(
    client: KnucklesClient, mocked_responses: responses.RequestsMock
) -> None:
    """The HTTP-date ``Retry-After`` form is not parsed — ``None``."""
    mocked_responses.post(
        f"{BASE_URL}/v1/auth/magic-link/start",
        status=429,
        json={"error": {"code": "RATE_LIMITED", "message": "slow down"}},
        headers={"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"},
    )
    with pytest.raises(KnucklesRateLimitError) as exc_info:
        client.magic_link.start(email="x@y", redirect_url="https://app/cb")
    assert exc_info.value.retry_after is None


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


# ---------------------------------------------------------------------------
# Account management (client.me.*)
# ---------------------------------------------------------------------------


def test_update_profile_sends_only_provided_fields(
    client: KnucklesClient, mocked_responses: responses.RequestsMock
) -> None:
    """``me.update_profile`` PATCHes only the field that was passed."""
    mocked_responses.patch(
        f"{BASE_URL}/v1/me",
        status=200,
        json={"data": {"id": "u-1", "display_name": "New Name"}},
    )
    out = client.me.update_profile(access_token="bearer", display_name="New Name")
    assert out["display_name"] == "New Name"
    call = mocked_responses.calls[0]
    assert call.request.headers["Authorization"] == "Bearer bearer"
    assert _request_json(call) == {"display_name": "New Name"}


def test_update_profile_explicit_none_clears_field(
    client: KnucklesClient, mocked_responses: responses.RequestsMock
) -> None:
    """An explicit ``None`` is sent in the body (clears server-side)."""
    mocked_responses.patch(
        f"{BASE_URL}/v1/me",
        status=200,
        json={"data": {"id": "u-1", "avatar_url": None}},
    )
    client.me.update_profile(access_token="bearer", avatar_url=None)
    assert _request_json(mocked_responses.calls[0]) == {"avatar_url": None}


def test_me_call_still_returns_user_profile(
    client: KnucklesClient, mocked_responses: responses.RequestsMock
) -> None:
    """``client.me(access_token=...)`` keeps its pre-0.1.2 behavior."""
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


def test_delete_account_handles_204(
    client: KnucklesClient, mocked_responses: responses.RequestsMock
) -> None:
    """``me.delete_account`` DELETEs /v1/me and accepts a 204."""
    mocked_responses.delete(f"{BASE_URL}/v1/me", status=204)
    client.me.delete_account(access_token="bearer")
    auth = mocked_responses.calls[0].request.headers["Authorization"]
    assert auth == "Bearer bearer"


def test_list_providers_returns_rows(
    client: KnucklesClient, mocked_responses: responses.RequestsMock
) -> None:
    """``me.list_providers`` returns the provider rows from ``data``."""
    mocked_responses.get(
        f"{BASE_URL}/v1/me/providers",
        status=200,
        json={
            "data": [
                {
                    "provider": "google",
                    "created_at": "2026-04-26T12:00:00+00:00",
                    "scopes": "openid email profile",
                }
            ]
        },
    )
    rows = client.me.list_providers(access_token="bearer")
    assert len(rows) == 1
    assert rows[0]["provider"] == "google"


def test_unlink_provider_handles_204(
    client: KnucklesClient, mocked_responses: responses.RequestsMock
) -> None:
    """``me.unlink_provider`` DELETEs the provider-specific path."""
    mocked_responses.delete(f"{BASE_URL}/v1/me/providers/google", status=204)
    client.me.unlink_provider(access_token="bearer", provider="google")
    auth = mocked_responses.calls[0].request.headers["Authorization"]
    assert auth == "Bearer bearer"


def test_start_email_change_posts_body_and_bearer(
    client: KnucklesClient, mocked_responses: responses.RequestsMock
) -> None:
    """``me.start_email_change`` POSTs the new address + redirect URL."""
    mocked_responses.post(f"{BASE_URL}/v1/me/email/start", status=202)
    client.me.start_email_change(
        access_token="bearer",
        new_email="new@example.com",
        redirect_url="https://app/email/verify",
    )
    call = mocked_responses.calls[0]
    assert call.request.headers["Authorization"] == "Bearer bearer"
    assert _request_json(call) == {
        "new_email": "new@example.com",
        "redirect_url": "https://app/email/verify",
    }


def test_verify_email_change_returns_email_with_client_headers_only(
    client: KnucklesClient, mocked_responses: responses.RequestsMock
) -> None:
    """``me.verify_email_change`` is client-headers-only and returns data."""
    mocked_responses.post(
        f"{BASE_URL}/v1/me/email/verify",
        status=200,
        json={"data": {"email": "new@example.com"}},
    )
    out = client.me.verify_email_change("raw-token")
    assert out == {"email": "new@example.com"}
    call = mocked_responses.calls[0]
    _assert_client_headers(call)
    assert "Authorization" not in call.request.headers
    assert _request_json(call) == {"token": "raw-token"}


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------


def test_sessions_list_returns_rows(
    client: KnucklesClient, mocked_responses: responses.RequestsMock
) -> None:
    """``sessions.list`` returns the session rows from ``data``."""
    mocked_responses.get(
        f"{BASE_URL}/v1/sessions",
        status=200,
        json={
            "data": [
                {
                    "id": "sess-1",
                    "created_at": "2026-06-01T12:00:00+00:00",
                    "expires_at": "2026-07-01T12:00:00+00:00",
                }
            ]
        },
    )
    rows = client.sessions.list(access_token="bearer")
    assert len(rows) == 1
    assert rows[0]["id"] == "sess-1"
    auth = mocked_responses.calls[0].request.headers["Authorization"]
    assert auth == "Bearer bearer"


def test_sessions_revoke_handles_204(
    client: KnucklesClient, mocked_responses: responses.RequestsMock
) -> None:
    """``sessions.revoke`` DELETEs the session-specific path."""
    mocked_responses.delete(f"{BASE_URL}/v1/sessions/sess-1", status=204)
    client.sessions.revoke(access_token="bearer", session_id="sess-1")
    auth = mocked_responses.calls[0].request.headers["Authorization"]
    assert auth == "Bearer bearer"


# ---------------------------------------------------------------------------
# Admin
# ---------------------------------------------------------------------------


def _assert_admin_headers(call: responses.Call) -> None:
    """Assert admin auth: ``X-Admin-Token`` on, client headers off.

    Args:
        call: The captured request from ``responses.calls``.
    """
    assert call.request.headers["X-Admin-Token"] == ADMIN_TOKEN
    assert "X-Client-Id" not in call.request.headers
    assert "X-Client-Secret" not in call.request.headers


def test_admin_methods_require_admin_token(client: KnucklesClient) -> None:
    """Calling any admin method without ``admin_token`` raises clearly."""
    with pytest.raises(RuntimeError, match="admin_token"):
        client.admin.list_app_clients()


def test_admin_create_app_client_sends_admin_header_and_body(
    admin_client: KnucklesClient, mocked_responses: responses.RequestsMock
) -> None:
    """``admin.create_app_client`` POSTs with X-Admin-Token only."""
    mocked_responses.post(
        f"{BASE_URL}/v1/admin/app-clients",
        status=201,
        json={
            "data": {
                "client_id": "new-app",
                "app_name": "New App",
                "client_secret": "one-time-secret",
            }
        },
    )
    out = admin_client.admin.create_app_client(
        client_id="new-app",
        app_name="New App",
        allowed_origins=["https://new-app.example.com"],
    )
    assert out["client_secret"] == "one-time-secret"
    call = mocked_responses.calls[0]
    _assert_admin_headers(call)
    assert _request_json(call) == {
        "client_id": "new-app",
        "app_name": "New App",
        "allowed_origins": ["https://new-app.example.com"],
    }


def test_admin_create_app_client_omits_origins_when_not_passed(
    admin_client: KnucklesClient, mocked_responses: responses.RequestsMock
) -> None:
    """``allowed_origins`` is left out of the body when not supplied."""
    mocked_responses.post(
        f"{BASE_URL}/v1/admin/app-clients",
        status=201,
        json={"data": {"client_id": "new-app", "client_secret": "s"}},
    )
    admin_client.admin.create_app_client(client_id="new-app", app_name="New App")
    assert _request_json(mocked_responses.calls[0]) == {
        "client_id": "new-app",
        "app_name": "New App",
    }


def test_admin_list_app_clients_returns_rows(
    admin_client: KnucklesClient, mocked_responses: responses.RequestsMock
) -> None:
    """``admin.list_app_clients`` returns the rows from ``data``."""
    mocked_responses.get(
        f"{BASE_URL}/v1/admin/app-clients",
        status=200,
        json={"data": [{"client_id": "my-app", "app_name": "My App"}]},
    )
    rows = admin_client.admin.list_app_clients()
    assert rows[0]["client_id"] == "my-app"
    _assert_admin_headers(mocked_responses.calls[0])


def test_admin_get_app_client_hits_id_path(
    admin_client: KnucklesClient, mocked_responses: responses.RequestsMock
) -> None:
    """``admin.get_app_client`` GETs the id-specific path."""
    mocked_responses.get(
        f"{BASE_URL}/v1/admin/app-clients/my-app",
        status=200,
        json={"data": {"client_id": "my-app", "app_name": "My App"}},
    )
    out = admin_client.admin.get_app_client("my-app")
    assert out["app_name"] == "My App"
    _assert_admin_headers(mocked_responses.calls[0])


def test_admin_update_app_client_passes_fields_through(
    admin_client: KnucklesClient, mocked_responses: responses.RequestsMock
) -> None:
    """``admin.update_app_client`` PATCHes the kwargs verbatim."""
    mocked_responses.patch(
        f"{BASE_URL}/v1/admin/app-clients/my-app",
        status=200,
        json={"data": {"client_id": "my-app", "app_name": "Renamed"}},
    )
    out = admin_client.admin.update_app_client(
        "my-app", app_name="Renamed", resend_from_email="auth@my-app.com"
    )
    assert out["app_name"] == "Renamed"
    assert _request_json(mocked_responses.calls[0]) == {
        "app_name": "Renamed",
        "resend_from_email": "auth@my-app.com",
    }


def test_admin_rotate_secret_returns_new_secret(
    admin_client: KnucklesClient, mocked_responses: responses.RequestsMock
) -> None:
    """``admin.rotate_secret`` POSTs the rotate path, returns the secret."""
    mocked_responses.post(
        f"{BASE_URL}/v1/admin/app-clients/my-app/rotate-secret",
        status=200,
        json={"data": {"client_id": "my-app", "client_secret": "rotated"}},
    )
    out = admin_client.admin.rotate_secret("my-app")
    assert out["client_secret"] == "rotated"
    _assert_admin_headers(mocked_responses.calls[0])


def test_admin_set_origins_puts_full_list(
    admin_client: KnucklesClient, mocked_responses: responses.RequestsMock
) -> None:
    """``admin.set_origins`` PUTs the complete origins list."""
    mocked_responses.put(
        f"{BASE_URL}/v1/admin/app-clients/my-app/origins",
        status=200,
        json={"data": {"client_id": "my-app", "allowed_origins": ["https://a"]}},
    )
    out = admin_client.admin.set_origins("my-app", ["https://a"])
    assert out["allowed_origins"] == ["https://a"]
    call = mocked_responses.calls[0]
    _assert_admin_headers(call)
    assert _request_json(call) == {"allowed_origins": ["https://a"]}

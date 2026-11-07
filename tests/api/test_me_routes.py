"""HTTP-layer tests for the ``/v1/me`` self-service endpoints.

Covers:

* ``PATCH /v1/me`` — profile update (display name + avatar URL) with
  sentinel-based absent-vs-null semantics and strict body validation.
* ``DELETE /v1/me`` — account deletion: revokes sessions, deletes the
  user's magic-link rows, removes the user row (FK cascades).
* ``GET /v1/me/providers`` / ``DELETE /v1/me/providers/<provider>`` —
  OAuth provider visibility without ever leaking provider secrets.
* ``POST /v1/me/email/start`` / ``POST /v1/me/email/verify`` — the
  two-step verified email-change flow, including the EMAIL_IN_USE
  conflict, rate limiting, and the purpose check that keeps an
  email-change token from being redeemed as a sign-in.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from flask.testing import FlaskClient
from sqlalchemy.orm import Session

import knuckles.services.magic_link as magic_link_service_mod
from knuckles.core.jwt import issue_access_token
from knuckles.core.rate_limit import magic_link_limiter
from knuckles.data.models import MagicLinkToken, OAuthProvider, RefreshToken, User
from knuckles.data.repositories import auth as repo
from knuckles.services import tokens


def _bearer_for(user_id: str, app_client_id: str) -> dict[str, str]:
    """Build an ``Authorization: Bearer`` header for a user.

    Args:
        user_id: UUID string to embed as ``sub``.
        app_client_id: ``aud`` claim to embed.

    Returns:
        Header dict suitable for the test client.
    """
    token = issue_access_token(user_id=user_id, app_client_id=app_client_id)
    return {"Authorization": f"Bearer {token}"}


def _client_headers(creds: tuple[str, str]) -> dict[str, str]:
    """Build ``X-Client-*`` headers from the ``app_client_creds`` fixture.

    Args:
        creds: Tuple of (client_id, plaintext secret).

    Returns:
        Header dict carrying the app-client credentials.
    """
    client_id, secret = creds
    return {"X-Client-Id": client_id, "X-Client-Secret": secret}


def _dual_headers(creds: tuple[str, str], user_id: str) -> dict[str, str]:
    """Combine client headers and a bearer token pinned to the same tenant.

    Args:
        creds: Tuple of (client_id, plaintext secret).
        user_id: UUID string of the bearer user.

    Returns:
        Header dict with both auth mechanisms.
    """
    return {**_client_headers(creds), **_bearer_for(user_id, creds[0])}


def _register_second_client(db_session: Session) -> tuple[str, str]:
    """Register a second app client to model tenant B.

    Args:
        db_session: Active SQLAlchemy session.

    Returns:
        Tuple of (client_id, plaintext secret) for the second tenant.
    """
    client_id = "other-app"
    secret = "other-secret"
    repo.create_app_client(
        db_session,
        client_id=client_id,
        app_name="Other App",
        client_secret_hash=hashlib.sha256(secret.encode("ascii")).hexdigest(),
        allowed_origins=["http://localhost:4000"],
    )
    return client_id, secret


class _SilentSender:
    """Email backend that drops every send."""

    def send(
        self,
        *,
        to: str,
        subject: str,
        body: str,
        from_name: str | None = None,
    ) -> None:
        """Discard the outbound email.

        Args:
            to: Recipient address (ignored).
            subject: Subject line (ignored).
            body: Email body (ignored).
            from_name: Optional display name (ignored).
        """
        return None


def _silence_email(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace the default email sender factory with a silent fake.

    Args:
        monkeypatch: pytest's monkeypatch helper.
    """
    monkeypatch.setattr(
        magic_link_service_mod,
        "get_default_sender",
        lambda api_key=None, from_address=None: _SilentSender(),
    )


def _make_user(db_session: Session, email: str = "user@example.com") -> User:
    """Create a user row for route tests.

    Args:
        db_session: Active SQLAlchemy session.
        email: Email address for the new user.

    Returns:
        The created ``User``.
    """
    return repo.create_user(db_session, email=email)


# ---------------------------------------------------------------------------
# PATCH /v1/me
# ---------------------------------------------------------------------------


def test_patch_me_updates_display_name_and_avatar(
    client: FlaskClient,
    db_session: Session,
    app_client_creds: tuple[str, str],
) -> None:
    """Both fields can be set in one request; response mirrors GET /v1/me."""
    user = _make_user(db_session)
    response = client.patch(
        "/v1/me",
        json={
            "display_name": "Knuckles Fan",
            "avatar_url": "https://cdn.example.com/me.png",
        },
        headers=_dual_headers(app_client_creds, str(user.id)),
    )
    assert response.status_code == 200
    data = response.get_json()["data"]
    assert data["id"] == str(user.id)
    assert data["email"] == "user@example.com"
    assert data["display_name"] == "Knuckles Fan"
    assert data["avatar_url"] == "https://cdn.example.com/me.png"
    assert data["app_client_id"] == app_client_creds[0]
    assert user.display_name == "Knuckles Fan"
    assert user.avatar_url == "https://cdn.example.com/me.png"


def test_patch_me_null_clears_fields(
    client: FlaskClient,
    db_session: Session,
    app_client_creds: tuple[str, str],
) -> None:
    """Explicit JSON null clears a previously set value."""
    user = _make_user(db_session)
    user.display_name = "Old Name"
    user.avatar_url = "https://cdn.example.com/old.png"
    db_session.flush()

    response = client.patch(
        "/v1/me",
        json={"display_name": None, "avatar_url": None},
        headers=_dual_headers(app_client_creds, str(user.id)),
    )
    assert response.status_code == 200
    assert user.display_name is None
    assert user.avatar_url is None


def test_patch_me_absent_field_is_left_untouched(
    client: FlaskClient,
    db_session: Session,
    app_client_creds: tuple[str, str],
) -> None:
    """A key absent from the body keeps its current value (sentinel test)."""
    user = _make_user(db_session)
    user.avatar_url = "https://cdn.example.com/keep.png"
    db_session.flush()

    response = client.patch(
        "/v1/me",
        json={"display_name": "Only Name"},
        headers=_dual_headers(app_client_creds, str(user.id)),
    )
    assert response.status_code == 200
    assert user.display_name == "Only Name"
    assert user.avatar_url == "https://cdn.example.com/keep.png"


def test_patch_me_rejects_unknown_keys(
    client: FlaskClient,
    db_session: Session,
    app_client_creds: tuple[str, str],
) -> None:
    """Unknown body keys are a 422, not silently ignored."""
    user = _make_user(db_session)
    response = client.patch(
        "/v1/me",
        json={"display_name": "ok", "email": "sneaky@example.com"},
        headers=_dual_headers(app_client_creds, str(user.id)),
    )
    assert response.status_code == 422
    assert response.get_json()["error"]["code"] == "VALIDATION_ERROR"
    assert user.email == "user@example.com"


def test_patch_me_requires_at_least_one_known_key(
    client: FlaskClient,
    db_session: Session,
    app_client_creds: tuple[str, str],
) -> None:
    """An empty body is rejected with 422."""
    user = _make_user(db_session)
    response = client.patch(
        "/v1/me",
        json={},
        headers=_dual_headers(app_client_creds, str(user.id)),
    )
    assert response.status_code == 422


def test_patch_me_rejects_overlong_display_name(
    client: FlaskClient,
    db_session: Session,
    app_client_creds: tuple[str, str],
) -> None:
    """A display name longer than 200 characters is a 422."""
    user = _make_user(db_session)
    response = client.patch(
        "/v1/me",
        json={"display_name": "x" * 201},
        headers=_dual_headers(app_client_creds, str(user.id)),
    )
    assert response.status_code == 422
    assert user.display_name is None


def test_patch_me_rejects_overlong_avatar_url(
    client: FlaskClient,
    db_session: Session,
    app_client_creds: tuple[str, str],
) -> None:
    """An avatar URL longer than 500 characters is a 422."""
    user = _make_user(db_session)
    response = client.patch(
        "/v1/me",
        json={"avatar_url": "https://example.com/" + "a" * 490},
        headers=_dual_headers(app_client_creds, str(user.id)),
    )
    assert response.status_code == 422


def test_patch_me_rejects_non_http_avatar_url(
    client: FlaskClient,
    db_session: Session,
    app_client_creds: tuple[str, str],
) -> None:
    """Avatar URLs must be absolute http(s) URLs — no javascript: etc."""
    user = _make_user(db_session)
    for bad in ("javascript:alert(1)", "ftp://example.com/a.png", "not a url"):
        response = client.patch(
            "/v1/me",
            json={"avatar_url": bad},
            headers=_dual_headers(app_client_creds, str(user.id)),
        )
        assert response.status_code == 422, bad
    assert user.avatar_url is None


def test_patch_me_rejects_non_string_values(
    client: FlaskClient,
    db_session: Session,
    app_client_creds: tuple[str, str],
) -> None:
    """A non-string, non-null value is a 422."""
    user = _make_user(db_session)
    response = client.patch(
        "/v1/me",
        json={"display_name": 42},
        headers=_dual_headers(app_client_creds, str(user.id)),
    )
    assert response.status_code == 422


def test_patch_me_rejects_cross_tenant_token(
    client: FlaskClient,
    db_session: Session,
    app_client_creds: tuple[str, str],
) -> None:
    """Tenant B's client credentials cannot use tenant A's user token."""
    other_creds = _register_second_client(db_session)
    user = _make_user(db_session)
    headers = {
        **_client_headers(other_creds),
        **_bearer_for(str(user.id), app_client_creds[0]),
    }
    response = client.patch("/v1/me", json={"display_name": "x"}, headers=headers)
    assert response.status_code == 401
    assert response.get_json()["error"]["code"] == "INVALID_TOKEN"


# ---------------------------------------------------------------------------
# DELETE /v1/me
# ---------------------------------------------------------------------------


def test_delete_me_removes_user_sessions_and_magic_links(
    client: FlaskClient,
    db_session: Session,
    app_client_creds: tuple[str, str],
) -> None:
    """Deletion is account-wide: every tenant's sessions and the user go."""
    other_id, _ = _register_second_client(db_session)
    client_id, _ = app_client_creds
    user = _make_user(db_session, email="leaving@example.com")
    tokens.issue_session(db_session, user_id=user.id, app_client_id=client_id)
    tokens.issue_session(db_session, user_id=user.id, app_client_id=other_id)
    repo.create_magic_link_token(
        db_session,
        email="leaving@example.com",
        token_hash="hash-leaving",
        expires_at=datetime.now(tz=UTC) + timedelta(minutes=10),
        app_client_id=client_id,
    )
    # An unrelated user's rows must survive.
    bystander = _make_user(db_session, email="stays@example.com")
    tokens.issue_session(db_session, user_id=bystander.id, app_client_id=client_id)
    repo.create_magic_link_token(
        db_session,
        email="stays@example.com",
        token_hash="hash-stays",
        expires_at=datetime.now(tz=UTC) + timedelta(minutes=10),
        app_client_id=client_id,
    )

    response = client.delete(
        "/v1/me", headers=_dual_headers(app_client_creds, str(user.id))
    )
    assert response.status_code == 204

    assert repo.get_user_by_email(db_session, "leaving@example.com") is None
    remaining_tokens = db_session.query(RefreshToken).all()
    assert {row.user_id for row in remaining_tokens} == {bystander.id}
    remaining_links = db_session.query(MagicLinkToken).all()
    assert [row.email for row in remaining_links] == ["stays@example.com"]


def test_delete_me_then_get_me_returns_user_not_found(
    client: FlaskClient,
    db_session: Session,
    app_client_creds: tuple[str, str],
) -> None:
    """The still-valid access token maps to no user after deletion."""
    user = _make_user(db_session)
    headers = _dual_headers(app_client_creds, str(user.id))

    response = client.delete("/v1/me", headers=headers)
    assert response.status_code == 204

    response = client.get("/v1/me", headers=headers)
    assert response.status_code == 404
    assert response.get_json()["error"]["code"] == "USER_NOT_FOUND"


def test_delete_me_rejects_cross_tenant_token(
    client: FlaskClient,
    db_session: Session,
    app_client_creds: tuple[str, str],
) -> None:
    """Tenant B cannot delete a user with tenant A's access token."""
    other_creds = _register_second_client(db_session)
    user = _make_user(db_session)
    headers = {
        **_client_headers(other_creds),
        **_bearer_for(str(user.id), app_client_creds[0]),
    }
    response = client.delete("/v1/me", headers=headers)
    assert response.status_code == 401
    assert repo.get_user_by_id(db_session, user.id) is not None


# ---------------------------------------------------------------------------
# GET /v1/me/providers + DELETE /v1/me/providers/<provider>
# ---------------------------------------------------------------------------


def test_list_providers_returns_safe_fields(
    client: FlaskClient,
    db_session: Session,
    app_client_creds: tuple[str, str],
) -> None:
    """The list carries provider, created_at, and scopes — nothing else."""
    user = _make_user(db_session)
    repo.create_oauth_provider(
        db_session,
        user_id=user.id,
        provider=OAuthProvider.GOOGLE,
        provider_user_id="google-uid-123456",
        scopes="openid email",
    )
    response = client.get(
        "/v1/me/providers", headers=_dual_headers(app_client_creds, str(user.id))
    )
    assert response.status_code == 200
    data = response.get_json()["data"]
    assert len(data) == 1
    assert data[0]["provider"] == "google"
    assert data[0]["scopes"] == "openid email"
    assert data[0]["created_at"]
    assert set(data[0].keys()) == {"provider", "created_at", "scopes"}


def test_list_providers_never_leaks_provider_secrets(
    client: FlaskClient,
    db_session: Session,
    app_client_creds: tuple[str, str],
) -> None:
    """Tokens, raw profile, and provider user id never appear in the body."""
    user = _make_user(db_session)
    repo.create_oauth_provider(
        db_session,
        user_id=user.id,
        provider=OAuthProvider.GOOGLE,
        provider_user_id="google-uid-secret-123",
        access_token="provider-access-token-secret",
        refresh_token="provider-refresh-token-secret",
        scopes="openid email",
        raw_profile={"name": "Raw Profile Name"},
    )
    response = client.get(
        "/v1/me/providers", headers=_dual_headers(app_client_creds, str(user.id))
    )
    assert response.status_code == 200
    text = response.get_data(as_text=True)
    for forbidden in (
        "provider-access-token-secret",
        "provider-refresh-token-secret",
        "google-uid-secret-123",
        "Raw Profile Name",
        "access_token",
        "refresh_token",
        "raw_profile",
        "provider_user_id",
    ):
        assert forbidden not in text, forbidden


def test_delete_provider_removes_link(
    client: FlaskClient,
    db_session: Session,
    app_client_creds: tuple[str, str],
) -> None:
    """Unlinking a connected provider returns 204 and removes the row."""
    user = _make_user(db_session)
    repo.create_oauth_provider(
        db_session,
        user_id=user.id,
        provider=OAuthProvider.GOOGLE,
        provider_user_id="uid-1",
    )
    response = client.delete(
        "/v1/me/providers/google",
        headers=_dual_headers(app_client_creds, str(user.id)),
    )
    assert response.status_code == 204
    assert repo.get_oauth_provider(db_session, OAuthProvider.GOOGLE, "uid-1") is None


def test_delete_provider_rejects_unknown_provider_name(
    client: FlaskClient,
    db_session: Session,
    app_client_creds: tuple[str, str],
) -> None:
    """A provider outside google|apple is a 404 PROVIDER_NOT_FOUND."""
    user = _make_user(db_session)
    response = client.delete(
        "/v1/me/providers/spotify",
        headers=_dual_headers(app_client_creds, str(user.id)),
    )
    assert response.status_code == 404
    assert response.get_json()["error"]["code"] == "PROVIDER_NOT_FOUND"


def test_delete_provider_absent_link_returns_404(
    client: FlaskClient,
    db_session: Session,
    app_client_creds: tuple[str, str],
) -> None:
    """A valid provider with no link for this user is a 404."""
    user = _make_user(db_session)
    response = client.delete(
        "/v1/me/providers/apple",
        headers=_dual_headers(app_client_creds, str(user.id)),
    )
    assert response.status_code == 404
    assert response.get_json()["error"]["code"] == "PROVIDER_NOT_FOUND"


def test_delete_provider_cannot_touch_other_users_link(
    client: FlaskClient,
    db_session: Session,
    app_client_creds: tuple[str, str],
) -> None:
    """The deletion is scoped by user — another user's link survives."""
    user = _make_user(db_session)
    other = _make_user(db_session, email="other@example.com")
    repo.create_oauth_provider(
        db_session,
        user_id=other.id,
        provider=OAuthProvider.GOOGLE,
        provider_user_id="uid-other",
    )
    response = client.delete(
        "/v1/me/providers/google",
        headers=_dual_headers(app_client_creds, str(user.id)),
    )
    assert response.status_code == 404
    assert (
        repo.get_oauth_provider(db_session, OAuthProvider.GOOGLE, "uid-other")
        is not None
    )


# ---------------------------------------------------------------------------
# POST /v1/me/email/start
# ---------------------------------------------------------------------------


def test_email_change_start_returns_202_and_persists_row(
    client: FlaskClient,
    db_session: Session,
    app_client_creds: tuple[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Starting an email change writes a purpose-tagged row and returns 202."""
    _silence_email(monkeypatch)
    user = _make_user(db_session)
    response = client.post(
        "/v1/me/email/start",
        json={
            "new_email": "fresh@example.com",
            "redirect_url": "http://localhost:3000/settings/email/verify",
        },
        headers=_dual_headers(app_client_creds, str(user.id)),
    )
    assert response.status_code == 202
    row = db_session.query(MagicLinkToken).one()
    assert row.purpose == "email_change"
    assert row.email == "fresh@example.com"
    assert row.user_id == user.id
    assert row.app_client_id == app_client_creds[0]


def test_email_change_start_rejects_invalid_email(
    client: FlaskClient,
    db_session: Session,
    app_client_creds: tuple[str, str],
) -> None:
    """A new_email without an @ is a 422."""
    user = _make_user(db_session)
    response = client.post(
        "/v1/me/email/start",
        json={
            "new_email": "not-an-email",
            "redirect_url": "http://localhost:3000/settings/email/verify",
        },
        headers=_dual_headers(app_client_creds, str(user.id)),
    )
    assert response.status_code == 422


def test_email_change_start_rejects_unregistered_redirect(
    client: FlaskClient,
    db_session: Session,
    app_client_creds: tuple[str, str],
) -> None:
    """A redirect outside the app-client's allowed origins is a 422."""
    user = _make_user(db_session)
    response = client.post(
        "/v1/me/email/start",
        json={
            "new_email": "fresh@example.com",
            "redirect_url": "http://evil.example.com/steal",
        },
        headers=_dual_headers(app_client_creds, str(user.id)),
    )
    assert response.status_code == 422


def test_email_change_start_rate_limited(
    client: FlaskClient,
    db_session: Session,
    app_client_creds: tuple[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exhausting the per-email budget returns 429 with Retry-After."""
    _silence_email(monkeypatch)
    user = _make_user(db_session)
    bucket = f"{app_client_creds[0]}:fresh@example.com"
    for _ in range(5):
        assert magic_link_limiter.allow(bucket)

    response = client.post(
        "/v1/me/email/start",
        json={
            "new_email": "Fresh@Example.com",
            "redirect_url": "http://localhost:3000/settings/email/verify",
        },
        headers=_dual_headers(app_client_creds, str(user.id)),
    )
    assert response.status_code == 429
    assert response.get_json()["error"]["code"] == "RATE_LIMITED"
    retry_after = response.headers.get("Retry-After")
    assert retry_after is not None and int(retry_after) > 0


def test_email_change_start_requires_bearer(
    client: FlaskClient,
    db_session: Session,
    app_client_creds: tuple[str, str],
) -> None:
    """Client headers alone are not enough — a bearer is required."""
    response = client.post(
        "/v1/me/email/start",
        json={
            "new_email": "fresh@example.com",
            "redirect_url": "http://localhost:3000/settings/email/verify",
        },
        headers=_client_headers(app_client_creds),
    )
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# POST /v1/me/email/verify
# ---------------------------------------------------------------------------


def _create_email_change_row(
    db_session: Session,
    *,
    raw_token: str,
    user_id: uuid.UUID,
    new_email: str,
    app_client_id: str,
) -> MagicLinkToken:
    """Persist a redeemable email-change row for a known raw token.

    Args:
        db_session: Active SQLAlchemy session.
        raw_token: Plaintext token whose hash is stored.
        user_id: UUID of the user changing their email.
        new_email: Address the change targets.
        app_client_id: Issuing tenant.

    Returns:
        The created ``MagicLinkToken`` row.
    """
    return repo.create_magic_link_token(
        db_session,
        email=new_email,
        token_hash=hashlib.sha256(raw_token.encode("ascii")).hexdigest(),
        expires_at=datetime.now(tz=UTC) + timedelta(minutes=10),
        user_id=user_id,
        app_client_id=app_client_id,
        purpose="email_change",
    )


def test_email_change_verify_updates_email(
    client: FlaskClient,
    db_session: Session,
    app_client_creds: tuple[str, str],
) -> None:
    """Verifying the token rewrites the user's email and returns it."""
    user = _make_user(db_session, email="old@example.com")
    _create_email_change_row(
        db_session,
        raw_token="raw-change-token",
        user_id=user.id,
        new_email="new@example.com",
        app_client_id=app_client_creds[0],
    )
    response = client.post(
        "/v1/me/email/verify",
        json={"token": "raw-change-token"},
        headers=_client_headers(app_client_creds),
    )
    assert response.status_code == 200
    assert response.get_json()["data"] == {"email": "new@example.com"}
    assert user.email == "new@example.com"


def test_email_change_verify_conflict_returns_409(
    client: FlaskClient,
    db_session: Session,
    app_client_creds: tuple[str, str],
) -> None:
    """A new email already owned by another user is a 409 EMAIL_IN_USE."""
    user = _make_user(db_session, email="old@example.com")
    _make_user(db_session, email="taken@example.com")
    _create_email_change_row(
        db_session,
        raw_token="raw-conflict-token",
        user_id=user.id,
        new_email="taken@example.com",
        app_client_id=app_client_creds[0],
    )
    response = client.post(
        "/v1/me/email/verify",
        json={"token": "raw-conflict-token"},
        headers=_client_headers(app_client_creds),
    )
    assert response.status_code == 409
    assert response.get_json()["error"]["code"] == "EMAIL_IN_USE"
    assert user.email == "old@example.com"


def test_email_change_token_rejected_by_sign_in_verify(
    client: FlaskClient,
    db_session: Session,
    app_client_creds: tuple[str, str],
) -> None:
    """An email-change token cannot be redeemed on the sign-in verify route.

    Without the purpose check the token would mint a session for a
    not-yet-existing user at the new address.
    """
    user = _make_user(db_session, email="old@example.com")
    _create_email_change_row(
        db_session,
        raw_token="raw-cross-purpose",
        user_id=user.id,
        new_email="new@example.com",
        app_client_id=app_client_creds[0],
    )
    response = client.post(
        "/v1/auth/magic-link/verify",
        json={"token": "raw-cross-purpose"},
        headers=_client_headers(app_client_creds),
    )
    assert response.status_code == 400
    assert response.get_json()["error"]["code"] == "MAGIC_LINK_INVALID"
    assert repo.get_user_by_email(db_session, "new@example.com") is None

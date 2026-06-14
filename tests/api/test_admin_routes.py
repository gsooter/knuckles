"""Tests for the ``/v1/admin/app-clients`` provisioning surface.

Covers all six admin routes: create, list, get, patch (tenant config),
rotate-secret, and origins replacement — including the redaction
guarantee (encrypted columns never appear as plaintext in any response
body) and the ``webauthn_rp_id`` guardrail.
"""

from __future__ import annotations

import hashlib

import pytest
from flask.testing import FlaskClient
from sqlalchemy.orm import Session

from knuckles.data.repositories import auth as repo

_ADMIN_TOKEN = "admin-route-test-token"


@pytest.fixture()
def admin_headers(monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    """Enable the admin surface and return matching request headers.

    Args:
        monkeypatch: pytest's monkeypatch helper.

    Returns:
        Headers carrying the configured ``X-Admin-Token``.
    """
    monkeypatch.setenv("KNUCKLES_ADMIN_TOKEN", _ADMIN_TOKEN)
    return {"X-Admin-Token": _ADMIN_TOKEN}


def _create_client_row(
    db_session: Session,
    *,
    client_id: str = "acme-prod",
    app_name: str = "Acme",
    secret: str = "acme-secret",
) -> str:
    """Insert an ``app_clients`` row directly via the repository.

    Args:
        db_session: Active SQLAlchemy session.
        client_id: Client id for the new row.
        app_name: App name for the new row.
        secret: Plaintext secret whose SHA-256 hash is stored.

    Returns:
        The ``client_id`` of the inserted row.
    """
    repo.create_app_client(
        db_session,
        client_id=client_id,
        app_name=app_name,
        client_secret_hash=hashlib.sha256(secret.encode("utf-8")).hexdigest(),
        allowed_origins=["http://localhost:3000"],
    )
    return client_id


# ---------------------------------------------------------------------------
# Auth gate
# ---------------------------------------------------------------------------


def test_admin_routes_404_when_disabled(
    client: FlaskClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With no admin token configured the surface does not exist."""
    monkeypatch.delenv("KNUCKLES_ADMIN_TOKEN", raising=False)

    response = client.get(
        "/v1/admin/app-clients", headers={"X-Admin-Token": "whatever"}
    )

    assert response.status_code == 404
    assert response.get_json()["error"]["code"] == "NOT_FOUND"


def test_admin_routes_401_without_token(
    client: FlaskClient, admin_headers: dict[str, str]
) -> None:
    """A configured admin surface rejects requests missing the header."""
    response = client.get("/v1/admin/app-clients")

    assert response.status_code == 401
    assert response.get_json()["error"]["code"] == "UNAUTHORIZED"


# ---------------------------------------------------------------------------
# POST /v1/admin/app-clients (create)
# ---------------------------------------------------------------------------


def test_create_app_client_returns_secret_once(
    client: FlaskClient, db_session: Session, admin_headers: dict[str, str]
) -> None:
    """Create returns 201, the plaintext secret, and persists the row."""
    response = client.post(
        "/v1/admin/app-clients",
        headers=admin_headers,
        json={
            "client_id": "acme-prod",
            "app_name": "Acme",
            "allowed_origins": ["http://localhost:3000"],
        },
    )

    assert response.status_code == 201
    data = response.get_json()["data"]
    assert data["client_id"] == "acme-prod"
    assert data["app_name"] == "Acme"
    assert data["allowed_origins"] == ["http://localhost:3000"]
    secret = data["client_secret"]
    assert isinstance(secret, str) and len(secret) > 32

    row = repo.get_app_client(db_session, "acme-prod")
    assert row is not None
    expected = hashlib.sha256(secret.encode("ascii")).hexdigest()
    assert row.client_secret_hash == expected


def test_create_app_client_defaults_origins_empty(
    client: FlaskClient, db_session: Session, admin_headers: dict[str, str]
) -> None:
    """Omitting ``allowed_origins`` registers an empty list."""
    response = client.post(
        "/v1/admin/app-clients",
        headers=admin_headers,
        json={"client_id": "acme-prod", "app_name": "Acme"},
    )

    assert response.status_code == 201
    assert response.get_json()["data"]["allowed_origins"] == []


def test_create_app_client_duplicate_client_id_422(
    client: FlaskClient, db_session: Session, admin_headers: dict[str, str]
) -> None:
    """A second registration of the same client_id is rejected."""
    _create_client_row(db_session)

    response = client.post(
        "/v1/admin/app-clients",
        headers=admin_headers,
        json={"client_id": "acme-prod", "app_name": "Other"},
    )

    assert response.status_code == 422
    assert response.get_json()["error"]["code"] == "VALIDATION_ERROR"


def test_create_app_client_duplicate_app_name_422(
    client: FlaskClient, db_session: Session, admin_headers: dict[str, str]
) -> None:
    """A second registration reusing an existing app_name is rejected."""
    _create_client_row(db_session, client_id="acme-prod", app_name="Acme")

    response = client.post(
        "/v1/admin/app-clients",
        headers=admin_headers,
        json={"client_id": "acme-staging", "app_name": "Acme"},
    )

    assert response.status_code == 422
    assert response.get_json()["error"]["code"] == "VALIDATION_ERROR"


@pytest.mark.parametrize(
    "bad_client_id",
    ["Bad_Id", "UPPER", "ab", "-leading-dash", "trailing-dash-", "has space", ""],
)
def test_create_app_client_bad_client_id_format_422(
    client: FlaskClient, admin_headers: dict[str, str], bad_client_id: str
) -> None:
    """Malformed client ids are rejected with a validation error."""
    response = client.post(
        "/v1/admin/app-clients",
        headers=admin_headers,
        json={"client_id": bad_client_id, "app_name": "Acme"},
    )

    assert response.status_code == 422
    assert response.get_json()["error"]["code"] == "VALIDATION_ERROR"


def test_create_app_client_missing_app_name_422(
    client: FlaskClient, admin_headers: dict[str, str]
) -> None:
    """Missing app_name is a validation error."""
    response = client.post(
        "/v1/admin/app-clients",
        headers=admin_headers,
        json={"client_id": "acme-prod"},
    )

    assert response.status_code == 422


# ---------------------------------------------------------------------------
# GET /v1/admin/app-clients (list) + GET one — redaction
# ---------------------------------------------------------------------------


def test_list_app_clients_ordered_and_redacted(
    client: FlaskClient, db_session: Session, admin_headers: dict[str, str]
) -> None:
    """List returns every row ordered by client_id with secrets redacted."""
    _create_client_row(db_session, client_id="zeta-prod", app_name="Zeta")
    _create_client_row(db_session, client_id="acme-prod", app_name="Acme")
    repo.update_app_client_config(
        db_session,
        client_id="acme-prod",
        resend_api_key="rk_super_secret_value",
        resend_from_email="Acme <signin@acme.test>",
    )

    response = client.get("/v1/admin/app-clients", headers=admin_headers)

    assert response.status_code == 200
    data = response.get_json()["data"]
    assert [c["client_id"] for c in data] == ["acme-prod", "zeta-prod"]

    acme = data[0]
    # Non-secret tenant config is visible in plaintext.
    assert acme["resend_from_email"] == "Acme <signin@acme.test>"
    # Encrypted columns appear only as booleans.
    assert acme["resend_api_key_configured"] is True
    assert acme["google_oauth_client_secret_configured"] is False
    assert acme["apple_oauth_private_key_configured"] is False
    assert "resend_api_key" not in acme
    assert "google_oauth_client_secret" not in acme
    assert "apple_oauth_private_key" not in acme
    assert "client_secret_hash" not in acme
    # The plaintext secret never appears anywhere in the body.
    assert "rk_super_secret_value" not in response.get_data(as_text=True)


def test_get_app_client_detail_redacted(
    client: FlaskClient, db_session: Session, admin_headers: dict[str, str]
) -> None:
    """Detail view returns the serialized row without secret plaintext."""
    _create_client_row(db_session)
    repo.update_app_client_config(
        db_session,
        client_id="acme-prod",
        resend_api_key="rk_super_secret_value",
    )

    response = client.get("/v1/admin/app-clients/acme-prod", headers=admin_headers)

    assert response.status_code == 200
    data = response.get_json()["data"]
    assert data["client_id"] == "acme-prod"
    assert data["resend_api_key_configured"] is True
    assert "rk_super_secret_value" not in response.get_data(as_text=True)


def test_get_app_client_unknown_404(
    client: FlaskClient, admin_headers: dict[str, str]
) -> None:
    """Looking up an unknown client_id is a 404."""
    response = client.get("/v1/admin/app-clients/nope", headers=admin_headers)

    assert response.status_code == 404
    assert response.get_json()["error"]["code"] == "APP_CLIENT_NOT_FOUND"


# ---------------------------------------------------------------------------
# PATCH /v1/admin/app-clients/<client_id> (tenant config)
# ---------------------------------------------------------------------------


def test_patch_sets_tenant_config_column(
    client: FlaskClient, db_session: Session, admin_headers: dict[str, str]
) -> None:
    """PATCH writes the column and echoes the serialized row."""
    _create_client_row(db_session)

    response = client.patch(
        "/v1/admin/app-clients/acme-prod",
        headers=admin_headers,
        json={"resend_from_email": "Acme <signin@acme.test>"},
    )

    assert response.status_code == 200
    assert response.get_json()["data"]["resend_from_email"] == "Acme <signin@acme.test>"
    row = repo.get_app_client(db_session, "acme-prod")
    assert row is not None
    assert row.resend_from_email == "Acme <signin@acme.test>"


@pytest.mark.parametrize("cleared_value", ["", None])
def test_patch_empty_string_and_null_clear_column(
    client: FlaskClient,
    db_session: Session,
    admin_headers: dict[str, str],
    cleared_value: str | None,
) -> None:
    """Both ``""`` and ``null`` clear the column back to NULL."""
    _create_client_row(db_session)
    repo.update_app_client_config(
        db_session, client_id="acme-prod", resend_from_email="old@acme.test"
    )

    response = client.patch(
        "/v1/admin/app-clients/acme-prod",
        headers=admin_headers,
        json={"resend_from_email": cleared_value},
    )

    assert response.status_code == 200
    assert response.get_json()["data"]["resend_from_email"] is None
    row = repo.get_app_client(db_session, "acme-prod")
    assert row is not None
    assert row.resend_from_email is None


def test_patch_secret_column_never_echoed(
    client: FlaskClient, db_session: Session, admin_headers: dict[str, str]
) -> None:
    """Setting an encrypted column returns only the configured boolean."""
    _create_client_row(db_session)

    response = client.patch(
        "/v1/admin/app-clients/acme-prod",
        headers=admin_headers,
        json={"google_oauth_client_secret": "GOCSPX-super-secret"},
    )

    assert response.status_code == 200
    data = response.get_json()["data"]
    assert data["google_oauth_client_secret_configured"] is True
    assert "GOCSPX-super-secret" not in response.get_data(as_text=True)


@pytest.mark.parametrize("field", ["client_secret_hash", "allowed_origins", "bogus"])
def test_patch_unknown_field_422(
    client: FlaskClient,
    db_session: Session,
    admin_headers: dict[str, str],
    field: str,
) -> None:
    """Fields outside the tenant-config allow-list are rejected."""
    _create_client_row(db_session)

    response = client.patch(
        "/v1/admin/app-clients/acme-prod",
        headers=admin_headers,
        json={field: "x"},
    )

    assert response.status_code == 422
    assert response.get_json()["error"]["code"] == "VALIDATION_ERROR"


def test_patch_empty_body_422(
    client: FlaskClient, db_session: Session, admin_headers: dict[str, str]
) -> None:
    """A PATCH with no updatable fields is a validation error."""
    _create_client_row(db_session)

    response = client.patch(
        "/v1/admin/app-clients/acme-prod", headers=admin_headers, json={}
    )

    assert response.status_code == 422


def test_patch_unknown_client_404(
    client: FlaskClient, admin_headers: dict[str, str]
) -> None:
    """PATCHing an unknown client is a 404."""
    response = client.patch(
        "/v1/admin/app-clients/nope",
        headers=admin_headers,
        json={"resend_from_email": "x@y.test"},
    )

    assert response.status_code == 404


def _setup_rp_id_with_passkey(db_session: Session) -> None:
    """Create a client with ``webauthn_rp_id`` set and one passkey row.

    Args:
        db_session: Active SQLAlchemy session.
    """
    _create_client_row(db_session)
    repo.update_app_client_config(
        db_session, client_id="acme-prod", webauthn_rp_id="acme.test"
    )
    user = repo.create_user(db_session, email="passkey-owner@acme.test")
    repo.create_passkey(
        db_session,
        user_id=user.id,
        credential_id="cred-1",
        public_key="pk-1",
        sign_count=0,
    )


def test_patch_rp_id_change_blocked_with_passkeys(
    client: FlaskClient, db_session: Session, admin_headers: dict[str, str]
) -> None:
    """Changing a set rp_id while passkeys exist is refused without force."""
    _setup_rp_id_with_passkey(db_session)

    response = client.patch(
        "/v1/admin/app-clients/acme-prod",
        headers=admin_headers,
        json={"webauthn_rp_id": "other.test"},
    )

    assert response.status_code == 422
    assert "passkey" in response.get_json()["error"]["message"].lower()
    row = repo.get_app_client(db_session, "acme-prod")
    assert row is not None
    assert row.webauthn_rp_id == "acme.test"


def test_patch_rp_id_change_allowed_with_force(
    client: FlaskClient, db_session: Session, admin_headers: dict[str, str]
) -> None:
    """``force_webauthn_rp_id`` overrides the guardrail."""
    _setup_rp_id_with_passkey(db_session)

    response = client.patch(
        "/v1/admin/app-clients/acme-prod",
        headers=admin_headers,
        json={"webauthn_rp_id": "other.test", "force_webauthn_rp_id": True},
    )

    assert response.status_code == 200
    assert response.get_json()["data"]["webauthn_rp_id"] == "other.test"
    row = repo.get_app_client(db_session, "acme-prod")
    assert row is not None
    assert row.webauthn_rp_id == "other.test"


def test_patch_rp_id_first_set_allowed_without_force(
    client: FlaskClient, db_session: Session, admin_headers: dict[str, str]
) -> None:
    """Setting rp_id for the first time (current NULL) needs no force."""
    _create_client_row(db_session)

    response = client.patch(
        "/v1/admin/app-clients/acme-prod",
        headers=admin_headers,
        json={"webauthn_rp_id": "acme.test"},
    )

    assert response.status_code == 200
    assert response.get_json()["data"]["webauthn_rp_id"] == "acme.test"


# ---------------------------------------------------------------------------
# POST /v1/admin/app-clients/<client_id>/rotate-secret
# ---------------------------------------------------------------------------


def test_rotate_secret_invalidates_old_and_enables_new(
    client: FlaskClient,
    db_session: Session,
    admin_headers: dict[str, str],
    app_client_creds: tuple[str, str],
) -> None:
    """The old secret stops authenticating and the new one works."""
    client_id, old_secret = app_client_creds

    # Old secret passes require_app_client (failure is the *refresh*
    # token, proving client auth succeeded).
    before = client.post(
        "/v1/token/refresh",
        headers={"X-Client-Id": client_id, "X-Client-Secret": old_secret},
        json={"refresh_token": "garbage"},
    )
    assert before.get_json()["error"]["code"] == "REFRESH_TOKEN_INVALID"

    response = client.post(
        f"/v1/admin/app-clients/{client_id}/rotate-secret", headers=admin_headers
    )
    assert response.status_code == 200
    data = response.get_json()["data"]
    assert data["client_id"] == client_id
    new_secret = data["client_secret"]
    assert isinstance(new_secret, str) and new_secret != old_secret

    after_old = client.post(
        "/v1/token/refresh",
        headers={"X-Client-Id": client_id, "X-Client-Secret": old_secret},
        json={"refresh_token": "garbage"},
    )
    assert after_old.status_code == 401
    assert after_old.get_json()["error"]["code"] == "INVALID_CLIENT"

    after_new = client.post(
        "/v1/token/refresh",
        headers={"X-Client-Id": client_id, "X-Client-Secret": new_secret},
        json={"refresh_token": "garbage"},
    )
    assert after_new.get_json()["error"]["code"] == "REFRESH_TOKEN_INVALID"


def test_rotate_secret_unknown_client_404(
    client: FlaskClient, admin_headers: dict[str, str]
) -> None:
    """Rotating an unknown client is a 404."""
    response = client.post(
        "/v1/admin/app-clients/nope/rotate-secret", headers=admin_headers
    )

    assert response.status_code == 404


# ---------------------------------------------------------------------------
# PUT /v1/admin/app-clients/<client_id>/origins
# ---------------------------------------------------------------------------


def test_put_origins_replaces_list(
    client: FlaskClient, db_session: Session, admin_headers: dict[str, str]
) -> None:
    """PUT replaces the entire allowed_origins list."""
    _create_client_row(db_session)

    response = client.put(
        "/v1/admin/app-clients/acme-prod/origins",
        headers=admin_headers,
        json={"allowed_origins": ["https://app.acme.test", "http://localhost:5173"]},
    )

    assert response.status_code == 200
    assert response.get_json()["data"]["allowed_origins"] == [
        "https://app.acme.test",
        "http://localhost:5173",
    ]
    row = repo.get_app_client(db_session, "acme-prod")
    assert row is not None
    assert row.allowed_origins == [
        "https://app.acme.test",
        "http://localhost:5173",
    ]


@pytest.mark.parametrize(
    "bad_origin", ["javascript:alert(1)", "not a url", "ftp://files.acme.test"]
)
def test_put_origins_invalid_origin_422(
    client: FlaskClient,
    db_session: Session,
    admin_headers: dict[str, str],
    bad_origin: str,
) -> None:
    """Origins that do not parse as http(s) origins are rejected."""
    _create_client_row(db_session)

    response = client.put(
        "/v1/admin/app-clients/acme-prod/origins",
        headers=admin_headers,
        json={"allowed_origins": [bad_origin]},
    )

    assert response.status_code == 422
    row = repo.get_app_client(db_session, "acme-prod")
    assert row is not None
    assert row.allowed_origins == ["http://localhost:3000"]


def test_put_origins_requires_list_of_strings(
    client: FlaskClient, db_session: Session, admin_headers: dict[str, str]
) -> None:
    """A non-list ``allowed_origins`` body is a validation error."""
    _create_client_row(db_session)

    response = client.put(
        "/v1/admin/app-clients/acme-prod/origins",
        headers=admin_headers,
        json={"allowed_origins": "https://app.acme.test"},
    )

    assert response.status_code == 422


def test_put_origins_unknown_client_404(
    client: FlaskClient, admin_headers: dict[str, str]
) -> None:
    """PUTting origins on an unknown client is a 404."""
    response = client.put(
        "/v1/admin/app-clients/nope/origins",
        headers=admin_headers,
        json={"allowed_origins": ["https://app.acme.test"]},
    )

    assert response.status_code == 404

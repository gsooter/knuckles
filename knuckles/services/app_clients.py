"""App-client provisioning service.

Backs both the admin HTTP API (``knuckles/api/v1/admin.py``) and the
operator CLIs (``scripts/register_app_client.py``,
``scripts/configure_app_client.py``) so registration, secret rotation,
origin management, and tenant-config updates run through exactly one
code path regardless of how the operator reaches them.

Security posture:

* Client secrets are generated here (``secrets.token_urlsafe(48)``)
  and only their SHA-256 hex digest is persisted. The plaintext is
  returned to the caller exactly once and never logged.
* :func:`serialize` is the single redaction seam — encrypted columns
  (Resend API key, Google client secret, Apple private key) are only
  ever exposed as ``<column>_configured`` booleans.
* Every mutation emits an audit line on the ``knuckles.audit`` logger
  carrying field names but never secret values.
"""

from __future__ import annotations

import hashlib
import logging
import re
import secrets

from sqlalchemy.orm import Session

from knuckles.core.app_client_auth import _origin_of
from knuckles.core.exceptions import NotFoundError, ValidationError
from knuckles.data.models import AppClient
from knuckles.data.repositories import auth as repo

_audit_log = logging.getLogger("knuckles.audit")

# Slug grammar for client ids: lowercase alphanumerics and hyphens,
# no leading/trailing hyphen, 3-64 characters total. The id lands in
# JWT ``aud`` claims and URLs, so it stays deliberately boring.
_CLIENT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$")

# Tenant-config columns safe to return in plaintext.
_NON_SECRET_CONFIG_COLUMNS: tuple[str, ...] = (
    "resend_from_email",
    "google_oauth_client_id",
    "apple_oauth_client_id",
    "apple_oauth_team_id",
    "apple_oauth_key_id",
    "webauthn_rp_id",
    "webauthn_rp_name",
    "webauthn_origin",
)

# Encrypted columns — never returned; only their configured-ness is.
_SECRET_CONFIG_COLUMNS: tuple[str, ...] = (
    "resend_api_key",
    "google_oauth_client_secret",
    "apple_oauth_private_key",
)


def _hash_secret(secret: str) -> str:
    """Return the SHA-256 hex digest of a plaintext client secret.

    Args:
        secret: The plaintext secret (``token_urlsafe`` output).

    Returns:
        The 64-character lowercase hex digest stored at rest.
    """
    return hashlib.sha256(secret.encode("ascii")).hexdigest()


def _normalize_origins(allowed_origins: list[str]) -> list[str]:
    """Canonicalize a list of origins, rejecting anything non-http(s).

    Reuses the same normalization :func:`require_app_client` applies
    when checking redirect URLs (default ports dropped, paths
    stripped) so stored origins always compare cleanly. Duplicates
    after normalization are collapsed, first occurrence wins.

    Args:
        allowed_origins: Raw origin strings from the operator.

    Returns:
        The canonicalized, de-duplicated origin list.

    Raises:
        ValidationError: If any entry does not parse as an absolute
            http(s) origin.
    """
    normalized: list[str] = []
    for raw in allowed_origins:
        origin = _origin_of(raw)
        if origin is None:
            raise ValidationError(
                f"{raw!r} is not a valid http(s) origin "
                "(expected scheme://host[:port])."
            )
        if origin not in normalized:
            normalized.append(origin)
    return normalized


def _require_client(session: Session, client_id: str) -> AppClient:
    """Load an ``AppClient`` or raise the canonical not-found error.

    Args:
        session: Active SQLAlchemy session.
        client_id: The ``app_clients.client_id`` to load.

    Returns:
        The matching ``AppClient`` row.

    Raises:
        NotFoundError: With code ``NOT_FOUND`` if no row matches.
    """
    client = repo.get_app_client(session, client_id)
    if client is None:
        raise NotFoundError(
            code="NOT_FOUND",
            message=f"No app client with client_id {client_id!r}.",
        )
    return client


def list_clients(session: Session) -> list[AppClient]:
    """Return every registered app client ordered by client id.

    Exists so the admin routes respect the layering rule (``api/``
    never imports ``data/`` directly).

    Args:
        session: Active SQLAlchemy session.

    Returns:
        All ``AppClient`` rows sorted by ``client_id``.
    """
    return repo.list_app_clients(session)


def get_client(session: Session, *, client_id: str) -> AppClient:
    """Load one app client or raise the canonical not-found error.

    Args:
        session: Active SQLAlchemy session.
        client_id: The ``app_clients.client_id`` to load.

    Returns:
        The matching ``AppClient`` row.

    Raises:
        NotFoundError: With code ``NOT_FOUND`` if no row matches.
    """
    return _require_client(session, client_id)


def register(
    session: Session,
    *,
    client_id: str,
    app_name: str,
    allowed_origins: list[str],
) -> tuple[AppClient, str]:
    """Register a new consuming app and mint its client secret.

    Args:
        session: Active SQLAlchemy session.
        client_id: Public client identifier (slug; becomes the JWT
            ``aud`` claim).
        app_name: Human-friendly application name (unique).
        allowed_origins: Origins the app may redirect to / run from.

    Returns:
        Tuple of the created ``AppClient`` row and the plaintext
        client secret. The plaintext is shown exactly once — only its
        SHA-256 hash is persisted.

    Raises:
        ValidationError: If the client_id is malformed, the app_name
            is blank, either collides with an existing row, or any
            origin fails to parse as an http(s) origin.
    """
    if not _CLIENT_ID_RE.match(client_id):
        raise ValidationError(
            "'client_id' must be 3-64 characters of lowercase letters, "
            "digits, and hyphens, with no leading or trailing hyphen."
        )
    if not app_name.strip():
        raise ValidationError("'app_name' must be a non-empty string.")
    if repo.get_app_client(session, client_id) is not None:
        raise ValidationError(
            f"An app client with client_id {client_id!r} already exists."
        )
    if any(c.app_name == app_name for c in repo.list_app_clients(session)):
        raise ValidationError(
            f"An app client with app_name {app_name!r} already exists."
        )

    origins = _normalize_origins(allowed_origins)
    plaintext_secret = secrets.token_urlsafe(48)
    client = repo.create_app_client(
        session,
        client_id=client_id,
        app_name=app_name,
        client_secret_hash=_hash_secret(plaintext_secret),
        allowed_origins=origins,
    )
    _audit_log.info(
        "app_client.register client_id=%s app_name=%s origins=%s",
        client_id,
        app_name,
        origins,
    )
    return client, plaintext_secret


def rotate_secret(session: Session, *, client_id: str) -> str:
    """Mint and store a fresh client secret for an existing tenant.

    Args:
        session: Active SQLAlchemy session.
        client_id: Target ``app_clients.client_id``.

    Returns:
        The new plaintext secret — shown exactly once; only its hash
        is persisted, so it cannot be recovered later.

    Raises:
        NotFoundError: With code ``NOT_FOUND`` if no row matches.
    """
    plaintext_secret = secrets.token_urlsafe(48)
    client = repo.rotate_app_client_secret(
        session, client_id, new_secret_hash=_hash_secret(plaintext_secret)
    )
    if client is None:
        raise NotFoundError(
            code="NOT_FOUND",
            message=f"No app client with client_id {client_id!r}.",
        )
    _audit_log.info("app_client.rotate_secret client_id=%s", client_id)
    return plaintext_secret


def set_origins(
    session: Session,
    *,
    client_id: str,
    allowed_origins: list[str],
) -> AppClient:
    """Replace the entire allowed-origins list for a tenant.

    Args:
        session: Active SQLAlchemy session.
        client_id: Target ``app_clients.client_id``.
        allowed_origins: The new complete list of origins.

    Returns:
        The updated ``AppClient`` row.

    Raises:
        ValidationError: If any origin fails to parse as http(s).
        NotFoundError: With code ``NOT_FOUND`` if no row matches.
    """
    origins = _normalize_origins(allowed_origins)
    client = repo.set_app_client_origins(session, client_id, allowed_origins=origins)
    if client is None:
        raise NotFoundError(
            code="NOT_FOUND",
            message=f"No app client with client_id {client_id!r}.",
        )
    _audit_log.info(
        "app_client.set_origins client_id=%s origins=%s", client_id, origins
    )
    return client


def update_config(
    session: Session,
    *,
    client_id: str,
    updates: dict[str, str | None],
    force_webauthn_rp_id: bool = False,
) -> AppClient:
    """Update per-tenant config columns with the rp_id guardrail.

    Args:
        session: Active SQLAlchemy session.
        client_id: Target ``app_clients.client_id``.
        updates: Column name → new value, or ``None`` to clear the
            column back to env-var fallback. Only the tenant-config
            allow-list in the repository is accepted.
        force_webauthn_rp_id: Acknowledge that changing (or clearing)
            an established ``webauthn_rp_id`` invalidates every
            passkey registered against the prior value.

    Returns:
        The updated ``AppClient`` row.

    Raises:
        NotFoundError: With code ``NOT_FOUND`` if no row matches.
        ValidationError: If any key is outside the tenant-config
            allow-list, or the ``webauthn_rp_id`` guardrail trips
            (value differs from a non-NULL current value while
            passkey credentials exist) without the force flag.
    """
    client = _require_client(session, client_id)

    if (
        "webauthn_rp_id" in updates
        and not force_webauthn_rp_id
        and client.webauthn_rp_id is not None
        and updates["webauthn_rp_id"] != client.webauthn_rp_id
        and repo.count_passkeys(session) > 0
    ):
        raise ValidationError(
            "Changing webauthn_rp_id invalidates every passkey registered "
            "against the prior value (the rp_id is bound into each "
            "credential at creation time). Re-send with "
            "force_webauthn_rp_id once the consequence is coordinated "
            "with the affected users."
        )

    try:
        updated = repo.update_app_client_config(session, client_id=client_id, **updates)
    except ValueError as exc:
        raise ValidationError(str(exc)) from exc
    if updated is None:  # pragma: no cover — row loaded above in-session.
        raise NotFoundError(
            code="NOT_FOUND",
            message=f"No app client with client_id {client_id!r}.",
        )
    _audit_log.info(
        "app_client.update_config client_id=%s fields=%s",
        client_id,
        sorted(updates),
    )
    return updated


def serialize(client: AppClient) -> dict[str, object]:
    """Render an ``AppClient`` as a redacted, JSON-safe dict.

    Non-secret tenant-config columns are returned in plaintext;
    encrypted columns appear only as ``<column>_configured`` booleans.
    Decrypted secret values and the ``client_secret_hash`` never leave
    this function.

    Args:
        client: The ``AppClient`` row to serialize.

    Returns:
        A dict with identity fields, plaintext non-secret config, and
        configured-ness booleans for the encrypted columns.
    """
    data: dict[str, object] = {
        "client_id": client.client_id,
        "app_name": client.app_name,
        "allowed_origins": list(client.allowed_origins),
        "created_at": client.created_at.isoformat(),
    }
    for column in _NON_SECRET_CONFIG_COLUMNS:
        data[column] = getattr(client, column)
    for column in _SECRET_CONFIG_COLUMNS:
        data[f"{column}_configured"] = bool(getattr(client, column))
    return data

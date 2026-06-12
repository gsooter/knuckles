"""User-profile service functions.

Routes never touch the repository directly (CLAUDE.md layering rule);
this module is the service seam between ``/v1/me``-shaped endpoints
and :mod:`knuckles.data.repositories.auth`. It covers profile reads
and updates, account deletion, and OAuth-provider visibility.
"""

from __future__ import annotations

import logging
import uuid
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from knuckles.core.exceptions import (
    PROVIDER_NOT_FOUND,
    USER_NOT_FOUND,
    NotFoundError,
    ValidationError,
)
from knuckles.data.models import OAuthProvider, User, UserOAuthProvider
from knuckles.data.repositories import auth as repo
from knuckles.data.repositories.auth import _UNSET, _Unset

_audit = logging.getLogger("knuckles.audit")

_DISPLAY_NAME_MAX_LENGTH = 200
_AVATAR_URL_MAX_LENGTH = 500


def require_user(session: Session, user_id: uuid.UUID) -> User:
    """Load a user by id or raise the canonical not-found error.

    Args:
        session: Active SQLAlchemy session.
        user_id: UUID of the user to load.

    Returns:
        The matching ``User`` row.

    Raises:
        NotFoundError: With code ``USER_NOT_FOUND`` if no row matches
            (e.g., the user was deleted mid-session).
    """
    user = repo.get_user_by_id(session, user_id)
    if user is None:
        raise NotFoundError(code=USER_NOT_FOUND, message="User not found.")
    return user


def _validate_display_name(display_name: str | None | _Unset) -> None:
    """Validate a candidate ``display_name`` value.

    Args:
        display_name: New display name, ``None`` to clear, or the
            absent sentinel.

    Raises:
        ValidationError: If the value is a string longer than 200
            characters.
    """
    if isinstance(display_name, str) and len(display_name) > _DISPLAY_NAME_MAX_LENGTH:
        raise ValidationError(
            f"'display_name' must be at most {_DISPLAY_NAME_MAX_LENGTH} characters."
        )


def _validate_avatar_url(avatar_url: str | None | _Unset) -> None:
    """Validate a candidate ``avatar_url`` value.

    Args:
        avatar_url: New avatar URL, ``None`` to clear, or the absent
            sentinel.

    Raises:
        ValidationError: If the value is a string longer than 500
            characters or not an absolute http(s) URL.
    """
    if not isinstance(avatar_url, str):
        return
    if len(avatar_url) > _AVATAR_URL_MAX_LENGTH:
        raise ValidationError(
            f"'avatar_url' must be at most {_AVATAR_URL_MAX_LENGTH} characters."
        )
    parsed = urlparse(avatar_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValidationError("'avatar_url' must be an absolute http(s) URL.")


def update_profile(
    session: Session,
    user_id: uuid.UUID,
    *,
    display_name: str | None | _Unset = _UNSET,
    avatar_url: str | None | _Unset = _UNSET,
) -> User:
    """Apply a validated partial profile update for a user.

    Absent parameters (left at the sentinel) keep their current value;
    an explicit ``None`` clears the field — the three-way semantics
    ``PATCH /v1/me`` exposes.

    Args:
        session: Active SQLAlchemy session.
        user_id: UUID of the user to update.
        display_name: New display name (max 200 chars), ``None`` to
            clear, or absent.
        avatar_url: New avatar URL (max 500 chars, absolute http(s)),
            ``None`` to clear, or absent.

    Returns:
        The updated ``User`` row.

    Raises:
        NotFoundError: With code ``USER_NOT_FOUND`` if the user no
            longer exists.
        ValidationError: If a provided value violates the length or
            URL-scheme constraints.
    """
    user = require_user(session, user_id)
    _validate_display_name(display_name)
    _validate_avatar_url(avatar_url)
    return repo.update_user_profile(
        session,
        user,
        display_name=display_name,
        avatar_url=avatar_url,
    )


def delete_account(
    session: Session,
    user_id: uuid.UUID,
    *,
    app_client_id: str,
) -> None:
    """Permanently delete a user's account.

    Account deletion is account-wide by nature: every active refresh
    token across every tenant is revoked (not just the calling app's),
    the user's pending magic-link rows are deleted by email, and the
    user row itself is removed — FK cascades take the OAuth links,
    passkeys, and refresh-token rows with it.

    Args:
        session: Active SQLAlchemy session.
        user_id: UUID of the user to delete.
        app_client_id: Calling app client, recorded in the audit log.

    Raises:
        NotFoundError: With code ``USER_NOT_FOUND`` if the user no
            longer exists.
    """
    user = require_user(session, user_id)
    revoked = repo.revoke_all_refresh_tokens_for_user(session, user_id)
    links_deleted = repo.delete_magic_links_for_email(session, email=user.email)
    repo.delete_user(session, user)
    # Deliberately no email in the log line — the account is gone and
    # its address should not live on in the logs.
    _audit.info(
        "account_deleted user_id=%s app_client_id=%s tokens_revoked=%d "
        "magic_links_deleted=%d",
        user_id,
        app_client_id,
        revoked,
        links_deleted,
    )


def list_providers(session: Session, user_id: uuid.UUID) -> list[UserOAuthProvider]:
    """Return the OAuth provider links for a user.

    Callers serializing the result must expose only the provider name,
    creation time, and scopes — never the stored provider tokens, raw
    profile, or provider user id.

    Args:
        session: Active SQLAlchemy session.
        user_id: UUID of the user whose links to list.

    Returns:
        The user's ``UserOAuthProvider`` rows (possibly empty).

    Raises:
        NotFoundError: With code ``USER_NOT_FOUND`` if the user no
            longer exists.
    """
    user = require_user(session, user_id)
    return list(user.oauth_providers)


def remove_provider(
    session: Session,
    user_id: uuid.UUID,
    *,
    provider: str,
) -> None:
    """Unlink an OAuth provider from a user's account.

    No lockout guard is needed: magic-link sign-in always remains
    available for the account's email, so removing the last (or only)
    OAuth link can never strand the user.

    Args:
        session: Active SQLAlchemy session.
        user_id: UUID of the user unlinking the provider.
        provider: Provider name from the URL — must be a valid
            :class:`OAuthProvider` value (``google`` or ``apple``).

    Raises:
        NotFoundError: With code ``USER_NOT_FOUND`` if the user no
            longer exists, or ``PROVIDER_NOT_FOUND`` if the name is
            not a known provider or the user has no such link.
    """
    require_user(session, user_id)
    try:
        provider_enum = OAuthProvider(provider)
    except ValueError as exc:
        raise NotFoundError(
            code=PROVIDER_NOT_FOUND, message="Provider not found."
        ) from exc
    if not repo.delete_oauth_provider_for_user(session, user_id, provider_enum):
        raise NotFoundError(code=PROVIDER_NOT_FOUND, message="Provider not found.")
    _audit.info(
        "oauth_provider_unlinked user_id=%s provider=%s",
        user_id,
        provider_enum.value,
    )

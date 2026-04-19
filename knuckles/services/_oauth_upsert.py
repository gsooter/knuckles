"""Shared find-or-create logic for OAuth identity providers.

Both :mod:`knuckles.services.google_oauth` and
:mod:`knuckles.services.apple_oauth` end their happy path the same way:

1. If a ``user_oauth_providers`` row already exists for
   ``(provider, provider_user_id)``, refresh its tokens, bump
   ``users.last_seen_at``, and return the linked user.
2. Otherwise look up by email — if a user exists, attach a new
   provider link to that row.
3. Otherwise create a new user *and* a new provider link.

This module owns steps (1) through (3) so the per-provider services only need
to translate provider-specific responses into the keyword arguments
of :func:`upsert_oauth_user`.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from knuckles.core.exceptions import AppError
from knuckles.data.models import OAuthProvider, User
from knuckles.data.repositories import auth as repo


def upsert_oauth_user(
    session: Session,
    *,
    provider: OAuthProvider,
    provider_user_id: str,
    email: str,
    display_name: str | None,
    avatar_url: str | None,
    access_token: str,
    refresh_token: str | None,
    token_expires_at: datetime | None,
    scopes: str,
    raw_profile: dict[str, Any],
    fail_code: str,
) -> User:
    """Find-or-create the user for an OAuth identity, refreshing tokens.

    Resolution order: existing OAuth link → existing user with the same
    email → new user.

    Args:
        session: Active SQLAlchemy session.
        provider: Identity provider being linked (Google or Apple).
        provider_user_id: Stable user id reported by the provider.
        email: Lowercased email returned by the provider.
        display_name: Best-effort display name. ``None`` keeps the
            existing value on a relink.
        avatar_url: Best-effort avatar URL. ``None`` keeps the
            existing value on a relink.
        access_token: Provider's current access token.
        refresh_token: Optional provider refresh token.
        token_expires_at: Optional expiry of the provider access token.
        scopes: Space-delimited scopes granted at this login.
        raw_profile: Verbatim profile payload, kept for audit.
        fail_code: Provider-specific error code to raise if the bound
            user row is deactivated (``GOOGLE_AUTH_FAILED`` /
            ``APPLE_AUTH_FAILED``).

    Returns:
        The :class:`User` now linked to this OAuth identity.

    Raises:
        AppError: With code ``fail_code`` if the bound user is
            deactivated.
    """
    existing = repo.get_oauth_provider(session, provider, provider_user_id)
    if existing is not None:
        if not existing.user.is_active:
            raise AppError(
                code=fail_code,
                message="This account is no longer active.",
                status_code=400,
            )
        repo.update_oauth_tokens(
            session,
            existing,
            access_token=access_token,
            refresh_token=refresh_token,
            token_expires_at=token_expires_at,
        )
        repo.update_last_seen(session, existing.user)
        return existing.user

    user = repo.get_user_by_email(session, email)
    if user is None:
        user = repo.create_user(
            session,
            email=email,
            display_name=display_name,
            avatar_url=avatar_url,
        )
    elif not user.is_active:
        raise AppError(
            code=fail_code,
            message="This account is no longer active.",
            status_code=400,
        )

    repo.create_oauth_provider(
        session,
        user_id=user.id,
        provider=provider,
        provider_user_id=provider_user_id,
        access_token=access_token,
        refresh_token=refresh_token,
        token_expires_at=token_expires_at,
        scopes=scopes,
        raw_profile=raw_profile,
    )
    repo.update_last_seen(session, user)
    return user

"""User-profile service functions.

Routes never touch the repository directly (CLAUDE.md layering rule);
this module is the service seam between ``/v1/me``-shaped endpoints
and :mod:`knuckles.data.repositories.auth`.
"""

from __future__ import annotations

import uuid

from sqlalchemy.orm import Session

from knuckles.core.exceptions import USER_NOT_FOUND, NotFoundError
from knuckles.data.models.auth import User
from knuckles.data.repositories import auth as repo


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

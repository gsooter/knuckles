"""SQLAlchemy ORM models.

Importing this package registers every model with ``Base.metadata`` so
Alembic autogenerate sees them. Keep the imports here exhaustive.
"""

from knuckles.data.models.auth import (
    AppClient,
    MagicLinkToken,
    OAuthProvider,
    PasskeyCredential,
    RefreshToken,
    User,
    UserOAuthProvider,
)

__all__ = [
    "AppClient",
    "MagicLinkToken",
    "OAuthProvider",
    "PasskeyCredential",
    "RefreshToken",
    "User",
    "UserOAuthProvider",
]

"""Python SDK for the Knuckles identity service.

Quickstart::

    from knuckles_client import KnucklesClient

    client = KnucklesClient(
        base_url="https://auth.example.com",
        client_id="my-app",
        client_secret="...",
    )

    # Verify a Knuckles access token (JWKS-cached, no network after warmup)
    claims = client.verify_access_token(token)

    # Drive a sign-in ceremony
    auth = client.google.start(redirect_url="https://my-app/auth/google/callback")
    # ... browser round trip ...
    pair = client.google.complete(code="...", state=auth.state)

    # Rotate
    pair = client.refresh(pair.refresh_token)
"""

from .client import KnucklesClient
from .exceptions import (
    KnucklesAPIError,
    KnucklesAuthError,
    KnucklesError,
    KnucklesNetworkError,
    KnucklesRateLimitError,
    KnucklesTokenError,
    KnucklesValidationError,
)
from .models import (
    CeremonyStart,
    PasskeyChallenge,
    PasskeyDescriptor,
    TokenPair,
    UserProfile,
)

__version__ = "0.1.1"

__all__ = [
    "CeremonyStart",
    "KnucklesAPIError",
    "KnucklesAuthError",
    "KnucklesClient",
    "KnucklesError",
    "KnucklesNetworkError",
    "KnucklesRateLimitError",
    "KnucklesTokenError",
    "KnucklesValidationError",
    "PasskeyChallenge",
    "PasskeyDescriptor",
    "TokenPair",
    "UserProfile",
    "__version__",
]

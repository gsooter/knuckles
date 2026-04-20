"""Application configuration loaded from environment variables.

All environment variables are defined and validated here using Pydantic
Settings. The app fails loudly at startup if a required variable is missing.
No other module should read ``os.environ`` directly.

**Scope reminder:** Knuckles is identity-only. No Spotify, Apple Music,
Tidal, or any other music-service configuration appears in this file.
Music services are a Greenroom concern — see CLAUDE.md for the full rule.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Knuckles settings loaded from environment variables.

    Attributes:
        database_url: PostgreSQL connection string for the Knuckles DB.
        knuckles_base_url: Public base URL of the Knuckles service.
            Published in the JWT ``iss`` claim and the JWKS URI.
        frontend_base_url: Default public URL for a consuming-app landing
            page (used when building email links that aren't scoped to a
            specific ``app_client``).
        knuckles_jwt_private_key: Base64-encoded PEM-encoded RS256
            private key used to sign access tokens.
        knuckles_jwt_key_id: Stable ``kid`` published in the JWKS
            alongside the public key.
        knuckles_access_token_ttl_seconds: Lifetime of an issued access
            token before its ``exp`` claim invalidates it.
        knuckles_refresh_token_ttl_seconds: Lifetime of an issued refresh
            token before its ``refresh_tokens.expires_at`` row expires.
        knuckles_state_secret: HMAC secret used for short-lived
            ceremony-state JWTs (OAuth ``state``, passkey challenge
            wrappers). Deliberately separate from the RS256 signing key
            because state tokens never leave Knuckles.
        magic_link_ttl_seconds: How long a magic-link token stays
            redeemable before ``expires_at`` invalidates it.
        resend_api_key: Resend API key for magic-link emails.
        resend_from_email: Sender address used on outgoing magic-link
            emails. Must be a verified Resend sender — typically
            ``Name <noreply@your-domain>``.
        google_oauth_client_id: Google OAuth client id. Empty when
            Google path is not configured.
        google_oauth_client_secret: Google OAuth client secret.
        apple_oauth_client_id: Sign-in-with-Apple services id.
        apple_oauth_team_id: Apple Developer team id used to sign the
            client secret JWT.
        apple_oauth_key_id: Apple private-key id (``*.p8`` filename).
        apple_oauth_private_key: PEM-encoded Apple private key contents.
        webauthn_rp_id: Relying-party id for WebAuthn — normally the
            apex domain shared across consuming apps.
        webauthn_rp_name: Display name on the native passkey prompt.
        webauthn_origin: Expected origin on WebAuthn ceremonies
            (scheme+host, no trailing slash).
        debug: Enable debug mode. Defaults to False.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # Database
    database_url: str

    # App
    knuckles_base_url: str = "http://localhost:5001"
    frontend_base_url: str = "http://localhost:3000"
    debug: bool = False

    # JWT (RS256)
    knuckles_jwt_private_key: str
    knuckles_jwt_key_id: str
    knuckles_access_token_ttl_seconds: int = 3600
    knuckles_refresh_token_ttl_seconds: int = 30 * 24 * 3600

    # Ceremony state
    knuckles_state_secret: str

    # Magic link
    magic_link_ttl_seconds: int = 15 * 60

    # Resend
    resend_api_key: str = ""
    resend_from_email: str = ""

    # Google OAuth
    google_oauth_client_id: str = ""
    google_oauth_client_secret: str = ""

    # Apple OAuth
    apple_oauth_client_id: str = ""
    apple_oauth_team_id: str = ""
    apple_oauth_key_id: str = ""
    apple_oauth_private_key: str = ""

    # WebAuthn
    webauthn_rp_id: str = "localhost"
    webauthn_rp_name: str = "Knuckles"
    webauthn_origin: str = "http://localhost:3000"


def get_settings() -> Settings:
    """Create and return a validated ``Settings`` instance.

    Returns:
        A ``Settings`` instance with all environment variables loaded.

    Raises:
        ValidationError: If any required environment variable is missing.
    """
    return Settings()  # type: ignore[call-arg]

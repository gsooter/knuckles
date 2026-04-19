"""WebAuthn passkey registration and sign-in for Knuckles.

Two ceremonies live here:

* **Registration** (the user is already signed in) — :func:`register_begin`
  mints navigator.credentials.create() options and a state JWT that
  binds the challenge to the user. :func:`register_complete` verifies
  the resulting attestation and persists a ``passkey_credentials`` row.
* **Authentication** (the user is anonymous) — :func:`authenticate_begin`
  mints navigator.credentials.get() options with no ``allow_credentials``
  list, enabling the discoverable / usernameless sign-in flow.
  :func:`authenticate_complete` verifies the assertion against the
  stored public key, advances the sign count, and mints a Knuckles
  :class:`~knuckles.services.tokens.TokenPair`.

State JWTs ride the same HS256 secret as the other ceremony tokens
(:mod:`knuckles.core.state_jwt`). Challenges are 32-byte random bytes
issued by ``webauthn.generate_*_options``; we round-trip them through
the state JWT as base64url strings.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session
from webauthn import (
    base64url_to_bytes,
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import bytes_to_base64url
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from knuckles.core.config import get_settings
from knuckles.core.exceptions import (
    PASSKEY_AUTH_FAILED,
    PASSKEY_REGISTRATION_FAILED,
    AppError,
)
from knuckles.core.state_jwt import issue_state, verify_state
from knuckles.data.repositories import auth as repo
from knuckles.services import tokens

_REGISTER_PURPOSE = "passkey_register"
_AUTHENTICATE_PURPOSE = "passkey_auth"
_STATE_TTL_SECONDS = 5 * 60


@dataclass(frozen=True)
class PasskeyRegisterStart:
    """Return value from :func:`register_begin`.

    Attributes:
        options: ``PublicKeyCredentialCreationOptions`` rendered to a
            plain dict the frontend can pass to
            ``navigator.credentials.create()``.
        state: Signed state JWT the frontend echoes back on
            :func:`register_complete`.
    """

    options: dict[str, Any]
    state: str


@dataclass(frozen=True)
class PasskeyAuthenticateStart:
    """Return value from :func:`authenticate_begin`.

    Attributes:
        options: ``PublicKeyCredentialRequestOptions`` rendered to a
            plain dict the frontend can pass to
            ``navigator.credentials.get()``.
        state: Signed state JWT the frontend echoes back on
            :func:`authenticate_complete`.
    """

    options: dict[str, Any]
    state: str


def register_begin(
    session: Session,
    *,
    user_id: str,
) -> PasskeyRegisterStart:
    """Mint registration options + state for an authenticated user.

    Args:
        session: Active SQLAlchemy session.
        user_id: UUID string of the signed-in user enrolling a passkey.

    Returns:
        A :class:`PasskeyRegisterStart` with the options dict and the
        signed state JWT.

    Raises:
        AppError: With code ``PASSKEY_REGISTRATION_FAILED`` if the user
            row no longer exists.
    """
    import uuid

    settings = get_settings()
    user_uuid = uuid.UUID(user_id)
    user = repo.get_user_by_id(session, user_uuid)
    if user is None:
        raise AppError(
            code=PASSKEY_REGISTRATION_FAILED,
            message="User no longer exists.",
            status_code=400,
        )

    existing = repo.list_passkeys_for_user(session, user_uuid)
    exclude = [
        PublicKeyCredentialDescriptor(id=base64url_to_bytes(cred.credential_id))
        for cred in existing
    ]
    options = generate_registration_options(
        rp_id=settings.webauthn_rp_id,
        rp_name=settings.webauthn_rp_name,
        user_id=user_uuid.bytes,
        user_name=user.email,
        user_display_name=user.display_name or user.email,
        exclude_credentials=exclude,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
    )
    state = issue_state(
        purpose=_REGISTER_PURPOSE,
        payload={
            "user_id": str(user_uuid),
            "challenge": bytes_to_base64url(options.challenge),
        },
        ttl_seconds=_STATE_TTL_SECONDS,
    )
    return PasskeyRegisterStart(
        options=json.loads(options_to_json(options)),
        state=state,
    )


def register_complete(
    session: Session,
    *,
    user_id: str,
    credential: dict[str, Any],
    state: str,
    name: str | None = None,
) -> str:
    """Verify a registration attestation and persist the passkey.

    Args:
        session: Active SQLAlchemy session.
        user_id: UUID string of the signed-in user — must match the
            ``user_id`` baked into ``state``.
        credential: The ``PublicKeyCredential`` JSON the browser
            produced from ``navigator.credentials.create()``.
        state: State JWT minted by :func:`register_begin`.
        name: Optional human-facing label for this passkey.

    Returns:
        Base64url-encoded credential id of the newly stored passkey.

    Raises:
        AppError: With code ``PASSKEY_REGISTRATION_FAILED`` for any
            state mismatch or attestation verification failure.
    """
    settings = get_settings()
    claims = _verify_register_state(state, user_id=user_id)
    expected_challenge = base64url_to_bytes(claims["challenge"])

    try:
        verified = verify_registration_response(
            credential=credential,
            expected_challenge=expected_challenge,
            expected_rp_id=settings.webauthn_rp_id,
            expected_origin=settings.webauthn_origin,
        )
    except Exception as exc:
        raise AppError(
            code=PASSKEY_REGISTRATION_FAILED,
            message="Passkey attestation could not be verified.",
            status_code=400,
        ) from exc

    import uuid

    cred_id = bytes_to_base64url(verified.credential_id)
    repo.create_passkey(
        session,
        user_id=uuid.UUID(user_id),
        credential_id=cred_id,
        public_key=bytes_to_base64url(verified.credential_public_key),
        sign_count=verified.sign_count,
        transports=_extract_transports(credential),
        name=name,
    )
    return cred_id


def authenticate_begin(*, app_client_id: str) -> PasskeyAuthenticateStart:
    """Mint discoverable-credential authentication options.

    No ``allow_credentials`` list is sent: the browser surfaces every
    resident credential it has for the relying party. The state JWT
    binds the challenge to the calling app so a state issued for one
    app can't be redeemed by another.

    Args:
        app_client_id: ``app_clients.client_id`` initiating the flow.

    Returns:
        A :class:`PasskeyAuthenticateStart` with the options dict and
        the signed state JWT.
    """
    settings = get_settings()
    options = generate_authentication_options(
        rp_id=settings.webauthn_rp_id,
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    state = issue_state(
        purpose=_AUTHENTICATE_PURPOSE,
        payload={
            "app_client_id": app_client_id,
            "challenge": bytes_to_base64url(options.challenge),
        },
        ttl_seconds=_STATE_TTL_SECONDS,
    )
    return PasskeyAuthenticateStart(
        options=json.loads(options_to_json(options)),
        state=state,
    )


def authenticate_complete(
    session: Session,
    *,
    credential: dict[str, Any],
    state: str,
    app_client_id: str,
    scopes: list[str] | None = None,
) -> tokens.TokenPair:
    """Verify an authentication assertion and mint a session.

    Args:
        session: Active SQLAlchemy session.
        credential: The ``PublicKeyCredential`` JSON the browser
            produced from ``navigator.credentials.get()``.
        state: State JWT minted by :func:`authenticate_begin`.
        app_client_id: Calling ``app_clients.client_id``. Must match
            the ``app_client_id`` baked into ``state``.
        scopes: Optional Knuckles access-token scopes to embed.

    Returns:
        A :class:`~knuckles.services.tokens.TokenPair` for the user
        who owns the asserted credential.

    Raises:
        AppError: With code ``PASSKEY_AUTH_FAILED`` for any state
            mismatch, unknown credential, deactivated user, or
            assertion verification failure (signature, sign-count
            regression, origin/RP mismatch).
    """
    settings = get_settings()
    claims = _verify_authenticate_state(state, app_client_id=app_client_id)
    expected_challenge = base64url_to_bytes(claims["challenge"])

    raw_credential_id = credential.get("id") or credential.get("rawId")
    if not isinstance(raw_credential_id, str) or not raw_credential_id:
        raise AppError(
            code=PASSKEY_AUTH_FAILED,
            message="Passkey assertion is missing a credential id.",
            status_code=400,
        )

    stored = repo.get_passkey_by_credential_id(session, raw_credential_id)
    if stored is None:
        raise AppError(
            code=PASSKEY_AUTH_FAILED,
            message="Unknown passkey credential.",
            status_code=400,
        )
    if not stored.user.is_active:
        raise AppError(
            code=PASSKEY_AUTH_FAILED,
            message="This account is no longer active.",
            status_code=400,
        )

    try:
        verified = verify_authentication_response(
            credential=credential,
            expected_challenge=expected_challenge,
            expected_rp_id=settings.webauthn_rp_id,
            expected_origin=settings.webauthn_origin,
            credential_public_key=base64url_to_bytes(stored.public_key),
            credential_current_sign_count=stored.sign_count,
        )
    except Exception as exc:
        raise AppError(
            code=PASSKEY_AUTH_FAILED,
            message="Passkey assertion could not be verified.",
            status_code=400,
        ) from exc

    repo.update_passkey_sign_count(session, stored, sign_count=verified.new_sign_count)
    repo.update_last_seen(session, stored.user)

    return tokens.issue_session(
        session,
        user_id=stored.user_id,
        app_client_id=app_client_id,
        scopes=scopes,
        email=stored.user.email,
    )


def _verify_register_state(state: str, *, user_id: str) -> dict[str, Any]:
    """Decode and validate a passkey-registration state JWT.

    Args:
        state: State token returned by the browser.
        user_id: Expected ``user_id`` baked into the state. Mismatch
            means the registration is for a different account.

    Returns:
        Decoded state claims.

    Raises:
        AppError: With code ``PASSKEY_REGISTRATION_FAILED`` on any
            signature, purpose, user, or challenge issue.
    """
    try:
        claims = verify_state(state, purpose=_REGISTER_PURPOSE)
    except ValueError as exc:
        raise AppError(
            code=PASSKEY_REGISTRATION_FAILED,
            message="Passkey registration state is invalid or expired.",
            status_code=400,
        ) from exc
    if claims.get("user_id") != user_id:
        raise AppError(
            code=PASSKEY_REGISTRATION_FAILED,
            message="Passkey registration state was issued for a different user.",
            status_code=400,
        )
    if not isinstance(claims.get("challenge"), str):
        raise AppError(
            code=PASSKEY_REGISTRATION_FAILED,
            message="Passkey registration state is missing a challenge.",
            status_code=400,
        )
    return claims


def _verify_authenticate_state(state: str, *, app_client_id: str) -> dict[str, Any]:
    """Decode and validate a passkey-authentication state JWT.

    Args:
        state: State token returned by the browser.
        app_client_id: Expected ``app_client_id`` baked into the state.
            Mismatch means a state issued for one app is being redeemed
            by another.

    Returns:
        Decoded state claims.

    Raises:
        AppError: With code ``PASSKEY_AUTH_FAILED`` on any signature,
            purpose, app-client, or challenge issue.
    """
    try:
        claims = verify_state(state, purpose=_AUTHENTICATE_PURPOSE)
    except ValueError as exc:
        raise AppError(
            code=PASSKEY_AUTH_FAILED,
            message="Passkey sign-in state is invalid or expired.",
            status_code=400,
        ) from exc
    if claims.get("app_client_id") != app_client_id:
        raise AppError(
            code=PASSKEY_AUTH_FAILED,
            message="Passkey sign-in state was issued for a different app.",
            status_code=400,
        )
    if not isinstance(claims.get("challenge"), str):
        raise AppError(
            code=PASSKEY_AUTH_FAILED,
            message="Passkey sign-in state is missing a challenge.",
            status_code=400,
        )
    return claims


def _extract_transports(credential: dict[str, Any]) -> str | None:
    """Pull a comma-joined transport list off a registration credential.

    The browser optionally reports which transports the authenticator
    supports (``internal``, ``hybrid``, ``usb``, ``nfc``, ``ble``).
    Storing them lets sign-in pre-populate ``allowCredentials.transports``
    so the prompt skips irrelevant authenticator hardware.

    Args:
        credential: The ``PublicKeyCredential`` JSON from the browser.

    Returns:
        Comma-joined transport string or ``None`` if absent or empty.
    """
    response = credential.get("response")
    if not isinstance(response, dict):
        return None
    transports = response.get("transports")
    if not isinstance(transports, list):
        return None
    cleaned = [str(t) for t in transports if isinstance(t, str) and t]
    return ",".join(cleaned) or None

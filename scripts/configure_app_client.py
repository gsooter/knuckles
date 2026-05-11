"""Set or rotate per-tenant config on an existing ``app_clients`` row.

Decision #017 moves Resend / Google / Apple / WebAuthn configuration
from process-global env vars onto nullable columns of ``app_clients``,
encrypted at rest for secret-bearing fields. This CLI is the operator
seam for populating those columns without re-issuing the client_secret
(use ``register_app_client.py`` for that).

Usage examples:

    # Apple Sign-in: rotate the Services ID, team, key, and .p8.
    python scripts/configure_app_client.py greenroom-prod \\
        --apple-client-id host.exp.Exponent \\
        --apple-team-id ABCD123456 \\
        --apple-key-id WXYZ987654 \\
        --apple-private-key-file /path/to/AuthKey_WXYZ987654.p8

    # Google: swap to a tenant-owned OAuth client.
    python scripts/configure_app_client.py greenroom-prod \\
        --google-client-id 12345.apps.googleusercontent.com \\
        --google-client-secret 'GOCSPX-...'

    # Resend: per-tenant sender (API key may stay global).
    python scripts/configure_app_client.py greenroom-prod \\
        --resend-from-email 'Greenroom <signin@mail.greenroom.live>'

    # Revert a single field to env-var fallback.
    python scripts/configure_app_client.py greenroom-prod \\
        --apple-team-id ''

Secret-bearing fields (``--resend-api-key``,
``--google-client-secret``, ``--apple-private-key`` and its
``-file`` variant) are encrypted by the SQLAlchemy
``EncryptedText`` type decorator on write — they leave the process
as Fernet ciphertext, never plaintext to disk.

WebAuthn ``rp_id`` is **effectively immutable** once a passkey has
been registered for the tenant (changing it invalidates every
credential because the rp_id is bound into the credential at
creation time). The CLI refuses to update ``--webauthn-rp-id``
without an explicit ``--force-rp-id`` flag. See Decision #017 for
the long-term immutability guardrail.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from knuckles.core.database import get_session_factory
from knuckles.data.repositories import auth as repo


def _read_private_key(path: str) -> str:
    """Read a ``.p8`` private key file and return its contents.

    Args:
        path: Filesystem path to the ``.p8`` file.

    Returns:
        The PEM-encoded contents as a string.

    Raises:
        SystemExit: If the file does not exist or cannot be read.
    """
    try:
        return Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"Could not read private key file at {path!r}: {exc}", file=sys.stderr)
        sys.exit(2)


def _build_parser() -> argparse.ArgumentParser:
    """Construct the argparse parser for the configure CLI.

    Returns:
        A configured :class:`argparse.ArgumentParser`.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("client_id", help="app_clients.client_id to update.")

    # Resend.
    parser.add_argument("--resend-api-key", help="Resend API key.")
    parser.add_argument(
        "--resend-from-email",
        help='From header value, e.g. "Greenroom <signin@mail.greenroom.live>".',
    )

    # Google OAuth.
    parser.add_argument("--google-client-id", help="Google OAuth client id.")
    parser.add_argument("--google-client-secret", help="Google OAuth client secret.")

    # Apple OAuth.
    parser.add_argument("--apple-client-id", help="Apple Services ID.")
    parser.add_argument("--apple-team-id", help="Apple Developer team id.")
    parser.add_argument("--apple-key-id", help="Apple .p8 key id.")
    parser.add_argument(
        "--apple-private-key",
        help=(
            "PEM-encoded .p8 contents (inline). Use --apple-private-key-file for paths."
        ),
    )
    parser.add_argument(
        "--apple-private-key-file",
        help="Filesystem path to the .p8 file; contents are read once and stored.",
    )

    # WebAuthn relying party.
    parser.add_argument(
        "--webauthn-rp-id",
        help=(
            "WebAuthn relying-party id (registrable domain). "
            "Refused without --force-rp-id; changing this invalidates every "
            "passkey registered against the prior value."
        ),
    )
    parser.add_argument(
        "--webauthn-rp-name",
        help="Display name on native passkey prompts.",
    )
    parser.add_argument(
        "--webauthn-origin",
        help="Expected origin on WebAuthn ceremonies, e.g. https://greenroom.live.",
    )

    parser.add_argument(
        "--force-rp-id",
        action="store_true",
        help="Acknowledge the consequences of changing webauthn_rp_id.",
    )

    return parser


def _collect_updates(args: argparse.Namespace) -> dict[str, str | None]:
    """Translate parsed CLI args into a ``{column: value}`` dict.

    Empty strings (``--foo ""``) become ``None`` so callers can revert
    a field to env-var fallback. Unset flags are omitted entirely.

    Args:
        args: Parsed :class:`argparse.Namespace`.

    Returns:
        A dict suitable for splatting into
        :func:`repo.update_app_client_config`.
    """
    updates: dict[str, str | None] = {}
    mapping: dict[str, str] = {
        "resend_api_key": "resend_api_key",
        "resend_from_email": "resend_from_email",
        "google_client_id": "google_oauth_client_id",
        "google_client_secret": "google_oauth_client_secret",
        "apple_client_id": "apple_oauth_client_id",
        "apple_team_id": "apple_oauth_team_id",
        "apple_key_id": "apple_oauth_key_id",
        "webauthn_rp_id": "webauthn_rp_id",
        "webauthn_rp_name": "webauthn_rp_name",
        "webauthn_origin": "webauthn_origin",
    }
    for attr, column in mapping.items():
        value = getattr(args, attr)
        if value is None:
            continue
        updates[column] = value or None

    # Apple private key has two input modes; resolve to a single
    # column write. Inline value wins if both are supplied.
    if args.apple_private_key is not None:
        updates["apple_oauth_private_key"] = args.apple_private_key or None
    elif args.apple_private_key_file is not None:
        updates["apple_oauth_private_key"] = _read_private_key(
            args.apple_private_key_file
        )
    return updates


def _redact(value: object) -> str:
    """Return a redacted preview for printing secret values.

    Args:
        value: The value about to be set. ``None`` and empty strings
            are printed as ``"(cleared)"``; everything else is shown
            as a single ``"***"`` so logs don't capture credentials.

    Returns:
        A short safe-to-log string.
    """
    if value in (None, ""):
        return "(cleared)"
    return "***"


_SECRET_COLUMNS: set[str] = {
    "resend_api_key",
    "google_oauth_client_secret",
    "apple_oauth_private_key",
}


def main(argv: list[str] | None = None) -> int:
    """Parse args, validate guards, and write the update.

    Args:
        argv: Optional argv override for testing; defaults to
            :data:`sys.argv` slicing the program name.

    Returns:
        Exit code: ``0`` on success; ``1`` for missing tenant or
        webauthn-rp-id guard refusal.
    """
    parser = _build_parser()
    args = parser.parse_args(argv)

    updates = _collect_updates(args)
    if not updates:
        print("No fields supplied; nothing to update.", file=sys.stderr)
        return 1

    if "webauthn_rp_id" in updates and not args.force_rp_id:
        print(
            "Refusing to update webauthn_rp_id without --force-rp-id. "
            "Changing rp_id invalidates every passkey registered against "
            "the prior value (the rp_id is bound into each credential at "
            "creation time). Re-run with --force-rp-id once you have "
            "coordinated the consequence with the affected users.",
            file=sys.stderr,
        )
        return 1

    session_factory = get_session_factory()
    with session_factory() as session:
        client = repo.update_app_client_config(
            session,
            client_id=args.client_id,
            **updates,
        )
        if client is None:
            print(
                f"No app_client found with client_id={args.client_id!r}.",
                file=sys.stderr,
            )
            return 1
        session.commit()

    print(f"Updated {args.client_id}:")
    for column, value in updates.items():
        rendered: Any = _redact(value) if column in _SECRET_COLUMNS else value
        print(f"  {column}: {rendered!s}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

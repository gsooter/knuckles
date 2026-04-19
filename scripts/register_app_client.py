"""Register a consuming app as an ``app_clients`` row.

Use this once per app (Greenroom, future apps) to mint a client_id /
client_secret pair that the app places in its own environment. Knuckles
stores only the SHA-256 hex digest of the secret.

Usage:
    python scripts/register_app_client.py \\
        --client-id greenroom-local \\
        --app-name "Greenroom (local)" \\
        --allowed-origin http://localhost:3000

Prints the plaintext client_secret exactly once. Save it immediately —
it cannot be recovered later.
"""

from __future__ import annotations

import argparse
import hashlib
import secrets
import sys

from knuckles.core.database import get_session_factory
from knuckles.data.repositories import auth as repo


def main() -> int:
    """Parse CLI args, insert an app_client, print its plaintext secret.

    Returns:
        Exit code: ``0`` on success, ``1`` if the client_id already exists.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client-id", required=True, help="Public client id.")
    parser.add_argument("--app-name", required=True, help="Human-friendly app name.")
    parser.add_argument(
        "--allowed-origin",
        action="append",
        required=True,
        help="Origin the app may run from. Repeat for multiple origins.",
    )
    args = parser.parse_args()

    session_factory = get_session_factory()
    with session_factory() as session:
        existing = repo.get_app_client(session, args.client_id)
        if existing is not None:
            print(
                f"app_client with client_id={args.client_id!r} already exists.",
                file=sys.stderr,
            )
            return 1

        plaintext_secret = secrets.token_urlsafe(48)
        secret_hash = hashlib.sha256(plaintext_secret.encode("ascii")).hexdigest()
        repo.create_app_client(
            session,
            client_id=args.client_id,
            app_name=args.app_name,
            client_secret_hash=secret_hash,
            allowed_origins=list(args.allowed_origin),
        )
        session.commit()

    print("Registered app_client.")
    print(f"  client_id:     {args.client_id}")
    print(f"  client_secret: {plaintext_secret}")
    print("")
    print("Save the secret now — it cannot be recovered.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

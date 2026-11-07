"""Re-encrypt every tenant secret under the primary Fernet key.

The Fernet rotation flow (Decision #017):

1. Generate a new key and prepend it to ``KNUCKLES_SECRETS_KEY``
   (comma-separated, new key first): ``NEW,OLD``.
2. Redeploy — reads keep working because decryption tries every key.
3. Run this script once: every populated encrypted column is
   rewritten under the new primary key.
4. Drop the old key from the env var and redeploy again.

Usage:
    python scripts/reencrypt_tenant_secrets.py

Exits 0 on success and prints the number of rewritten rows.
Idempotent — re-running rewrites the same rows under the same key.
"""

from __future__ import annotations

import sys

from knuckles.core.database import get_session_factory
from knuckles.data.repositories import auth as repo


def main() -> int:
    """Re-encrypt all populated tenant-secret columns, print the count.

    Returns:
        Exit code: ``0`` on success.
    """
    session_factory = get_session_factory()
    with session_factory() as session:
        rewritten = repo.reencrypt_app_client_secrets(session)
        session.commit()

    print(f"Re-encrypted secrets on {rewritten} app-client row(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())

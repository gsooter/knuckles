"""Delete magic-link rows whose ``expires_at`` is older than a cutoff.

Decision #006 calls for a nightly cleanup task. This script is the
implementation: a single, idempotent CLI invocation suitable for
Railway's cron, a Kubernetes CronJob, or a plain ``cron`` line.

Usage:
    python scripts/cleanup_magic_links.py [--older-than-hours 24]

Exits 0 on success and prints the number of deleted rows. Idempotent
— running it twice in a row deletes nothing the second time.
"""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime, timedelta

from knuckles.core.database import get_session_factory
from knuckles.data.repositories import auth as repo


def main() -> int:
    """Parse CLI args, delete expired magic-link rows, print the count.

    Returns:
        Exit code: ``0`` on success.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--older-than-hours",
        type=int,
        default=24,
        help=(
            "Delete rows whose ``expires_at`` is more than this many "
            "hours in the past. Defaults to 24."
        ),
    )
    args = parser.parse_args()

    cutoff = datetime.now(tz=UTC) - timedelta(hours=args.older_than_hours)
    session_factory = get_session_factory()
    with session_factory() as session:
        deleted = repo.delete_expired_magic_links(session, older_than=cutoff)
        session.commit()

    print(f"Deleted {deleted} magic-link row(s) expired before {cutoff.isoformat()}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Delete refresh-token rows whose ``expires_at`` is older than a cutoff.

Refresh tokens are retained after consumption so reuse detection can
distinguish a replayed token from an unknown one (Decision #004/#008)
— but once ``expires_at`` passes, a token can never rotate again and
the row is dead weight. Without this cleanup the table grows by one
row per sign-in plus one per rotation, forever.

Usage:
    python scripts/cleanup_refresh_tokens.py [--older-than-days 7]

Schedule alongside ``cleanup_magic_links.py`` (Railway cron, a
Kubernetes CronJob, or a plain ``cron`` line). Exits 0 on success and
prints the number of deleted rows. Idempotent.
"""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime, timedelta

from knuckles.core.database import get_session_factory
from knuckles.data.repositories import auth as repo


def main() -> int:
    """Parse CLI args, delete expired refresh-token rows, print the count.

    Returns:
        Exit code: ``0`` on success.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--older-than-days",
        type=int,
        default=7,
        help=(
            "Delete rows whose expires_at is more than this many days "
            "in the past. Defaults to 7 — a grace window so a freshly "
            "expired token still produces REFRESH_TOKEN_EXPIRED rather "
            "than REFRESH_TOKEN_INVALID, which is friendlier to debug."
        ),
    )
    args = parser.parse_args()

    cutoff = datetime.now(tz=UTC) - timedelta(days=args.older_than_days)
    session_factory = get_session_factory()
    with session_factory() as session:
        deleted = repo.delete_expired_refresh_tokens(session, older_than=cutoff)
        session.commit()

    print(
        f"Deleted {deleted} refresh-token row(s) expired before {cutoff.isoformat()}."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

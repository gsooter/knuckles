"""Migration-chain integrity tests against a real Postgres database.

These close the gap where Alembic migrations were never executed by
any test — only the ORM ``create_all`` path was exercised, so
migration-vs-model drift and Postgres-only constructs (the native
``knuckles_oauth_provider`` enum, foreign keys, partial round trips)
went unverified.

The tests are **skipped** unless ``KNUCKLES_TEST_DATABASE_URL`` points
at a reachable PostgreSQL database — they are an integration gate for
CI (where ``knuckles_test`` exists), not part of the hermetic SQLite
unit suite. They run inside a SAVEPOINT-free disposable schema and
restore it to ``base`` on the way out.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import Engine

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_ALEMBIC_INI = _PROJECT_ROOT / "knuckles" / "alembic.ini"

_TEST_DB_URL = os.environ.get("KNUCKLES_TEST_DATABASE_URL", "")

pytestmark = pytest.mark.skipif(
    not _TEST_DB_URL.startswith("postgresql"),
    reason="KNUCKLES_TEST_DATABASE_URL must point at a PostgreSQL database.",
)


def _alembic_config(database_url: str):  # type: ignore[no-untyped-def]
    """Build an Alembic ``Config`` bound to the given database URL.

    Args:
        database_url: PostgreSQL URL the migrations should run against.

    Returns:
        A configured Alembic ``Config`` object.
    """
    from alembic.config import Config

    config = Config(str(_ALEMBIC_INI))
    config.set_main_option("script_location", str(_ALEMBIC_INI.parent / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url)
    return config


@pytest.fixture()
def clean_engine() -> Iterator[Engine]:
    """Yield an engine to a freshly emptied schema, dropped on teardown.

    Args:
        None.

    Yields:
        A SQLAlchemy ``Engine`` whose ``public`` schema starts empty so
        ``upgrade head`` builds the entire chain from scratch.
    """
    engine = create_engine(_TEST_DB_URL, poolclass=None)
    with engine.begin() as conn:
        conn.execute(text("DROP SCHEMA public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))
    try:
        yield engine
    finally:
        with engine.begin() as conn:
            conn.execute(text("DROP SCHEMA public CASCADE"))
            conn.execute(text("CREATE SCHEMA public"))
        engine.dispose()


def test_full_chain_upgrades_downgrades_and_re_upgrades(clean_engine: Engine) -> None:
    """upgrade head -> downgrade base -> upgrade head all succeed.

    Proves every migration's ``downgrade`` is real (not a stub) and
    that the chain is replayable — the property a production rollback
    depends on.
    """
    from alembic import command

    config = _alembic_config(str(clean_engine.url))
    command.upgrade(config, "head")

    inspector = inspect(clean_engine)
    tables = set(inspector.get_table_names())
    assert {
        "users",
        "user_oauth_providers",
        "magic_link_tokens",
        "passkey_credentials",
        "app_clients",
        "refresh_tokens",
    } <= tables

    command.downgrade(config, "base")
    after_down = set(inspect(clean_engine).get_table_names())
    assert "users" not in after_down

    command.upgrade(config, "head")


def test_migrated_schema_matches_orm_metadata(clean_engine: Engine) -> None:
    """Autogenerate finds no diff between migrations and the models.

    A non-empty diff means a model column/index/constraint was added
    without a matching migration (or vice versa) — the exact drift
    that ships a 500 the unit suite can't see because SQLite builds
    the schema from ``create_all`` instead of the migrations.
    """
    from alembic import command
    from alembic.autogenerate import compare_metadata
    from alembic.migration import MigrationContext

    import knuckles.data.models  # noqa: F401 — register models on metadata
    from knuckles.core.database import Base

    config = _alembic_config(str(clean_engine.url))
    command.upgrade(config, "head")

    with clean_engine.connect() as conn:
        context = MigrationContext.configure(conn)
        diff = compare_metadata(context, Base.metadata)

    assert diff == [], f"ORM/migration drift detected: {diff}"

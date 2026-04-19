"""Alembic environment for the Knuckles service.

Loads the database URL from application config and wires SQLAlchemy
metadata for autogenerate support.
"""

import sys
from logging.config import fileConfig
from pathlib import Path

from sqlalchemy import engine_from_config, pool

from alembic import context

# Make the Knuckles package importable when alembic is invoked from
# its own migrations directory.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from knuckles.core.config import get_settings  # noqa: E402
from knuckles.core.database import Base  # noqa: E402

# Import all models so they register with Base.metadata.
import knuckles.data.models  # noqa: E402, F401

config = context.config

settings = get_settings()
config.set_main_option("sqlalchemy.url", settings.database_url)

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations in offline mode using a URL only."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in online mode against a live connection."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()

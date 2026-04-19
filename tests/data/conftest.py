"""SQLAlchemy fixtures for repository-layer tests.

Repository tests run against SQLite in-memory so they are hermetic and
fast. Knuckles' models use cross-dialect types (``sa.Uuid``, ``sa.JSON``)
so the same models work against Postgres in production without a second
schema definition. Dedicated migration / Postgres integration tests are
a separate tier and not part of this fixture.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from knuckles.core.database import Base
from knuckles.data import models  # noqa: F401 — register models on Base.metadata


@pytest.fixture()
def db_session() -> Iterator[Session]:
    """Yield a fresh SQLite-backed SQLAlchemy session per test.

    The schema is created from the ORM metadata at the start of every
    test and the engine is disposed at teardown, giving each test a
    pristine database.

    Yields:
        An active ``Session`` bound to an in-memory SQLite engine.
    """
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    session = factory()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()

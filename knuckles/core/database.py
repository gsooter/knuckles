"""SQLAlchemy engine, session factory, and ORM base.

Provides a request-scoped session the same way Greenroom does — the
pattern is proven and keeps the Knuckles service familiar to anyone
moving between the two codebases.
"""

from datetime import UTC, datetime
from uuid import uuid4

from flask import Flask, g
from sqlalchemy import DateTime, Engine, create_engine
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    Session,
    mapped_column,
    sessionmaker,
)

from knuckles.core.config import get_settings


def _utcnow() -> datetime:
    """Return the current UTC time as a timezone-aware datetime.

    Returns:
        Current UTC time with ``tzinfo=UTC``.
    """
    return datetime.now(tz=UTC)


class Base(DeclarativeBase):
    """Base class for all Knuckles ORM models."""

    pass


class TimestampMixin:
    """Adds ``created_at`` and ``updated_at`` columns to a model.

    Attributes:
        created_at: Timestamp when the row was inserted.
        updated_at: Timestamp when the row was last modified.
    """

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
        onupdate=_utcnow,
    )


def new_uuid() -> str:
    """Generate a new UUID4 string for use as a default primary key.

    Returns:
        A new UUID4 formatted as a lowercase string.
    """
    return str(uuid4())


def get_engine() -> Engine:
    """Create a SQLAlchemy engine from the configured ``DATABASE_URL``.

    Returns:
        A SQLAlchemy ``Engine`` with ``pool_pre_ping`` enabled.
    """
    settings = get_settings()
    return create_engine(
        settings.database_url,
        pool_pre_ping=True,
        echo=settings.debug,
    )


def get_session_factory() -> sessionmaker[Session]:
    """Create a ``sessionmaker`` bound to the application engine.

    Returns:
        A ``sessionmaker`` configured with ``expire_on_commit=False``.
    """
    engine = get_engine()
    return sessionmaker(bind=engine, expire_on_commit=False)


_session_factory: sessionmaker[Session] | None = None


def init_db(app: Flask) -> None:
    """Initialize the request-scoped session factory on a Flask app.

    Args:
        app: The Flask application instance.
    """
    global _session_factory
    _session_factory = get_session_factory()
    app.teardown_appcontext(_teardown_session)


def _teardown_session(exception: BaseException | None) -> None:
    """Close the request-scoped DB session.

    Rolls back on exception, commits otherwise. Called automatically by
    Flask at the end of each request.

    Args:
        exception: The exception raised during the request, if any.
    """
    session: Session | None = g.pop("db_session", None)
    if session is not None:
        if exception is not None:
            session.rollback()
        else:
            session.commit()
        session.close()


def get_db() -> Session:
    """Return the request-scoped database session.

    Creates a new session on first access within a request and reuses
    it for the remainder of the request.

    Returns:
        An active SQLAlchemy ``Session``.

    Raises:
        RuntimeError: If ``init_db`` has not been called for this app.
    """
    if "db_session" not in g:
        if _session_factory is None:
            raise RuntimeError("Database not initialized. Call init_db(app) first.")
        g.db_session = _session_factory()
    session: Session = g.db_session
    return session

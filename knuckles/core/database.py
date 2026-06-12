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


_session_factory: sessionmaker[Session] | None = None


def get_session_factory() -> sessionmaker[Session]:
    """Return the application sessionmaker, building one if needed.

    Reuses the factory (and its pooled engine) created by
    :func:`init_db` when available so out-of-request callers (the
    strict-CORS cache refresh) don't construct a fresh engine — and a
    fresh Postgres connection — on every invocation.

    Returns:
        A ``sessionmaker`` configured with ``expire_on_commit=False``.
    """
    if _session_factory is not None:
        return _session_factory
    engine = get_engine()
    return sessionmaker(bind=engine, expire_on_commit=False)


def init_db(app: Flask) -> None:
    """Initialize the request-scoped session factory on a Flask app.

    Args:
        app: The Flask application instance.
    """
    global _session_factory
    engine = get_engine()
    _session_factory = sessionmaker(bind=engine, expire_on_commit=False)
    app.after_request(_commit_session)
    app.teardown_appcontext(_teardown_session)


def _commit_session(response: object) -> object:
    """Commit the request-scoped session before the response is sent.

    Registered as an ``after_request`` hook so a failed commit becomes
    a 500 the caller actually sees — committing in app-context
    teardown happens after the response status has already gone out,
    which can acknowledge writes that never landed (e.g. a refresh
    token the client received but that doesn't exist server-side).

    Runs for handled-error responses too: the reuse-detection
    revocation and its audit log must persist even though the request
    itself returns 401.

    Args:
        response: The outgoing response object (passed through).

    Returns:
        The same response object.

    Raises:
        Exception: Whatever the commit raised, after rolling back, so
            Flask's error handling converts it to a 500.
    """
    session: Session | None = g.get("db_session")
    if session is not None:
        try:
            session.commit()
        except Exception:
            session.rollback()
            raise
    return response


def _teardown_session(exception: BaseException | None) -> None:
    """Close the request-scoped DB session.

    The happy-path commit already ran in :func:`_commit_session`;
    this hook rolls back whatever is left when the request died with
    an unhandled exception (Flask skips ``after_request`` hooks in
    that case) and always closes the session.

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

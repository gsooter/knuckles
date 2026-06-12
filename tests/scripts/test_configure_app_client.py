"""Tests for ``scripts/configure_app_client.py`` CLI additions.

Covers the ``--rotate-secret`` and ``--set-origin`` flags (which call
the same service functions the admin API uses) plus a regression check
that the original tenant-config update path still works.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable

import pytest
from sqlalchemy.orm import Session

import scripts.configure_app_client as cli
from knuckles.data.repositories import auth as repo


@pytest.fixture()
def cli_session(db_session: Session, monkeypatch: pytest.MonkeyPatch) -> Session:
    """Route the CLI's session factory at the in-memory test session.

    Args:
        db_session: The SQLite-backed SQLAlchemy session fixture.
        monkeypatch: pytest's monkeypatch helper.

    Returns:
        The same ``db_session``, now wired into the CLI module.
    """

    def _factory() -> Callable[[], Session]:
        """Return a callable mimicking ``sessionmaker``.

        Returns:
            A zero-argument callable producing the test session.
        """
        return lambda: db_session

    monkeypatch.setattr(cli, "get_session_factory", _factory)
    return db_session


def _register_client(session: Session) -> str:
    """Insert a baseline ``app_clients`` row.

    Args:
        session: Active SQLAlchemy session.

    Returns:
        The client_id of the inserted row.
    """
    repo.create_app_client(
        session,
        client_id="acme-prod",
        app_name="Acme",
        client_secret_hash=hashlib.sha256(b"old-secret").hexdigest(),
        allowed_origins=["http://localhost:3000"],
    )
    # Commit so the row survives the CLI closing the session (the
    # ``with session_factory() as session`` exit rolls back anything
    # uncommitted on early-return paths).
    session.commit()
    return "acme-prod"


def test_rotate_secret_prints_new_plaintext_once(
    cli_session: Session, capsys: pytest.CaptureFixture[str]
) -> None:
    """``--rotate-secret`` rotates the hash and prints the new secret."""
    client_id = _register_client(cli_session)
    old_hash = hashlib.sha256(b"old-secret").hexdigest()

    rc = cli.main([client_id, "--rotate-secret"])

    assert rc == 0
    out = capsys.readouterr().out
    secret_lines = [line for line in out.splitlines() if "client_secret:" in line]
    assert len(secret_lines) == 1
    printed_secret = secret_lines[0].split("client_secret:", 1)[1].strip()

    row = repo.get_app_client(cli_session, client_id)
    assert row is not None
    assert row.client_secret_hash != old_hash
    expected = hashlib.sha256(printed_secret.encode("ascii")).hexdigest()
    assert row.client_secret_hash == expected


def test_rotate_secret_unknown_client_fails(
    cli_session: Session, capsys: pytest.CaptureFixture[str]
) -> None:
    """``--rotate-secret`` on an unknown client exits non-zero."""
    rc = cli.main(["nope", "--rotate-secret"])

    assert rc == 1


def test_set_origin_replaces_whole_list(
    cli_session: Session, capsys: pytest.CaptureFixture[str]
) -> None:
    """Repeated ``--set-origin`` flags replace allowed_origins entirely."""
    client_id = _register_client(cli_session)

    rc = cli.main(
        [
            client_id,
            "--set-origin",
            "https://app.acme.test",
            "--set-origin",
            "http://localhost:5173",
        ]
    )

    assert rc == 0
    row = repo.get_app_client(cli_session, client_id)
    assert row is not None
    assert row.allowed_origins == [
        "https://app.acme.test",
        "http://localhost:5173",
    ]


def test_set_origin_rejects_invalid_origin(
    cli_session: Session, capsys: pytest.CaptureFixture[str]
) -> None:
    """An invalid ``--set-origin`` value fails without changing the row."""
    client_id = _register_client(cli_session)

    rc = cli.main([client_id, "--set-origin", "javascript:alert(1)"])

    assert rc == 1
    row = repo.get_app_client(cli_session, client_id)
    assert row is not None
    assert row.allowed_origins == ["http://localhost:3000"]


def test_existing_config_update_path_still_works(
    cli_session: Session, capsys: pytest.CaptureFixture[str]
) -> None:
    """The original tenant-config flags keep functioning (regression)."""
    client_id = _register_client(cli_session)

    rc = cli.main([client_id, "--resend-from-email", "Acme <signin@acme.test>"])

    assert rc == 0
    row = repo.get_app_client(cli_session, client_id)
    assert row is not None
    assert row.resend_from_email == "Acme <signin@acme.test>"


def test_no_flags_still_errors(
    cli_session: Session, capsys: pytest.CaptureFixture[str]
) -> None:
    """Supplying no flags at all remains a usage error."""
    client_id = _register_client(cli_session)

    rc = cli.main([client_id])

    assert rc == 1

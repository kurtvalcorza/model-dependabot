"""A store that fails to open closes the connection it opened (RFC #38 follow-up).

The caller never receives a store whose open raised, so it cannot close the connection: the store
must. The upgrade failures (an interrupted rebuild or back-fill) are covered where they are built,
in ``test_migration_004``, ``test_rfc38_atomic_upgrades`` and ``test_store_assurance_schema``.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from conftest import asserting_connections_closed
from model_dependabot.store import OutdatedDatabaseError, Store


def _not_a_database(path: Path) -> Path:
    path.write_bytes(b"this is not a SQLite database, only text long enough to look like one" * 8)
    return path


def test_a_read_write_open_of_a_non_database_closes_its_connection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _not_a_database(tmp_path / "noise.db")
    with asserting_connections_closed(monkeypatch), pytest.raises(sqlite3.DatabaseError):
        Store(path)


def test_a_read_only_open_of_a_non_database_closes_its_connection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _not_a_database(tmp_path / "noise.db")
    with asserting_connections_closed(monkeypatch), pytest.raises(sqlite3.DatabaseError):
        Store.open_read_only(path)


def test_a_read_only_open_of_an_outdated_database_closes_its_connection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "empty.db"
    conn = sqlite3.connect(path)
    try:
        conn.execute("CREATE TABLE unrelated (id INTEGER)")
        conn.commit()
    finally:
        conn.close()
    with asserting_connections_closed(monkeypatch), pytest.raises(OutdatedDatabaseError):
        Store.open_read_only(path)

"""RFC #38 item 1: every upgrade step on open is one transaction.

``evidence.canonical_sha256`` (feature 006) used to be added under ``with self.conn:``, where
Python's ``sqlite3`` commits the ``ALTER`` on its own. An open interrupted during the back-fill then
left the column in place with no canonical hashes, and no later open repaired it, because the
upgrade only checks that the column exists. These tests interrupt that back-fill and check that the
column is rolled back with it, then that the next open completes the upgrade.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from conftest import asserting_connections_closed
from model_dependabot.store import Store, canonical_sha256

NOW = datetime(2026, 11, 27, 9, 0, tzinfo=UTC)
BODY = json.dumps({"b": 2, "a": 1}).encode()


def _store(path: Path) -> Store:
    return Store(path, now=lambda: NOW)


def _columns(path: Path, table: str) -> set[str]:
    conn = sqlite3.connect(path)
    try:
        return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
    finally:
        conn.close()


def _execute(path: Path, *statements: str) -> None:
    conn = sqlite3.connect(path)
    try:
        with conn:
            for statement in statements:
                conn.execute(statement)
    finally:
        conn.close()


def pre_006_database(path: Path) -> None:
    """A database with one JSON evidence record, written before ``canonical_sha256`` existed."""
    with _store(path) as store:
        store.add_evidence(
            source="test",
            url="https://example.invalid/advisory",
            retrieved_at=NOW,
            matched_identifier="pkg:pypi/example@1.0",
            body=BODY,
        )
    _execute(path, "ALTER TABLE evidence DROP COLUMN canonical_sha256")


def test_an_interrupted_canonical_back_fill_leaves_no_column(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "old.db"
    pre_006_database(path)
    _execute(  # makes the back-fill fail after the column would have been added
        path,
        "CREATE TRIGGER fail_back_fill BEFORE UPDATE ON evidence"
        " BEGIN SELECT RAISE(ABORT, 'interrupted'); END",
    )
    with (
        asserting_connections_closed(monkeypatch),
        pytest.raises(sqlite3.IntegrityError, match="interrupted"),
    ):
        _store(path)
    assert "canonical_sha256" not in _columns(path, "evidence")


def test_the_next_open_completes_the_interrupted_upgrade(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "old.db"
    pre_006_database(path)
    _execute(
        path,
        "CREATE TRIGGER fail_back_fill BEFORE UPDATE ON evidence"
        " BEGIN SELECT RAISE(ABORT, 'interrupted'); END",
    )
    with asserting_connections_closed(monkeypatch), pytest.raises(sqlite3.IntegrityError):
        _store(path)
    _execute(path, "DROP TRIGGER fail_back_fill")
    with _store(path) as store:
        (row,) = store.conn.execute("SELECT canonical_sha256 FROM evidence").fetchall()
    assert row["canonical_sha256"] == canonical_sha256(BODY)


def test_a_database_without_the_plain_columns_gains_them(tmp_path: Path) -> None:
    path = tmp_path / "old.db"
    _store(path).conn.close()
    _execute(
        path,
        "ALTER TABLE etag_cache DROP COLUMN used_at",
        "ALTER TABLE model_versions DROP COLUMN registration_record_sha256",
    )
    _store(path).conn.close()
    assert "used_at" in _columns(path, "etag_cache")
    assert "registration_record_sha256" in _columns(path, "model_versions")

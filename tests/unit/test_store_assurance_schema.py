"""Feature 003 schema: version origin, format origin and claim checks (T004, data-model.md).

A fresh database has the new columns and table; a database written before 003 (the schema of main
at 308e323, kept in ``tests/fixtures/db/schema-pre-003.sql``) gains them when opened. Rows that
were registered from a registration record are back-filled as ``record``; every other old row keeps
a null origin (legacy, research A2).
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from model_dependabot.store import WATCH_KINDS, Store

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
PRE_003 = FIXTURES / "db" / "schema-pre-003.sql"
NOW = datetime(2026, 11, 12, 9, 0, tzinfo=UTC)
SHA = "sha256:" + "a" * 64


def _store(path: Path) -> Store:
    return Store(path, now=lambda: NOW)


def pre_003_database(path: Path) -> None:
    """A database written by the tool before feature 003, with one manifest-registered version
    and one registered from a registration record."""
    conn = sqlite3.connect(path)
    conn.executescript(PRE_003.read_text(encoding="utf-8"))
    stamp = "2026-11-01T00:00:00Z"
    with conn:
        for model_id in ("legacy", "from-record"):
            conn.execute(
                "INSERT INTO models (model_id, created_at) VALUES (?, ?)", (model_id, stamp)
            )
        conn.execute(
            "INSERT INTO model_versions (model_id, version, registered_at, manifest_sha256,"
            " inventory) VALUES ('legacy', 1, ?, ?, '{}')",
            (stamp, "b" * 64),
        )
        conn.execute(
            "INSERT INTO model_versions (model_id, version, registered_at, manifest_sha256,"
            " inventory, registration_record_sha256) VALUES ('from-record', 1, ?, ?, '{}', ?)",
            (stamp, "b" * 64, "c" * 64),
        )
        conn.execute(
            "INSERT INTO inventory_entries (model_id, version, kind, identifier, pinned,"
            " location, format, can_run_code) VALUES ('legacy', 1, 'weight_file', ?, 1,"
            " 'model.safetensors', 'safetensors', 0)",
            (SHA,),
        )
    conn.close()


def _check_values(conn: sqlite3.Connection, table: str) -> str:
    row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)
    ).fetchone()
    return str(row[0])


def test_a_fresh_database_has_the_new_columns_and_table(tmp_path: Path) -> None:
    with _store(tmp_path / "md.db") as store:
        assert "origin" in store.columns("model_versions")
        assert "format_origin" in store.columns("inventory_entries")
        assert store.columns("claim_checks") == {
            "claim_check_id",
            "model_id",
            "version",
            "entry_identifier",
            "claim",
            "run_id",
            "outcome",
            "measured_format",
            "measured_can_run_code",
            "reason",
            "evidence_id",
            "checked_at",
        }
        assert {"format_claim_contradicted", "format_claim_unreadable"} <= set(WATCH_KINDS)


def _version(store: Store, model_id: str, origin: str | None, format_origin: str | None) -> int:
    store.add_model(model_id)
    entry = {
        "kind": "weight_file",
        "identifier": SHA,
        "pinned": True,
        "location": "model.safetensors",
        "format": "safetensors",
        "can_run_code": False,
        "format_origin": format_origin,
    }
    return store.add_version(model_id, {}, "d" * 64, [entry], origin=origin)


@pytest.mark.parametrize("origin", ["manifest", "record", "import", None])
def test_version_origin_is_stored(tmp_path: Path, origin: str | None) -> None:
    with _store(tmp_path / "md.db") as store:
        version = _version(store, "m", origin, None)
        assert store.get_version("m", version)["origin"] == origin


def test_version_origin_is_limited_to_the_listed_values(tmp_path: Path) -> None:
    with _store(tmp_path / "md.db") as store, pytest.raises(sqlite3.IntegrityError):
        _version(store, "m", "guessed", None)


@pytest.mark.parametrize("format_origin", ["bytes", "name", "record", "import", None])
def test_format_origin_is_stored(tmp_path: Path, format_origin: str | None) -> None:
    with _store(tmp_path / "md.db") as store:
        version = _version(store, "m", "manifest", format_origin)
        assert store.entries("m", version)[0]["format_origin"] == format_origin


def test_format_origin_is_limited_to_the_listed_values(tmp_path: Path) -> None:
    with _store(tmp_path / "md.db") as store, pytest.raises(sqlite3.IntegrityError):
        _version(store, "m", "manifest", "hearsay")


def test_claim_checks_are_recorded_and_read_back(tmp_path: Path) -> None:
    with _store(tmp_path / "md.db") as store:
        version = _version(store, "m", "import", "import")
        evidence = store.add_evidence(
            source="format-check",
            url="",
            retrieved_at=NOW,
            matched_identifier=SHA,
            body=b"{}",
        )
        first = store.add_claim_check(
            model_id="m",
            version=version,
            entry_identifier=SHA,
            claim="code_free",
            run_id=None,
            outcome="unreadable",
            measured_format=None,
            measured_can_run_code=None,
            reason="hub returned HTTP 403",
            evidence_id=evidence,
        )
        second = store.add_claim_check(
            model_id="m",
            version=version,
            entry_identifier=SHA,
            claim="code_free",
            run_id=None,
            outcome="confirmed",
            measured_format="safetensors",
            measured_can_run_code=False,
            reason=None,
            evidence_id=evidence,
        )
        assert second > first
        latest = store.latest_claim_check("m", version, SHA)
        assert latest is not None
        assert latest["outcome"] == "confirmed"
        assert latest["measured_can_run_code"] is False
        assert latest["checked_at"] == "2026-11-12T09:00:00Z"
        assert store.latest_claim_check("m", version, SHA, claim="identity") is None
        assert [check["outcome"] for check in store.claim_checks("m", version)] == [
            "unreadable",
            "confirmed",
        ]


@pytest.mark.parametrize(
    ("field", "value"), [("claim", "licence"), ("outcome", "probably"), ("version", 0)]
)
def test_claim_check_values_are_limited(tmp_path: Path, field: str, value: object) -> None:
    with _store(tmp_path / "md.db") as store:
        version = _version(store, "m", "import", "import")
        evidence = store.add_evidence(
            source="format-check", url="", retrieved_at=NOW, matched_identifier=SHA, body=b"{}"
        )
        values = {
            "model_id": "m",
            "version": version,
            "entry_identifier": SHA,
            "claim": "code_free",
            "run_id": None,
            "outcome": "confirmed",
            "measured_format": "safetensors",
            "measured_can_run_code": False,
            "reason": None,
            "evidence_id": evidence,
        }
        values[field] = value
        with pytest.raises(sqlite3.IntegrityError):
            store.add_claim_check(**values)  # type: ignore[arg-type]


def test_a_pre_003_database_gains_the_additions_on_open(tmp_path: Path) -> None:
    path = tmp_path / "old.db"
    pre_003_database(path)
    with _store(path) as store:
        assert "origin" in store.columns("model_versions")
        assert "format_origin" in store.columns("inventory_entries")
        assert "claim_checks" in store.tables()
        assert store.get_version("from-record", 1)["origin"] == "record"
        assert store.get_version("legacy", 1)["origin"] is None
        assert store.entries("legacy", 1)[0]["format_origin"] is None
        assert "format_claim_contradicted" in _check_values(store.conn, "watch_events")
        # The versions stay immutable after the back-fill.
        with pytest.raises(sqlite3.IntegrityError):
            store.conn.execute("UPDATE model_versions SET origin = 'import'")
    with _store(path) as store:  # opening again changes nothing
        assert store.get_version("legacy", 1)["origin"] is None
        assert store.get_version("from-record", 1)["origin"] == "record"


def test_the_back_fill_keeps_every_other_field(tmp_path: Path) -> None:
    path = tmp_path / "old.db"
    pre_003_database(path)
    with _store(path) as store:
        record = store.get_version("from-record", 1)
    assert record["registration_record_sha256"] == "c" * 64
    assert record["inventory"] == json.loads("{}")
    assert record["registered_at"] == "2026-11-01T00:00:00Z"


# --- Review F5: the upgrade is one transaction and recovers from an interrupted one ---------------


def _columns(path: Path, table: str) -> set[str]:
    conn = sqlite3.connect(path)
    try:
        return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
    finally:
        conn.close()


def test_a_failed_upgrade_leaves_the_old_database_as_it_was(tmp_path: Path) -> None:
    path = tmp_path / "old.db"
    pre_003_database(path)
    conn = sqlite3.connect(path)
    with conn:  # makes the back-fill fail after the new columns would have been added
        conn.execute(
            "CREATE TRIGGER fail_back_fill BEFORE UPDATE ON model_versions"
            " BEGIN SELECT RAISE(ABORT, 'interrupted'); END"
        )
    conn.close()
    with pytest.raises(sqlite3.IntegrityError, match="interrupted"):
        _store(path)
    assert "origin" not in _columns(path, "model_versions")
    assert "format_origin" not in _columns(path, "inventory_entries")
    conn = sqlite3.connect(path)
    with conn:
        conn.execute("DROP TRIGGER fail_back_fill")
    conn.close()
    with _store(path) as store:
        assert store.get_version("from-record", 1)["origin"] == "record"
        with pytest.raises(sqlite3.IntegrityError):  # the guard is back
            store.conn.execute("UPDATE model_versions SET origin = 'import'")


def test_a_back_fill_an_earlier_release_did_not_finish_is_completed_on_open(
    tmp_path: Path,
) -> None:
    path = tmp_path / "old.db"
    pre_003_database(path)
    conn = sqlite3.connect(path)
    with conn:  # what an interrupted earlier upgrade left: the columns, but no back-fill
        conn.execute("ALTER TABLE model_versions ADD COLUMN origin TEXT")
        conn.execute("ALTER TABLE inventory_entries ADD COLUMN format_origin TEXT")
    conn.close()
    with _store(path) as store:
        assert store.get_version("from-record", 1)["origin"] == "record"
        assert store.get_version("legacy", 1)["origin"] is None


def _old_watch_events(path: Path, rows: int, leftover_rows: int, dropped: bool) -> None:
    """A pre-003 database with a ``watch_events_widened`` left by an interrupted rebuild."""
    pre_003_database(path)
    conn = sqlite3.connect(path)
    values = (
        "legacy",
        1,
        SHA,
        "pickle_format",
        "2026-11-01T00:00:00Z",
        "2026-11-01T00:00:00Z",
    )
    insert = (
        "INSERT INTO {} (model_id, version, entry_identifier, kind, first_seen, last_seen)"
        " VALUES (?, ?, ?, ?, ?, ?)"
    )
    with conn:
        for _ in range(rows):
            conn.execute(insert.format("watch_events"), values)
        conn.execute("CREATE TABLE watch_events_widened AS SELECT * FROM watch_events WHERE 0")
        for _ in range(leftover_rows):
            conn.execute(insert.format("watch_events_widened"), values)
        if dropped:
            conn.execute("DROP TABLE watch_events")
    conn.close()


def test_a_leftover_rebuild_copy_is_dropped_when_the_old_table_still_holds_the_rows(
    tmp_path: Path,
) -> None:
    path = tmp_path / "old.db"
    _old_watch_events(path, rows=1, leftover_rows=0, dropped=False)
    with _store(path) as store:
        assert "watch_events_widened" not in store.tables()
        assert len(store.watch_events("legacy", 1)) == 1
        assert "format_claim_contradicted" in _check_values(store.conn, "watch_events")


def test_a_leftover_rebuild_copy_takes_the_place_of_a_dropped_table(tmp_path: Path) -> None:
    path = tmp_path / "old.db"
    _old_watch_events(path, rows=1, leftover_rows=1, dropped=True)
    with _store(path) as store:
        assert "watch_events_widened" not in store.tables()
        assert len(store.watch_events("legacy", 1)) == 1
        assert "format_claim_contradicted" in _check_values(store.conn, "watch_events")

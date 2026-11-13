"""Feature 004 upgrade of a database written before it (T008, data-model.md, research S2).

``tests/fixtures/db/schema-pre-004.sql`` is the schema of ``main`` at ``c07c14d`` with one model,
one version, an open ``weight_file_scan`` alert, a dismissed alert and one check run. Opening it
read-write adds the new tables and columns, rebuilds ``alerts`` so its kind check accepts
``globals_policy`` and keeps every row and id; opening it read-only writes nothing.
"""

from __future__ import annotations

import contextlib
import hashlib
import sqlite3
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from model_dependabot.store import Store

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
PRE_004 = FIXTURES / "db" / "schema-pre-004.sql"
NOW = datetime(2026, 11, 13, 9, 0, tzinfo=UTC)
SHA = "a" * 64


def pre_004_database(path: Path) -> Path:
    conn = sqlite3.connect(path)
    conn.executescript(PRE_004.read_text(encoding="utf-8"))
    conn.close()
    return path


def _dump(path: Path) -> tuple[list[tuple[str, str]], list[str]]:
    conn = sqlite3.connect(path)
    try:
        schema = sorted(
            (row[0], row[1] or "")
            for row in conn.execute(
                "SELECT name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"
            )
        )
        return schema, list(conn.iterdump())
    finally:
        conn.close()


def _alerts(path: Path) -> list[tuple[object, ...]]:
    conn = sqlite3.connect(path)
    try:
        return conn.execute(
            "SELECT alert_id, kind, state, cause, dismissal_reason, dismissed_by FROM alerts"
            " ORDER BY alert_id"
        ).fetchall()
    finally:
        conn.close()


def _links(path: Path) -> list[tuple[object, ...]]:
    conn = sqlite3.connect(path)
    try:
        return conn.execute("SELECT * FROM alert_evidence ORDER BY alert_id").fetchall()
    finally:
        conn.close()


def test_opening_adds_the_tables_and_columns(tmp_path: Path) -> None:
    path = pre_004_database(tmp_path / "old.db")
    with Store(path, now=lambda: NOW) as store:
        tables = store.tables()
        assert {"global_exceptions", "file_scans", "check_run_overview"} <= tables
        assert {"globals_policy", "globals_policy_set_by", "globals_policy_set_at"} <= (
            store.columns("models")
        )
        assert "excepted_at" in store.columns("alerts")
        model = store.get_model("legacy")
        assert model["globals_policy"] == "default"
        assert model["globals_policy_set_by"] is None
        info = {row["name"]: row for row in store.conn.execute("PRAGMA table_info(models)")}
        assert info["globals_policy"]["notnull"] == 1
        assert info["globals_policy"]["dflt_value"] == "'default'"


def test_every_alert_keeps_its_id_state_and_evidence(tmp_path: Path) -> None:
    path = pre_004_database(tmp_path / "old.db")
    before, links = _alerts(path), _links(path)
    Store(path, now=lambda: NOW).close()
    assert _alerts(path) == before
    assert _links(path) == links
    with Store(path, now=lambda: NOW) as store:
        assert [store.get_alert(1)["excepted_at"], store.get_alert(2)["excepted_at"]] == [
            None,
            None,
        ]
        assert store.get_alert(1)["evidence_ids"] == [1]


def test_the_alerts_kind_check_accepts_globals_policy(tmp_path: Path) -> None:
    path = pre_004_database(tmp_path / "old.db")
    with Store(path, now=lambda: NOW) as store:
        alert_id = store.insert_alert(
            model_id="legacy",
            kind="globals_policy",
            cause_key=f"globals_policy:{SHA}",
            cause={"identifier": f"sha256:{SHA}"},
            severity="MODERATE",
            severity_origin="policy",
            opened_in_version=1,
            evidence_ids=[1],
        )
        assert store.get_alert(alert_id)["kind"] == "globals_policy"


def test_the_rebuild_recreates_the_one_open_alert_index(tmp_path: Path) -> None:
    path = pre_004_database(tmp_path / "old.db")
    with Store(path, now=lambda: NOW) as store:
        index = store.conn.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'index'"
            " AND name = 'one_open_alert_per_cause'"
        ).fetchone()
        assert index is not None
        assert "WHERE state = 'open'" in index["sql"]
        with pytest.raises(sqlite3.IntegrityError):
            store.insert_alert(
                model_id="legacy",
                kind="weight_file_scan",
                cause_key=f"weight_file_scan:sha256:{SHA}",
                cause={},
                severity="HIGH",
                severity_origin="policy",
                opened_in_version=1,
                evidence_ids=[],
            )


def test_a_second_open_changes_nothing(tmp_path: Path) -> None:
    path = pre_004_database(tmp_path / "old.db")
    Store(path, now=lambda: NOW).close()
    first = _dump(path)
    Store(path, now=lambda: NOW).close()
    assert _dump(path) == first


class _InterruptedRebuild(Store):
    """A store whose open is interrupted inside the ``alerts`` rebuild, before it commits."""

    @contextlib.contextmanager
    def _atomic(self) -> Iterator[None]:
        with super()._atomic():
            yield
            row = self.conn.execute(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'alerts'"
            ).fetchone()
            if row is not None and "'globals_policy'" in row["sql"]:
                raise KeyboardInterrupt("interrupted inside the alerts rebuild")


def test_an_interrupted_rebuild_leaves_the_old_table_and_index(tmp_path: Path) -> None:
    path = pre_004_database(tmp_path / "old.db")
    conn = sqlite3.connect(path)
    old_table, old_index = (
        conn.execute("SELECT sql FROM sqlite_master WHERE name = ?", (name,)).fetchone()[0]
        for name in ("alerts", "one_open_alert_per_cause")
    )
    conn.close()
    before = _alerts(path)
    with pytest.raises(KeyboardInterrupt):
        _InterruptedRebuild(path, now=lambda: NOW)
    conn = sqlite3.connect(path)
    try:
        assert conn.execute("SELECT sql FROM sqlite_master WHERE name = 'alerts'").fetchone()[
            0
        ] == (old_table)
        assert (
            conn.execute(
                "SELECT sql FROM sqlite_master WHERE name = 'one_open_alert_per_cause'"
            ).fetchone()[0]
            == old_index
        )
        assert "alerts_rebuilt" not in {
            row[0] for row in conn.execute("SELECT name FROM sqlite_master")
        }
    finally:
        conn.close()
    assert _alerts(path) == before
    # The next ordinary open finishes the upgrade.
    with Store(path, now=lambda: NOW) as store:
        assert "excepted_at" in store.columns("alerts")
    assert _alerts(path) == before


def test_a_read_only_open_reads_the_defaults_and_writes_nothing(tmp_path: Path) -> None:
    path = pre_004_database(tmp_path / "old.db")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    store = Store.open_read_only(path, now=lambda: NOW)
    try:
        model = store.get_model("legacy")
        assert model["globals_policy"] == "default"
        assert model["globals_policy_set_by"] is None
        assert model["globals_policy_set_at"] is None
        assert store.exceptions(include_inactive=True) == []
        assert store.latest_file_scan(SHA) is None
        assert store.check_run_overview(1) == []
        assert store.get_alert(1)["excepted_at"] is None
    finally:
        store.close()
    assert hashlib.sha256(path.read_bytes()).hexdigest() == digest

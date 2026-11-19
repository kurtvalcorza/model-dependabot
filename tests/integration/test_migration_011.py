"""Feature 011 upgrade of a database written before it (T008, data-model.md, research L2).

``tests/fixtures/db/schema-pre-011.sql`` is the schema of ``main`` at ``6e146c1`` with one model, a
version of origin ``manifest`` and a legacy one (null origin), each with a ``base_model`` entry, an
open ``base_model_disabled`` alert, a watch event and one check run. Opening it read-write adds
``lineage_edges`` and widens ``watch_events``; opening it read-only writes nothing and reads
synthesised ``unspecified`` edges.
"""

from __future__ import annotations

import hashlib
import shutil
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from model_dependabot.store import Store

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
PRE_011 = FIXTURES / "db" / "schema-pre-011.sql"
NOW = datetime(2026, 11, 20, 9, 0, tzinfo=UTC)
PURL = "pkg:huggingface/example-org/base-a@0123456789abcdef0123456789abcdef01234567"


def pre_011_database(path: Path) -> Path:
    conn = sqlite3.connect(path)
    conn.executescript(PRE_011.read_text(encoding="utf-8"))
    conn.close()
    return path


def _schema(path: Path) -> list[tuple[str, str, str]]:
    conn = sqlite3.connect(path)
    try:
        rows = conn.execute("SELECT type, name, sql FROM sqlite_master ORDER BY type, name")
        return [(row[0], row[1], row[2] or "") for row in rows]
    finally:
        conn.close()


def test_opening_adds_the_edge_table_and_keeps_every_row(tmp_path: Path) -> None:
    db = pre_011_database(tmp_path / "md.db")
    with Store(db, now=lambda: NOW) as store:
        names = {name for _, name, _ in _schema(db)}
        assert {"lineage_edges", "lineage_edge_identity"} <= names
        assert {"lineage_edges_no_update", "lineage_edges_no_delete"} <= names
        alert = store.get_alert(1)
        assert alert is not None
        assert (alert["state"], alert["kind"]) == ("open", "base_model_disabled")
        assert [e["evidence_id"] for e in store.alert_evidence(1)] == [1]
        [event] = store.watch_events("legacy", 2)
        assert (event["watch_event_id"], event["kind"]) == (7, "base_model_new_revision")
        assert [e["evidence_id"] for e in event["evidence"]] == [1]
        new = store.record_watch_event(
            model_id="legacy",
            version=2,
            entry_identifier="model:parent@1/x",
            kind="lineage_inherited",
            detail={},
            evidence_ids=[1],
        )
        assert new > 7
    first = _schema(db)
    Store(db, now=lambda: NOW).close()
    assert _schema(db) == first


def test_a_read_only_open_writes_nothing_and_synthesises_legacy_edges(tmp_path: Path) -> None:
    db = pre_011_database(tmp_path / "md.db")
    before = hashlib.sha256(db.read_bytes()).hexdigest()
    store = Store.open_read_only(db, now=lambda: NOW)
    try:
        assert "lineage_edges" not in store.tables()
        [manifest] = store.edges("legacy", 1)
        [legacy] = store.edges("legacy", 2)
        all_edges = store.all_edges()
    finally:
        store.close()
    assert hashlib.sha256(db.read_bytes()).hexdigest() == before
    assert (manifest["relationship"], manifest["origin"], manifest["state"]) == (
        "unspecified",
        "manifest",
        "owner",
    )
    assert (manifest["source_key"], manifest["entry_identifier"]) == ("base_model", PURL)
    assert (manifest["parent_repo"], manifest["edge_id"]) == ("example-org/base-a", None)
    assert (legacy["origin"], legacy["state"]) == (None, "unverified")
    assert sorted(all_edges) == [("legacy", 1), ("legacy", 2)]


def test_an_upgraded_legacy_version_still_reads_synthesised_edges(tmp_path: Path) -> None:
    db = pre_011_database(tmp_path / "md.db")
    copy = shutil.copy(db, tmp_path / "copy.db")
    with Store(copy, now=lambda: NOW) as store:
        assert store.conn.execute("SELECT count(*) FROM lineage_edges").fetchone()[0] == 0
        [edge] = store.edges("legacy", 1)
        assert edge["relationship"] == "unspecified"
        assert store.version_exists("legacy", 2) and not store.version_exists("legacy", 3)

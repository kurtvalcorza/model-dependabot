"""Lock-entry environment markers on a database written before them (issue #28).

``tests/fixtures/db/schema-pre-028.sql`` is the schema of ``main`` at ``0c2a5ee`` with one model, an
``import`` version 1 and a ``manifest`` version 2, each holding ``pillow==9.0.0``, an open
``package_advisory`` alert on it, its evidence row and one check run. Opening it read-write adds
``inventory_entries.marker`` and leaves every old row's marker null: not recorded, which the
advisory view tells apart from a package recorded with no marker. A read-only open writes nothing.
"""

from __future__ import annotations

import hashlib
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from model_dependabot.assurance.advice import (
    MARKER_LIMITATION,
    MARKER_NOT_IMPORTED,
    advice_text,
    advice_view,
)
from model_dependabot.store import Store

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
PRE_028 = FIXTURES / "db" / "schema-pre-028.sql"
NOW = datetime(2026, 11, 20, 9, 0, tzinfo=UTC)
PILLOW = "pkg:pypi/pillow@9.0.0"
NOT_RECORDED = {"state": "not_recorded", "expression": None}


def pre_028_database(path: Path) -> Path:
    conn = sqlite3.connect(path)
    conn.executescript(PRE_028.read_text(encoding="utf-8"))
    conn.close()
    return path


def _columns(path: Path) -> list[str]:
    conn = sqlite3.connect(path)
    try:
        return [row[1] for row in conn.execute("PRAGMA table_info(inventory_entries)")]
    finally:
        conn.close()


def _schema(path: Path) -> list[tuple[str, str]]:
    conn = sqlite3.connect(path)
    try:
        rows = conn.execute("SELECT name, sql FROM sqlite_master ORDER BY type, name")
        return [(row[0], row[1] or "") for row in rows]
    finally:
        conn.close()


def _texts(items: list[dict]) -> list[str]:
    return [item["text"] for item in items]


def test_the_fixture_predates_the_marker_column(tmp_path: Path) -> None:
    assert "marker" not in _columns(pre_028_database(tmp_path / "md.db"))


def test_opening_adds_the_column_and_keeps_old_markers_unknown(tmp_path: Path) -> None:
    db = pre_028_database(tmp_path / "md.db")
    with Store(db, now=lambda: NOW) as store:
        assert "marker" in _columns(db)
        assert [e["marker"] for v in (1, 2) for e in store.entries("legacy", v)] == [None, None]
        alert = store.get_alert(1)
        assert alert is not None and alert["state"] == "open"
        view = advice_view(store, alert)
    places = view["entry"]["places"]
    assert [(p["version"], p["marker"]) for p in places] == [(2, NOT_RECORDED), (1, NOT_RECORDED)]
    # places[0] is the manifest version 2, recorded before markers were stored.
    assert _texts(view["limitations"])[-1] == MARKER_LIMITATION
    assert "recorded before environment markers were stored" in MARKER_LIMITATION
    assert "v2 manifest, [environment] lock, 9.0.0, marker not recorded" in advice_text(view)
    first = _schema(db)
    Store(db, now=lambda: NOW).close()
    assert _schema(db) == first


def test_a_version_registered_after_the_upgrade_records_its_markers(tmp_path: Path) -> None:
    db = pre_028_database(tmp_path / "md.db")
    entry = {
        "kind": "package",
        "identifier": PILLOW,
        "pinned": True,
        "name": "pillow",
        "version": "9.0.0",
        "hashes": ["sha256:" + "ab" * 32],
    }
    with Store(db, now=lambda: NOW) as store:
        store.add_version("legacy", {}, "f" * 64, [entry | {"marker": ""}], origin="manifest")
        store.add_version(
            "legacy",
            {},
            "a" * 64,
            [entry | {"marker": 'sys_platform == "linux"'}],
            origin="manifest",
        )
        assert [e["marker"] for e in store.entries("legacy", 3)] == [""]
        assert [e["marker"] for e in store.entries("legacy", 4)] == ['sys_platform == "linux"']
        alert = store.get_alert(1)
        assert alert is not None
        view = advice_view(store, alert)
    markers = [p["marker"] for p in view["entry"]["places"]]
    assert markers == [
        {"state": "set", "expression": 'sys_platform == "linux"'},
        {"state": "none", "expression": None},
        NOT_RECORDED,
        NOT_RECORDED,
    ]
    limitations = _texts(view["limitations"])
    assert MARKER_LIMITATION not in limitations and MARKER_NOT_IMPORTED not in limitations


def test_a_read_only_open_writes_nothing_and_reads_markers_as_unknown(tmp_path: Path) -> None:
    db = pre_028_database(tmp_path / "md.db")
    before = hashlib.sha256(db.read_bytes()).hexdigest()
    store = Store.open_read_only(db, now=lambda: NOW)
    try:
        assert "marker" not in store.columns("inventory_entries")
        assert [e["marker"] for e in store.entries("legacy", 2)] == [None]
        alert = store.get_alert(1)
        assert alert is not None
        view = advice_view(store, alert)
    finally:
        store.close()
    assert hashlib.sha256(db.read_bytes()).hexdigest() == before
    assert "marker" not in _columns(db)
    assert view["entry"]["places"][0]["marker"] == NOT_RECORDED
    assert _texts(view["limitations"])[-1] == MARKER_LIMITATION

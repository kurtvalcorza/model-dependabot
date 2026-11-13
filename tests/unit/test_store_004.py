"""Store rules of feature 004 (T009, data-model.md).

Global exceptions are never deleted and only their revocation can be set, once; the latest file
scan per hash decides; the check overview keeps its run-wide row under ``model_id = ''``; and
``latest_alert`` returns the most recent alert for a cause in any state.
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from model_dependabot.store import Store

NOW = datetime(2026, 11, 13, 9, 0, tzinfo=UTC)
SHA = "b" * 64


@pytest.fixture
def store(tmp_path: Path) -> Store:
    with Store(tmp_path / "md.db", now=lambda: NOW) as opened:
        opened.add_model("m")
        yield opened


def _evidence(store: Store) -> int:
    return store.add_evidence(
        source="test",
        url="test:1",
        retrieved_at=NOW,
        matched_identifier=f"sha256:{SHA}",
        body=b"{}",
    )


def _exception_row(store: Store) -> int:
    evidence_id = _evidence(store)
    with store.conn:
        cursor = store.conn.execute(
            "INSERT INTO global_exceptions (module, name, sha256, reason, accepted_by,"
            " recorded_at, evidence_id) VALUES ('os', 'system', ?, 'reviewed', 'Owner', ?, ?)",
            (SHA, "2026-11-13T09:00:00Z", evidence_id),
        )
    return int(cursor.lastrowid)


# --- global exceptions ---------------------------------------------------------------------------


def test_an_exception_row_cannot_be_deleted(store: Store) -> None:
    exception_id = _exception_row(store)
    with pytest.raises(sqlite3.IntegrityError), store.conn:
        store.conn.execute("DELETE FROM global_exceptions WHERE exception_id = ?", (exception_id,))


@pytest.mark.parametrize(
    "assignment",
    ["reason = 'other'", "sha256 = '" + "c" * 64 + "'", "expires_on = '2027-01-01'", "name = 'x'"],
)
def test_only_the_revocation_can_be_set(store: Store, assignment: str) -> None:
    exception_id = _exception_row(store)
    with pytest.raises(sqlite3.IntegrityError), store.conn:
        store.conn.execute(
            f"UPDATE global_exceptions SET {assignment} WHERE exception_id = ?", (exception_id,)
        )


def test_the_revocation_is_set_once_and_all_together(store: Store) -> None:
    exception_id = _exception_row(store)
    with pytest.raises(sqlite3.IntegrityError), store.conn:
        store.conn.execute(
            "UPDATE global_exceptions SET revoked_at = 'now' WHERE exception_id = ?",
            (exception_id,),
        )
    revoke = (
        "UPDATE global_exceptions SET revoked_at = ?, revoked_by = 'Owner',"
        " revoke_reason = 'replaced' WHERE exception_id = ?"
    )
    with store.conn:
        store.conn.execute(revoke, ("2026-11-14T00:00:00Z", exception_id))
    with pytest.raises(sqlite3.IntegrityError), store.conn:
        store.conn.execute(revoke, ("2026-11-15T00:00:00Z", exception_id))


@pytest.mark.parametrize(
    ("module", "name", "sha256"),
    [
        ("os", "system", "B" * 64),
        ("os", "system", "b" * 63),
        ("os", "system", "g" * 64),
        ("os", "system", "sha256:" + "b" * 57),
        ("", "system", SHA),
        ("os", "", SHA),
        ("os.*", "system", SHA),
        ("unknown", "eval", SHA),
        ("os", "unknown_name", SHA),
    ],
)
def test_the_table_refuses_a_malformed_row(
    store: Store, module: str, name: str, sha256: str
) -> None:
    evidence_id = _evidence(store)
    with pytest.raises(sqlite3.IntegrityError), store.conn:
        store.conn.execute(
            "INSERT INTO global_exceptions (module, name, sha256, reason, accepted_by,"
            " recorded_at, evidence_id) VALUES (?, ?, ?, 'reviewed', 'Owner', ?, ?)",
            (module, name, sha256, "2026-11-13T09:00:00Z", evidence_id),
        )


# --- file scans ----------------------------------------------------------------------------------


def test_the_latest_file_scan_per_hash_decides(store: Store) -> None:
    evidence_id = _evidence(store)
    assert store.latest_file_scan(SHA) is None
    for globals_ in (
        [{"module": "os", "name": "system", "safety": "dangerous"}],
        [{"module": "torch", "name": "Size", "safety": "suspicious"}],
    ):
        store.add_file_scan(
            sha256=SHA,
            scanner="picklescan",
            scanner_version="1.0.5",
            complete=True,
            globals=globals_,
            scanned_at=NOW,
            run_id=None,
            evidence_id=evidence_id,
        )
    latest = store.latest_file_scan(SHA)
    assert latest["globals"] == [{"module": "torch", "name": "Size", "safety": "suspicious"}]
    assert latest["complete"] is True
    assert latest["run_id"] is None
    assert latest["scanned_at"] == "2026-11-13T09:00:00Z"
    assert store.latest_file_scan("c" * 64) is None


def test_a_file_scan_hash_has_no_prefix(store: Store) -> None:
    with pytest.raises(sqlite3.IntegrityError):
        store.add_file_scan(
            sha256=f"sha256:{SHA}",
            scanner="picklescan",
            scanner_version="1.0.5",
            complete=True,
            globals=[],
            scanned_at=NOW,
            run_id=None,
            evidence_id=_evidence(store),
        )


# --- the check overview --------------------------------------------------------------------------


def _overview_row(store: Store, run_id: int, model_id: str, source: str) -> None:
    with store.conn:
        store.conn.execute(
            "INSERT INTO check_run_overview (run_id, model_id, version, source, state, entries)"
            " VALUES (?, ?, NULL, ?, 'passed', 0)",
            (run_id, model_id, source),
        )


def test_the_run_wide_row_is_stored_under_an_empty_model_id(store: Store) -> None:
    run_id = store.start_check_run(scope="all")
    _overview_row(store, run_id, "", "osv")
    _overview_row(store, run_id, "m", "osv")
    with pytest.raises(sqlite3.IntegrityError):
        _overview_row(store, run_id, "", "osv")
    with pytest.raises(sqlite3.IntegrityError), store.conn:
        store.conn.execute(
            "INSERT INTO check_run_overview (run_id, model_id, source, state, entries)"
            " VALUES (?, NULL, 'picklescan', 'passed', 0)",
            (run_id,),
        )
    rows = store.check_run_overview(run_id)
    assert [(row["model_id"], row["source"]) for row in rows] == [(None, "osv"), ("m", "osv")]


# --- latest alert --------------------------------------------------------------------------------


def _alert(store: Store, cause_key: str) -> int:
    return store.insert_alert(
        model_id="m",
        kind="weight_file_scan",
        cause_key=cause_key,
        cause={},
        severity="HIGH",
        severity_origin="policy",
        opened_in_version=1,
        evidence_ids=[],
    )


def test_latest_alert_returns_the_most_recent_in_any_state(store: Store) -> None:
    key = f"weight_file_scan:sha256:{SHA}"
    assert store.latest_alert("m", key) is None
    first = _alert(store, key)
    store.close_alert(first, state="dismissed", dismissal_reason="risk_accepted", dismissed_by="O")
    assert store.latest_alert("m", key)["alert_id"] == first
    assert store.latest_alert("m", key)["state"] == "dismissed"
    second = _alert(store, key)
    assert store.latest_alert("m", key)["alert_id"] == second
    assert store.latest_alert("other", key) is None


# --- the globals policy --------------------------------------------------------------------------


def test_set_globals_policy_records_who_and_when(store: Store) -> None:
    assert store.get_model("m")["globals_policy"] == "default"
    model = store.set_globals_policy("m", "strict", set_by="Owner")
    assert (model["globals_policy"], model["globals_policy_set_by"]) == ("strict", "Owner")
    assert model["globals_policy_set_at"] == "2026-11-13T09:00:00Z"
    assert model["format_policy"] == "default"  # separate from the format policy (FR-006)


@pytest.mark.parametrize(("policy", "by"), [("lenient", "Owner"), ("strict", "  ")])
def test_set_globals_policy_refuses_bad_input(store: Store, policy: str, by: str) -> None:
    with pytest.raises(ValueError):
        store.set_globals_policy("m", policy, set_by=by)


def test_set_globals_policy_refuses_an_unknown_model(store: Store) -> None:
    with pytest.raises(KeyError):
        store.set_globals_policy("nobody", "strict", set_by="Owner")

"""Default-policy equivalence (T010, SC-002, FR-007, research S10).

With ``globals_policy = 'default'`` and no exceptions, feature 004 changes no alert and no watch
event: every scenario recorded from the build before it (``tools/record_equivalence_baseline.py``,
``tests/fixtures/equivalence/pre-004-baseline.json``) is replayed and compared row for row. Its new
writes are a ``file_scans`` row for every file the check or the registration scanned.
"""

from __future__ import annotations

import importlib.util
import json
import sqlite3
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
BASELINE = json.loads((FIXTURES / "equivalence" / "pre-004-baseline.json").read_text("utf-8"))


def _scenarios() -> ModuleType:
    name = "equivalence_scenarios"
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(
            name, FIXTURES / "equivalence" / "scenarios.py"
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


SCENARIOS = _scenarios()


def _without_rule_ids(value: Any) -> Any:
    """The ``rule_id`` view field (US4) is not part of the comparison."""
    if isinstance(value, dict):
        return {
            k: _without_rule_ids(v) for k, v in value.items() if k not in ("rule_id", "rule_doc")
        }
    if isinstance(value, list):
        return [_without_rule_ids(item) for item in value]
    return value


def test_the_baseline_names_every_scenario() -> None:
    assert sorted(BASELINE["scenarios"]) == sorted(SCENARIOS.SCENARIOS)


@pytest.mark.parametrize("name", sorted(SCENARIOS.SCENARIOS))
def test_alerts_and_watch_events_equal_the_pre_004_baseline(
    name: str, tmp_path: Path, craft: ModuleType
) -> None:
    replayed = SCENARIOS.run(name, tmp_path, craft)
    assert _without_rule_ids(replayed) == _without_rule_ids(BASELINE["scenarios"][name])


@pytest.mark.parametrize(
    ("name", "db", "files"),
    [
        ("check_weights.dangerous_benign_and_onnx", "md", 2),
        ("check_weights.joblib_incomplete", "md", 1),
        ("register_from_record.round_trip", "direct", 4),
        ("register_from_record.round_trip", "ci", 4),
        ("register_from_record.hub_files", "md", 1),
        ("posix_path.picklescan", "md", 1),
    ],
)
def test_every_scanned_file_has_a_file_scan_row(
    name: str, db: str, files: int, tmp_path: Path, craft: ModuleType
) -> None:
    scenario = SCENARIOS.Scenario(tmp_path, craft)
    SCENARIOS.SCENARIOS[name](scenario)
    conn = sqlite3.connect(scenario.db(db))
    try:
        pickles = {
            row[0].removeprefix("sha256:")
            for row in conn.execute(
                "SELECT identifier FROM inventory_entries WHERE kind = 'weight_file'"
                " AND can_run_code = 1 AND hub_repo IS NULL"
            )
        }
        assert len(pickles) == files
        rows = conn.execute(
            "SELECT sha256, scanner, scanner_version, complete, globals, run_id FROM file_scans"
        ).fetchall()
    finally:
        conn.close()
    assert {row[0] for row in rows} == pickles
    for _sha256, scanner, version, complete, globals_, _run_id in rows:
        assert (scanner, version) == ("picklescan", "1.0.5")
        assert complete in (0, 1)
        assert all(set(item) == {"module", "name", "safety"} for item in json.loads(globals_))


def test_a_posix_path_global_stays_a_suspicious_watch_event(
    tmp_path: Path, craft: ModuleType
) -> None:
    replayed = SCENARIOS.run("posix_path.picklescan", tmp_path, craft)["md"]
    assert replayed["alerts"] == []
    [suspicious] = [e for e in replayed["watch_events"] if e["kind"] == "scan_suspicious"]
    assert json.loads(suspicious["detail"])["suspicious"] == ["pathlib.PosixPath"]


def test_a_recorded_scan_is_a_file_scan_without_a_run(tmp_path: Path, craft: ModuleType) -> None:
    scenario = SCENARIOS.Scenario(tmp_path, craft)
    SCENARIOS.SCENARIOS["register_from_record.hub_files"](scenario)
    conn = sqlite3.connect(scenario.db("md"))
    try:
        [(run_id, scanned_at)] = conn.execute(
            "SELECT run_id, scanned_at FROM file_scans"
        ).fetchall()
    finally:
        conn.close()
    assert run_id is None
    assert scanned_at == "2026-11-13T09:00:00Z"

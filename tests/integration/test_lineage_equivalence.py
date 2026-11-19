"""Legacy ``[base_model]`` equivalence (T010, SC-001, FR-003, research L11).

Every scenario of ``tests/fixtures/equivalence/lineage_scenarios.py`` was recorded once, before any
feature 011 code, into ``pre-011-baseline.json`` by ``tools/record_equivalence_baseline.py``. Each
is replayed on the current build and compared on exactly SC-001's fields: entry identifiers and
gaps, cause keys, the number, states and severities of alerts, watch event kinds and exit codes.
Every other difference is one FR-003 allows (edge fields, the edges in finding evidence, the new
properties on exported ancestors). Each registered version also has one stored edge per
``base_model`` entry: ``unspecified``, origin ``manifest``, state ``owner``, key ``base_model``.
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
BASELINE = json.loads((FIXTURES / "equivalence" / "pre-011-baseline.json").read_text("utf-8"))


def _scenarios() -> ModuleType:
    name = "lineage_scenarios"
    if name not in sys.modules:
        path = FIXTURES / "equivalence" / "lineage_scenarios.py"
        spec = importlib.util.spec_from_file_location(name, path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


SCENARIOS = _scenarios()


def sc001(recorded: dict[str, Any]) -> dict[str, Any]:
    """SC-001's fields of one database's snapshot."""
    return {
        "entries": [
            (e["model_id"], e["version"], e["kind"], e["identifier"], e["pinned"], e["gap_reason"])
            for e in recorded["entries"]
        ],
        "alerts": [
            (a["kind"], a["cause_key"], a["state"], a["severity"]) for a in recorded["alerts"]
        ],
        "watch_event_kinds": [event["kind"] for event in recorded["watch_events"]],
        "exit_codes": [tuple(code) for code in recorded["exit_codes"]],
    }


def test_the_baseline_has_provenance_and_names_every_scenario() -> None:
    assert len(BASELINE["src_tree"]) == 40 and BASELINE["recorded_from"]
    assert sorted(BASELINE["scenarios"]) == sorted(SCENARIOS.SCENARIOS)


@pytest.mark.parametrize("name", sorted(SCENARIOS.SCENARIOS))
def test_each_base_model_scenario_equals_the_pre_011_baseline(
    name: str, tmp_path: Path, craft: ModuleType
) -> None:
    replayed, scenario = SCENARIOS.replay(name, tmp_path, craft)
    assert sorted(replayed) == sorted(BASELINE["scenarios"][name])
    for db, recorded in BASELINE["scenarios"][name].items():
        assert sc001(replayed[db]) == sc001(recorded)
        conn = sqlite3.connect(scenario.db(db))
        try:
            entries = conn.execute(
                "SELECT model_id, version, count(*) FROM inventory_entries"
                " WHERE kind = 'base_model' GROUP BY model_id, version"
            ).fetchall()
            edges = conn.execute(
                "SELECT model_id, version, relationship, origin, state, source_key, gap_reason"
                " FROM lineage_edges ORDER BY edge_id"
            ).fetchall()
            gaps = conn.execute(
                "SELECT model_id, version, gap_reason FROM inventory_entries"
                " WHERE kind = 'base_model' ORDER BY entry_id"
            ).fetchall()
        finally:
            conn.close()
        assert [(m, v) for m, v, _ in entries] == [(m, v) for m, v, *_ in edges]
        assert all(count == 1 for *_, count in entries)
        assert {edge[2:6] for edge in edges} <= {("unspecified", "manifest", "owner", "base_model")}
        assert [(m, v, gap) for m, v, *_, gap in edges] == gaps

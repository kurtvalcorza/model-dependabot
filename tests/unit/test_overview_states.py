"""Overview states and counts (T037, data-model.md Check overview, research S6, D4).

Written after ``assurance/overview.py`` in this pass (see the progress record); it pins the rules.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from model_dependabot.assurance import overview
from model_dependabot.store import Store

ZERO = {"incomplete": 0, "alerts_open": 0}


@pytest.mark.parametrize(
    ("counts", "status", "state"),
    [
        ({"incomplete": 1, "alerts_open": 1}, "failed: down", "failed"),
        ({"incomplete": 0, "alerts_open": 0}, "skipped", "failed"),
        ({"incomplete": 1, "alerts_open": 2}, "ok", "incomplete"),
        ({"incomplete": 0, "alerts_open": 1}, "ok", "alerted"),
        (ZERO, "ok", "passed"),
    ],
)
def test_first_match_wins(counts: dict, status: str, state: str) -> None:
    assert overview.state_of(counts, status) == state


def _row(model: str, source: str, state: str, **counts: int) -> dict:
    base = dict.fromkeys(overview.COUNTS, 0) | counts
    return {"model_id": model, "version": 1, "source": source, "state": state} | base


def test_the_run_wide_row_is_the_worst_state_with_summed_counts() -> None:
    rows = [
        _row("a", "picklescan", "alerted", entries=2, alerts_open=1),
        _row("b", "picklescan", "incomplete", entries=3, incomplete=1),
    ]
    [wide, policy] = overview.run_rows(rows, ["picklescan"], {"picklescan": "ok"})
    assert (wide["state"], wide["entries"], wide["incomplete"]) == ("incomplete", 5, 1)
    assert wide["alerts_open"] == 1
    assert wide["model_id"] is None
    assert policy["source"] == "policy"


def test_a_source_no_model_needed_passes_with_a_note() -> None:
    [wide] = overview.run_rows([], ["osv"], {"osv": "ok"})
    assert (wide["state"], wide["entries"], wide["reason"]) == (
        "passed",
        0,
        "no entry needed this source",
    )


def test_a_failed_source_has_null_counts() -> None:
    [wide] = overview.run_rows([], ["osv"], {"osv": "failed: HTTP 503"})
    assert (wide["state"], wide["reason"], wide["alerts_open"]) == ("failed", "HTTP 503", None)


def test_the_policy_row_counts_pinned_code_capable_weight_files(tmp_path: Path) -> None:
    entries = [
        {"kind": "weight_file", "pinned": 1, "can_run_code": 1},
        {"kind": "weight_file", "pinned": 1, "can_run_code": 0},
        {"kind": "weight_file", "pinned": 0, "can_run_code": 1},
        {"kind": "package", "pinned": 1, "can_run_code": None},
    ]
    with Store(tmp_path / "md.db") as store:
        assert overview.entries_for(store, entries, None, "policy") == 1
        rows = overview.model_rows(
            store,
            model_id="m",
            version=1,
            entries=entries,
            origin=None,
            tally={},
            held=None,
            sources=["picklescan"],
            statuses={"picklescan": "ok"},
        )
    assert [(row["source"], row["dismissals_held"]) for row in rows] == [
        ("picklescan", 0),
        ("policy", 0),
    ]
    assert rows[0]["entries"] == 1  # only the pinned code-capable local file

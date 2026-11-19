"""Runtime use (T014, FR-007, FR-008, research R3)."""

from __future__ import annotations

import ast
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from model_dependabot.assurance import affected
from model_dependabot.assurance.affected import UNKNOWN_WHY, runtime_use
from model_dependabot.store import DISMISSAL_REASONS, Store

MOMENT = datetime(2026, 11, 19, 9, 0, tzinfo=UTC)


def alert(alert_id: int, state: str = "open", **fields: Any) -> dict[str, Any]:
    return {
        "alert_id": alert_id,
        "state": state,
        "dismissal_reason": None,
        "dismissed_by": None,
        "closed_at": None,
        "note": None,
        "cause": {"identifier": "pkg:pypi/pillow@12.3.0"},
        **fields,
    }


DISMISSED = alert(
    3,
    "dismissed",
    dismissal_reason="not_used_at_runtime",
    dismissed_by="Owner",
    closed_at="2026-11-19T09:00:00Z",
    note="not loaded",
)


def test_a_not_used_at_runtime_dismissal_is_a_declaration() -> None:
    use = runtime_use(DISMISSED, [])
    assert use == {
        "state": "declared",
        "polarity": "not_used",
        "basis": {"by": "Owner", "at": "2026-11-19T09:00:00Z", "note": "not loaded", "alert_id": 3},
        "context": [],
    }


@pytest.mark.parametrize("reason", [r for r in DISMISSAL_REASONS if r != "not_used_at_runtime"])
def test_every_other_reason_reads_unknown(reason: str) -> None:
    other = alert(4, "dismissed", dismissal_reason=reason, dismissed_by="Owner")
    use = runtime_use(other, [])
    assert (use["state"], use["polarity"], use["basis"]) == ("unknown", None, {"why": UNKNOWN_WHY})


@pytest.mark.parametrize("state", ["open", "fixed", "withdrawn", "cleared"])
def test_every_other_state_reads_unknown(state: str) -> None:
    assert runtime_use(alert(5, state), [])["state"] == "unknown"


def test_a_second_alert_on_the_same_identifier_names_the_dismissal_as_context() -> None:
    use = runtime_use(alert(7), [DISMISSED, alert(6)])
    assert use["state"] == "unknown"
    assert use["context"] == [{"alert_id": 3, "by": "Owner", "at": "2026-11-19T09:00:00Z"}]


def test_an_alert_reopened_from_a_held_dismissal_reads_unknown() -> None:
    reopened = alert(8, cause={"identifier": "pkg:pypi/pillow@12.3.0", "reopens": [3]})
    use = runtime_use(reopened, [DISMISSED])
    assert use["state"] == "unknown"
    assert [item["alert_id"] for item in use["context"]] == [3]


def test_no_code_path_produces_observed() -> None:
    source = Path(affected.__file__).read_text("utf-8")
    strings = [n.value for n in ast.walk(ast.parse(source)) if isinstance(n, ast.Constant)]
    assert "observed" not in strings


def test_close_alert_stamps_closed_at_on_a_dismissal(tmp_path: Path) -> None:
    # Regression guard for research R3: the declaration's ``at`` is the dismissal's closed_at.
    with Store(tmp_path / "md.db", now=lambda: MOMENT) as store:
        store.add_model("m")
        store.add_version("m", {}, "0" * 64, [])
        alert_id = store.insert_alert(
            model_id="m",
            kind="dataset_not_findable",
            cause_key="dataset_not_findable:x",
            cause={"identifier": "x"},
            severity="LOW",
            severity_origin="policy",
            opened_in_version=1,
            evidence_ids=[],
        )
        store.close_alert(
            alert_id, state="dismissed", dismissal_reason="risk_accepted", dismissed_by="O"
        )
        stored = store.get_alert(alert_id)
        assert stored is not None
        assert stored["closed_at"] == "2026-11-19T09:00:00Z"

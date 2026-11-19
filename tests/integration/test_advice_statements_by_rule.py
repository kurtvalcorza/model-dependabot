"""What is established and what is not, over one alert of every rule ID (T025, US2, SC-003)."""

from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from model_dependabot.cli import main, make_handlers
from model_dependabot.lifecycle import dismiss_alert
from model_dependabot.rules import RULES
from model_dependabot.sources.fetcher import RecordedFetcher
from model_dependabot.store import Store

ROOT = Path(__file__).resolve().parent.parent.parent
VERDICTS = json.loads((ROOT / "tests" / "fixtures" / "advice" / "verdicts.json").read_text("utf-8"))
NOW = datetime(2026, 11, 20, 9, 0, tzinfo=UTC)


def run(db: Path, *argv: str) -> str:
    out = io.StringIO()
    handlers = make_handlers(fetcher=RecordedFetcher(db.parent / "none"), now=lambda: NOW)
    with redirect_stdout(out):
        assert main([*argv, "--db", str(db)], handlers=handlers) == 0
    return out.getvalue()


def advice(db: Path, alert_id: int) -> dict[str, Any]:
    return json.loads(run(db, "alert", "show", str(alert_id), "--advice", "--json"))["advice"]


def strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for item in value.values() for s in strings(item)]
    if isinstance(value, list):
        return [s for item in value for s in strings(item)]
    return []


def verdicts_in(text: str) -> list[str]:
    for item in VERDICTS["allowed"]:
        text = text.replace(item["sentence"], "")
    return [p["phrase"] for p in VERDICTS["phrases"] if p["phrase"] in text.lower()]


def test_every_rule_id_cites_its_own_evidence_and_reads_impact_undetermined(
    advice_db: tuple[Path, dict[str, int]],
) -> None:
    db, ids = advice_db
    seen = set()
    with Store(db, now=lambda: NOW) as store:
        own = {i: {e["evidence_id"] for e in store.alert_evidence(i)} for i in ids.values()}
    for alert_id in ids.values():
        view = advice(db, alert_id)
        seen.add(view["rule_doc"])
        assert view["impact"] == "impact undetermined"
        assert view["established"], alert_id
        for statement in view["established"]:
            assert statement["evidence_ids"] and set(statement["evidence_ids"]) <= own[alert_id]
        assert view["not_established"][0]["text"].startswith("whether this alert affects model ")
    assert seen == {rule.page for rule in RULES}


def test_a_paper_retraction_does_not_call_anything_compromised(
    advice_db: tuple[Path, dict[str, int]],
) -> None:
    db, ids = advice_db
    view = advice(db, ids["paper_retracted"])
    texts = [s["text"] for s in view["not_established"]]
    assert "whether the retraction affects the data this model was trained or evaluated on" in texts
    assert not verdicts_in(" ".join(strings(view)))


def test_a_licence_change_leaves_the_effect_to_the_owner(
    advice_db: tuple[Path, dict[str, int]],
) -> None:
    db, ids = advice_db
    texts = [s["text"] for s in advice(db, ids["licence_changed"])["not_established"]]
    assert any(
        "licence the model was obtained under" in t and "owner's own review" in t for t in texts
    )


def test_a_dismissal_and_an_exception_are_owner_decisions(
    advice_db: tuple[Path, dict[str, int]],
) -> None:
    db, ids = advice_db
    build = __import__("advice_build")
    with Store(db, now=lambda: NOW) as store:
        dismiss_alert(
            store, ids["dataset_not_findable"], reason="risk_accepted", by="Owner", note="ok"
        )
        record = build.except_weight_alert(store, ids["weight_file_scan"])
    dismissed = advice(db, ids["dataset_not_findable"])
    assert dismissed["owner_decision"] == {
        "type": "dismissal",
        "items": [
            {"by": "Owner", "at": "2026-11-20T09:00:00Z", "reason": "risk_accepted", "note": "ok"}
        ],
    }
    assert dismissed["impact"] == "impact undetermined"
    excepted = advice(db, ids["weight_file_scan"])
    [item] = excepted["owner_decision"]["items"]
    assert excepted["owner_decision"]["type"] == "exception"
    assert (item["global"], item["exception_id"], item["by"]) == (
        "os.system",
        record["exception_id"],
        "Owner",
    )
    assert (item["reason"], item["expires_on"]) == ("reviewed", None)
    assert item["evidence_id"] is not None
    assert all(item["evidence_id"] not in s["evidence_ids"] for s in excepted["established"])
    assert excepted["impact"] == "impact undetermined"
    text = run(db, "alert", "show", str(ids["weight_file_scan"]), "--advice")
    assert f"Owner decision: exception {record['exception_id']} for os.system by Owner" in text


def test_no_view_states_an_impact_verdict(advice_db: tuple[Path, dict[str, int]]) -> None:
    db, ids = advice_db
    build = __import__("advice_build")
    with Store(db, now=lambda: NOW) as store:
        dismiss_alert(store, ids["hub_scan"], reason="not_used_at_runtime", by="Owner")
        build.except_weight_alert(store, ids["weight_file_scan"])
    for alert_id in ids.values():
        view = advice(db, alert_id)
        for text in strings(view):
            assert not verdicts_in(text), (alert_id, text)
        assert not verdicts_in(run(db, "alert", "show", str(alert_id), "--advice")), alert_id
    for model in ("advice-model", "unavailable-model", "record-model", "import-model"):
        for state in ("open", "excepted", "closed", "all"):
            assert not verdicts_in(run(db, "alerts", model, "--state", state, "--advice")), model

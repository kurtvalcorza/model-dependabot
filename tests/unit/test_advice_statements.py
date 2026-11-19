"""Established, not established and limitations (T023, FR-009 to FR-011, research R6)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from model_dependabot.assurance.advice import MARKER_LIMITATION, advice_view
from model_dependabot.rules import rule_for, texts_for
from model_dependabot.store import Store

NOW = datetime(2026, 11, 20, 9, 0, tzinfo=UTC)
IMPACT_Q = "whether this alert affects model "


def view(db: Path, alert_id: int) -> dict:
    with Store(db, now=lambda: NOW) as store:
        alert = store.get_alert(alert_id)
        assert alert is not None
        return advice_view(store, alert)


def test_one_statement_per_evidence_row_citing_that_row(
    advice_db: tuple[Path, dict[str, int]],
) -> None:
    db, ids = advice_db
    with Store(db, now=lambda: NOW) as store:
        alert = store.get_alert(ids["package_advisory"])
        assert alert is not None
        rows = [e["evidence_id"] for e in store.alert_evidence(alert["alert_id"])]
        advice = advice_view(store, alert)
    assert [s["evidence_ids"] for s in advice["established"]] == [[row] for row in rows]
    for statement in advice["established"]:
        assert statement["kind"] == "established"
        assert [e["evidence_id"] for e in statement["evidence"]] == statement["evidence_ids"]
        assert statement["text"].startswith("osv.dev reported pkg:pypi/pillow@12.3.0 at ")


def test_a_cleared_alert_states_the_clearance_not_that_the_model_was_never_affected(
    advice_db: tuple[Path, dict[str, int]],
) -> None:
    db, ids = advice_db
    advice = view(db, ids["cleared"])
    assert advice["established"][-1]["text"].startswith("the source cleared the cause")
    assert advice["not_established"][0]["text"] == IMPACT_Q + "advice-model"


def test_redacted_fields_are_listed_on_the_statement(
    advice_db: tuple[Path, dict[str, int]],
) -> None:
    db, ids = advice_db
    [statement] = view(db, ids["dataset_retracted"])["established"]
    assert statement["text"].endswith("; redacted: author")
    assert statement["evidence"][0]["redacted_fields"] == ["author"]


def test_not_established_order_impact_then_rule_then_conditions(
    advice_db: tuple[Path, dict[str, int]],
) -> None:
    db, ids = advice_db
    texts = [s["text"] for s in view(db, ids["package_advisory"])["not_established"]]
    rule = texts_for("MDB201").not_established
    assert texts[0] == IMPACT_Q + "advice-model"
    assert len(texts) == len(rule) + 1
    assert texts[-1] == "whether pillow is installed where the model runs"
    imported = [s["text"] for s in view(db, ids["imported_package"])["not_established"]]
    assert any("imported declaration" in text for text in imported)
    hub = [s["text"] for s in view(db, ids["hub_scan"])["not_established"]]
    assert any("no local scan read this file" in text for text in hub)
    absent = [s["text"] for s in view(db, ids["record_weight"])["not_established"]]
    assert any("the bytes were not read in this place" in text for text in absent)


def test_an_unresolved_entry_is_not_established(advice_db: tuple[Path, dict[str, int]]) -> None:
    db, ids = advice_db
    with Store(db, now=lambda: NOW) as store:
        alert = store.get_alert(ids["weight_file_scan"])
        assert alert is not None
        alert = alert | {"cause": alert["cause"] | {"identifier": "sha256:" + "cd" * 32}}
        advice = advice_view(store, alert)
    assert advice["entry"]["status"] == "unresolved"
    assert advice["relationship"] is None
    assert any("which inventory entry" in s["text"] for s in advice["not_established"])


def test_limitations_are_the_rule_s_text(advice_db: tuple[Path, dict[str, int]]) -> None:
    db, ids = advice_db
    for name, alert_id in ids.items():
        advice = view(db, alert_id)
        rule_id = advice["rule_doc"].rsplit("/", 1)[-1].removesuffix(".md")
        assert advice["limitations"][0]["text"] == texts_for(rule_id).limitations, name
    package = view(db, ids["package_advisory"])["limitations"]
    assert [s["text"] for s in package][-1] == MARKER_LIMITATION


def test_an_alias_group_is_one_view_with_every_id_and_its_stored_severity(
    advice_db: tuple[Path, dict[str, int]],
) -> None:
    db, ids = advice_db
    advice = view(db, ids["package_advisory"])
    assert advice["severity"]["value"] == "HIGH"
    assert "GHSA-cp9v-662q-vvx9, GHSA-24rc-8hj2-v98c" in advice["review_steps"][0]["text"]
    assert rule_for("package_advisory").page == advice["rule_doc"]

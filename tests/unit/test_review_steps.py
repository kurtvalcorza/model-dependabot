"""The numbered review steps (T031, FR-014, FR-015, constitution III)."""

from __future__ import annotations

import re
import shlex
from datetime import UTC, datetime
from pathlib import Path

import pytest

from model_dependabot.assurance.advice import _values, advice_view, review_steps
from model_dependabot.cli import build_parser
from model_dependabot.rules import CLOSING, PAGES, RULES, rule_for, texts_for
from model_dependabot.store import Store

NOW = datetime(2026, 11, 20, 9, 0, tzinfo=UTC)
SAMPLES = {
    "alert_id": "7",
    "model_id": "demo",
    "identifier": "sha256:" + "a" * 64,
    "location": "weights/model.pkl",
    "package": "pillow",
    "version": "12.3.0",
    "advisory_ids": "GHSA-xxxx",
    "dataset": "10.5281/zenodo.1",
    "paper_doi": "10.1/paper",
    "repo": "owner/repo",
    "item": "pkg:huggingface/owner/repo@0",
    "rule_doc": "docs/rules/MDB101.md",
}


def fixture_alerts(db: Path, ids: dict[str, int]) -> dict[str, dict]:
    with Store(db, now=lambda: NOW) as store:
        alerts = [store.get_alert(i) for i in ids.values()]
    return {rule_for(a["kind"]).rule_id: a for a in alerts if a is not None}


def test_every_placeholder_is_in_the_fixture_alert_s_cause(
    advice_db: tuple[Path, dict[str, int]],
) -> None:
    db, ids = advice_db
    by_rule = fixture_alerts(db, ids)
    assert set(by_rule) == {rule.rule_id for rule in RULES}
    for rule_id, alert in by_rule.items():
        texts = texts_for(rule_id)
        used = {
            name
            for text in (*texts.steps, *texts.not_established)
            for name in re.findall(r"\{([a-z_]+)\}", text)
        }
        values = _values(alert)
        missing = sorted(name for name in used if not values.get(name))
        assert not missing, (rule_id, missing)


def test_two_alerts_of_one_rule_differ_only_in_substituted_values(
    advice_db: tuple[Path, dict[str, int]],
) -> None:
    db, ids = advice_db
    with Store(db, now=lambda: NOW) as store:
        first = store.get_alert(ids["weight_file_scan"])
        second = store.get_alert(ids["record_weight"])
        assert first is not None and second is not None
        one, two = review_steps(first), review_steps(second)
    assert len(one) == len(two)
    differ = [(a["text"], b["text"]) for a, b in zip(one, two, strict=True) if a != b]
    assert differ

    def neutral(text: str, alert: dict) -> str:
        for value, mark in ((alert["cause"]["location"], "@"), (alert["model_id"], "%")):
            text = text.replace(value, mark)
        return text.replace(f"alert show {alert['alert_id']}", "alert show #").replace(
            f"alert dismiss {alert['alert_id']}", "alert dismiss #"
        )

    for a, b in differ:
        assert neutral(a, first) == neutral(b, second)


@pytest.mark.parametrize("rule", RULES, ids=lambda rule: rule.rule_id)
def test_the_last_step_says_how_the_alert_closes(rule) -> None:
    alert = {
        "alert_id": 1,
        "model_id": "m",
        "kind": rule.kind,
        "cause": {"identifier": "x"},
    }
    steps = review_steps(alert)
    assert [step["number"] for step in steps] == list(range(1, len(steps) + 1))
    assert steps[-1]["text"] == CLOSING + texts_for(rule.rule_id).closes


@pytest.mark.parametrize("rule", PAGES, ids=lambda rule: rule.rule_id)
def test_every_command_in_a_step_parses(rule) -> None:
    parser = build_parser()
    for step in texts_for(rule.rule_id).steps:
        assert "automatically" not in step.lower(), step
        assert not re.search(r"\b(the tool|model-dependabot) (will|does|records|dismisses)\b", step)
        for command in re.findall(r"`(model-dependabot [^`]+)`", step):
            filled = re.sub(r"\{([a-z_]+)\}", lambda m: SAMPLES[m.group(1)], command)
            parser.parse_args(shlex.split(filled)[1:])


def test_a_step_with_a_missing_value_reads_not_recorded(
    advice_db: tuple[Path, dict[str, int]],
) -> None:
    db, ids = advice_db
    with Store(db, now=lambda: NOW) as store:
        alert = store.get_alert(ids["package_advisory"])
        assert alert is not None
        bare = alert | {"cause": {"identifier": alert["cause"]["identifier"]}}
        steps = advice_view(store, bare)["review_steps"]
    assert "not recorded" in steps[0]["text"]


# --- review round 1, M10-R6: the steps follow what the CLI allows for the alert's state ----------


@pytest.mark.parametrize("state", ["fixed", "withdrawn", "cleared", "dismissed"])
@pytest.mark.parametrize("rule", RULES, ids=lambda rule: rule.rule_id)
def test_a_closed_or_dismissed_alert_is_never_told_to_dismiss(rule, state: str) -> None:
    alert = {"alert_id": 1, "model_id": "m", "kind": rule.kind, "cause": {}, "state": state}
    steps = review_steps(alert)
    assert all("alert dismiss" not in step["text"] for step in steps)
    assert steps[-2]["text"].startswith(f"This alert is {state}, and only an open alert")
    assert steps[-1]["text"] == CLOSING + texts_for(rule.rule_id).closes


@pytest.mark.parametrize("rule", RULES, ids=lambda rule: rule.rule_id)
def test_an_open_alert_keeps_every_step(rule) -> None:
    alert = {"alert_id": 1, "model_id": "m", "kind": rule.kind, "cause": {}, "state": "open"}
    assert len(review_steps(alert)) == len(texts_for(rule.rule_id).steps) + 1

"""The per-model views: alerts by severity, watch events apart, closed history (T048).

FR-018: open alerts by severity, watch events separately and the closed history with each item's
outcome. FR-019 and SC-003: every item carries its evidence (source, retrieval time and the exact
identifier matched).
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from model_dependabot.reports import (
    _cause_text,
    alerts_report,
    alerts_text,
    history_report,
    history_text,
)
from model_dependabot.store import Store

START = datetime(2026, 10, 24, 8, 0, tzinfo=UTC)
MODEL = "m"


class Clock:
    """A store clock that moves one minute on every reading, so close times differ."""

    def __init__(self) -> None:
        self.moment = START

    def __call__(self) -> datetime:
        self.moment += timedelta(minutes=1)
        return self.moment


@pytest.fixture
def store(tmp_path: Path) -> Iterator[Store]:
    with Store(tmp_path / "md.db", now=Clock()) as opened:
        opened.add_model(MODEL)
        opened.add_version(MODEL, {}, "0" * 64, [])
        yield opened


def _alert(store: Store, key: str, severity: str) -> int:
    identifier = f"pkg:pypi/{key}@1.0.0"
    evidence_id = store.add_evidence(
        source="osv.dev",
        url=f"https://api.osv.dev/v1/vulns/GHSA-{key}",
        retrieved_at=START,
        matched_identifier=identifier,
        body=key.encode(),
    )
    return store.insert_alert(
        model_id=MODEL,
        kind="package_advisory",
        cause_key=f"package_advisory:{key}",
        cause={"advisory_id": f"GHSA-{key}", "package": key, "version": "1.0.0", "fixed": []},
        severity=severity,
        severity_origin="database_specific",
        opened_in_version=1,
        evidence_ids=[evidence_id],
    )


def _watch(store: Store) -> None:
    evidence_id = store.add_evidence(
        source="picklescan",
        url="file:model.pt",
        retrieved_at=START,
        matched_identifier="sha256:" + "e" * 64,
        body=b"scan",
    )
    store.record_watch_event(
        model_id=MODEL,
        version=1,
        entry_identifier="sha256:" + "e" * 64,
        kind="pickle_format",
        detail={"format": "pytorch-zip", "suggestion": "safetensors or ONNX"},
        evidence_ids=[evidence_id],
    )


def _seed(store: Store) -> dict[str, int]:
    """Open alerts inserted out of severity order, four closed ones and one watch event."""
    ids = {
        severity.lower(): _alert(store, severity.lower(), severity)
        for severity in ("LOW", "CRITICAL", "UNKNOWN", "HIGH", "MODERATE")
    }
    ids["high2"] = _alert(store, "high2", "HIGH")
    for outcome in ("fixed", "dismissed", "withdrawn", "cleared"):
        ids[outcome] = _alert(store, outcome, "HIGH")
    store.close_alert(ids["fixed"], state="fixed", closed_by_version=2)
    store.close_alert(
        ids["dismissed"],
        state="dismissed",
        dismissal_reason="not_used_at_runtime",
        dismissed_by="Owner",
        note="only used in training",
    )
    store.close_alert(ids["withdrawn"], state="withdrawn")
    store.close_alert(ids["cleared"], state="cleared")
    _watch(store)
    return ids


def test_open_alerts_are_ordered_by_severity(store: Store) -> None:
    ids = _seed(store)
    report = alerts_report(store, MODEL)
    assert [alert["severity"] for alert in report["alerts"]] == [
        "CRITICAL",
        "HIGH",
        "HIGH",
        "MODERATE",
        "LOW",
        "UNKNOWN",
    ]
    # Within a severity, the older alert comes first.
    highs = [alert["alert_id"] for alert in report["alerts"] if alert["severity"] == "HIGH"]
    assert highs == [ids["high"], ids["high2"]]
    assert {alert["state"] for alert in report["alerts"]} == {"open"}
    assert report["model_id"] == MODEL
    assert report["current_version"] == 1


def test_watch_events_are_listed_apart_from_alerts(store: Store) -> None:
    _seed(store)
    report = alerts_report(store, MODEL)
    assert [event["kind"] for event in report["watch_events"]] == ["pickle_format"]
    assert all(alert["kind"] != "pickle_format" for alert in report["alerts"])
    event = report["watch_events"][0]
    assert event["identifier"] == "sha256:" + "e" * 64
    assert event["evidence"][0]["source"] == "picklescan"
    text = alerts_text(report)
    assert text.index("Alerts (6)") < text.index("Watch events (1)")
    assert "pickle_format" in text.split("Watch events (1)")[1]


def test_every_alert_carries_its_evidence(store: Store) -> None:
    _seed(store)
    report = alerts_report(store, MODEL, state="all")
    assert len(report["alerts"]) == 10
    for alert in report["alerts"]:
        assert alert["evidence"], alert
        for evidence in alert["evidence"]:
            assert evidence["source"] == "osv.dev"
            assert evidence["retrieved_at"] == "2026-10-24T08:00:00Z"
            assert evidence["matched_identifier"].startswith("pkg:pypi/")
    # The text view shows the evidence too, so it is one step from the list (SC-003).
    assert "osv.dev" in alerts_text(alerts_report(store, MODEL))


def test_closed_state_lists_only_closed_alerts(store: Store) -> None:
    _seed(store)
    closed = alerts_report(store, MODEL, state="closed")
    assert sorted(alert["state"] for alert in closed["alerts"]) == [
        "cleared",
        "dismissed",
        "fixed",
        "withdrawn",
    ]


def test_history_shows_how_and_when_each_alert_closed(store: Store) -> None:
    ids = _seed(store)
    report = history_report(store, MODEL)
    assert report["model_id"] == MODEL
    items = report["history"]
    # Closed alerts only, oldest closure first.
    assert [item["outcome"] for item in items] == ["fixed", "dismissed", "withdrawn", "cleared"]
    assert [item["alert_id"] for item in items] == [
        ids["fixed"],
        ids["dismissed"],
        ids["withdrawn"],
        ids["cleared"],
    ]
    closed_times = [item["closed_at"] for item in items]
    assert closed_times == sorted(closed_times)
    assert all(time.endswith("Z") for time in closed_times)
    assert items[0]["closed_by_version"] == 2
    dismissed = items[1]
    assert dismissed["dismissal_reason"] == "not_used_at_runtime"
    assert dismissed["dismissed_by"] == "Owner"
    assert dismissed["note"] == "only used in training"
    for item in items:
        assert item["evidence"][0]["matched_identifier"].startswith("pkg:pypi/")


def test_history_text_names_each_outcome_with_its_time(store: Store) -> None:
    _seed(store)
    report = history_report(store, MODEL)
    text = history_text(report)
    for item in report["history"]:
        line = next(line for line in text.splitlines() if f"#{item['alert_id']} " in line)
        assert item["outcome"] in line
        assert item["closed_at"] in line
    assert "not_used_at_runtime by Owner" in text
    assert "osv.dev" in text


def test_empty_history(store: Store) -> None:
    _alert(store, "only", "LOW")
    report = history_report(store, MODEL)
    assert report["history"] == []
    assert "History (0)" in history_text(report)


def test_a_merged_package_alert_names_every_id() -> None:
    cause = {
        "advisory_id": "GHSA-aaaa-bbbb-cccc",
        "advisory_ids": ["GHSA-aaaa-bbbb-cccc", "PYSEC-2026-1"],
        "package": "pillow",
        "version": "12.3.0",
        "fixed": ["13.0.0"],
    }
    text = _cause_text("package_advisory", cause)
    assert text == "GHSA-aaaa-bbbb-cccc (also PYSEC-2026-1) pillow==12.3.0 (fixed: 13.0.0)"
    one = _cause_text("package_advisory", {**cause, "advisory_ids": ["GHSA-aaaa-bbbb-cccc"]})
    assert one == "GHSA-aaaa-bbbb-cccc pillow==12.3.0 (fixed: 13.0.0)"

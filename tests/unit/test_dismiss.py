"""Dismissing an alert with a listed reason (T044; FR-015)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from model_dependabot.cli import EXIT_INVALID_INPUT, EXIT_OK, main, make_handlers
from model_dependabot.lifecycle import DISMISSAL_REASONS, dismiss_alert
from model_dependabot.sources.fetcher import RecordedFetcher
from model_dependabot.store import Store

MOMENT = datetime(2026, 10, 24, 8, 0, tzinfo=UTC)


def _open_alert(store: Store, cause_key: str = "format_policy:" + "a" * 64) -> int:
    if store.get_model("m") is None:
        store.add_model("m")
        store.add_version("m", {}, "0" * 64, [])
    evidence_id = store.add_evidence(
        source="format-policy",
        url="",
        retrieved_at=MOMENT,
        matched_identifier="sha256:" + "a" * 64,
        body=b"{}",
    )
    return store.insert_alert(
        model_id="m",
        kind="format_policy",
        cause_key=cause_key,
        cause={"identifier": "sha256:" + "a" * 64, "location": "model.pkl"},
        severity="MODERATE",
        severity_origin="policy",
        opened_in_version=1,
        evidence_ids=[evidence_id],
    )


@pytest.fixture
def store(tmp_path: Path) -> Store:
    with Store(tmp_path / "md.db", now=lambda: MOMENT) as opened:
        yield opened


def test_the_reasons_are_the_fixed_list() -> None:
    assert DISMISSAL_REASONS == (
        "not_used_at_runtime",
        "risk_accepted",
        "false_positive",
        "fix_not_available",
    )


@pytest.mark.parametrize("reason", DISMISSAL_REASONS)
def test_dismissal_records_reason_person_and_time(store: Store, reason: str) -> None:
    alert_id = _open_alert(store)
    dismiss_alert(store, alert_id, reason=reason, by="Model owner", note="only used offline")
    alert = store.get_alert(alert_id)
    assert alert["state"] == "dismissed"
    assert alert["dismissal_reason"] == reason
    assert alert["dismissed_by"] == "Model owner"
    assert alert["note"] == "only used offline"
    assert alert["closed_at"] == "2026-10-24T08:00:00Z"
    assert alert["closed_by_version"] is None
    assert len(alert["evidence_ids"]) == 1


def test_the_note_is_optional(store: Store) -> None:
    alert_id = _open_alert(store)
    dismiss_alert(store, alert_id, reason="false_positive", by="Model owner")
    alert = store.get_alert(alert_id)
    assert (alert["state"], alert["note"]) == ("dismissed", None)


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"reason": "wont_fix"}, "reason"),
        ({"reason": ""}, "reason"),
        ({"by": "  "}, "who"),
    ],
)
def test_invalid_dismissals_change_nothing(
    store: Store, changes: dict[str, Any], message: str
) -> None:
    alert_id = _open_alert(store)
    arguments = {"reason": "risk_accepted", "by": "Model owner"} | changes
    with pytest.raises(ValueError, match=message):
        dismiss_alert(store, alert_id, **arguments)
    assert store.get_alert(alert_id)["state"] == "open"


def test_only_an_open_alert_can_be_dismissed(store: Store) -> None:
    alert_id = _open_alert(store)
    dismiss_alert(store, alert_id, reason="risk_accepted", by="Model owner")
    with pytest.raises(ValueError, match="not open"):
        dismiss_alert(store, alert_id, reason="risk_accepted", by="Model owner")
    with pytest.raises(ValueError, match="no alert"):
        dismiss_alert(store, 999, reason="risk_accepted", by="Model owner")


# --- the command ---------------------------------------------------------------------------------


@pytest.fixture
def db(tmp_path: Path) -> Path:
    path = tmp_path / "cli.db"
    with Store(path) as opened:
        _open_alert(opened)
    return path


def run(db: Path, tmp_path: Path, *argv: str) -> int:
    handlers = make_handlers(fetcher=RecordedFetcher(tmp_path / "none"))
    return main([*argv, "--db", str(db), "--json"], handlers=handlers)


def test_alert_dismiss_command(
    db: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    argv = ["alert", "dismiss", "1", "--reason", "not_used_at_runtime"]
    argv += ["--note", "the file is never loaded", "--by", "Model owner"]
    assert run(db, tmp_path, *argv) == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["alert_id"] == 1
    assert payload["state"] == "dismissed"
    assert payload["dismissal_reason"] == "not_used_at_runtime"
    assert payload["dismissed_by"] == "Model owner"
    assert payload["note"] == "the file is never loaded"
    assert payload["closed_at"].endswith("Z")

    assert run(db, tmp_path, "alert", "show", "1") == EXIT_OK
    shown = json.loads(capsys.readouterr().out)
    assert (shown["state"], shown["dismissal_reason"]) == ("dismissed", "not_used_at_runtime")


@pytest.mark.parametrize(
    "argv",
    [
        ["alert", "dismiss", "1", "--reason", "wont_fix", "--by", "Model owner"],
        ["alert", "dismiss", "1", "--by", "Model owner"],
        ["alert", "dismiss", "1", "--reason", "risk_accepted"],
        ["alert", "dismiss", "1", "--reason", "risk_accepted", "--by", " "],
        ["alert", "dismiss", "999", "--reason", "risk_accepted", "--by", "Model owner"],
    ],
    ids=["unlisted-reason", "no-reason", "no-person", "blank-person", "unknown-alert"],
)
def test_invalid_dismissal_exits_1_and_changes_nothing(
    db: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str], argv: list[str]
) -> None:
    assert run(db, tmp_path, *argv) == EXIT_INVALID_INPUT
    with Store(db) as store:
        assert store.get_alert(1)["state"] == "open"


def test_dismissing_a_closed_alert_exits_1(db: Path, tmp_path: Path) -> None:
    argv = ["alert", "dismiss", "1", "--reason", "risk_accepted", "--by", "Model owner"]
    assert run(db, tmp_path, *argv) == EXIT_OK
    assert run(db, tmp_path, *argv) == EXIT_INVALID_INPUT

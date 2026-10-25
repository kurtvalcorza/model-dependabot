"""``alerts --json`` and ``history --json`` against contracts/cli.md (T049; US5, FR-018, FR-019).

Offline: the OSV answers are the recordings in ``tests/fixtures/osv``. The model pins the affected
pillow and carries a PyTorch checkpoint, so it has open alerts and a ``pickle_format`` watch event;
version 2 pins the fixed pillow, so the history has closed alerts.
"""

from __future__ import annotations

import json
import shutil
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from model_dependabot.cli import EXIT_INVALID_INPUT, EXIT_OK, main, make_handlers
from model_dependabot.sources.fetcher import RecordedFetcher

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
MODEL = "pillow-model"

ALERTS_KEYS = {"model_id", "current_version", "alerts", "watch_events", "last_check"}
ALERT_KEYS = {
    "alert_id",
    "kind",
    "state",
    "severity",
    "severity_origin",
    "cause",
    "opened_in_version",
    "evidence",
}
CAUSE_KEYS = {"advisory_id", "aliases", "package", "version", "fixed"}
EVIDENCE_KEYS = {"source", "url", "retrieved_at", "matched_identifier", "body_sha256", "detail"}
WATCH_KEYS = {"kind", "identifier", "detail"}
HISTORY_KEYS = {"model_id", "current_version", "history"}
HISTORY_ITEM_KEYS = {
    "alert_id",
    "kind",
    "outcome",
    "severity",
    "cause",
    "opened_in_version",
    "closed_at",
    "closed_by_version",
    "dismissal_reason",
    "dismissed_by",
    "note",
    "evidence",
}
SEVERITIES = ("CRITICAL", "HIGH", "MODERATE", "LOW", "UNKNOWN")


def _manifest(directory: Path, lock: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    shutil.copy(FIXTURES / "locks" / lock, directory / "requirements.txt")
    shutil.copy(FIXTURES / "manifests" / "weights" / "tiny.pt", directory / "model.pt")
    path = directory / "model.toml"
    path.write_text(
        "\n".join(
            [
                "[model]",
                f'id = "{MODEL}"',
                'name = "Contract test model"',
                'owner = "Owner"',
                "",
                "[environment]",
                'lock = "requirements.txt"',
                "",
                "[[weights]]",
                'path = "model.pt"',
                "",
            ]
        ),
        encoding="utf-8",
    )
    return path


@pytest.fixture
def cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> Callable[..., tuple[int, Any]]:
    db = tmp_path / "db" / "md.db"
    handlers = make_handlers(fetcher=RecordedFetcher(FIXTURES / "osv"))

    def invoke(*argv: str) -> tuple[int, Any]:
        code = main([*argv, "--db", str(db), "--json"], handlers=handlers)
        out = capsys.readouterr().out
        return code, json.loads(out) if out.strip() else None

    return invoke


@pytest.fixture
def checked(cli: Callable[..., tuple[int, Any]], tmp_path: Path) -> Callable[..., Any]:
    assert cli("register", str(_manifest(tmp_path / "v1", "vulnerable.txt")))[0] == EXIT_OK
    assert cli("check", MODEL, "--source", "osv,picklescan")[0] == EXIT_OK
    return cli


def _check_evidence(evidence: list[dict[str, Any]]) -> None:
    assert evidence
    for record in evidence:
        assert set(record) >= EVIDENCE_KEYS
        assert record["retrieved_at"].endswith("Z")
        assert len(record["body_sha256"]) == 64
        assert record["matched_identifier"]


def test_alerts_json_matches_the_contract(checked: Callable[..., tuple[int, Any]]) -> None:
    code, payload = checked("alerts", MODEL)
    assert code == EXIT_OK
    assert set(payload) == ALERTS_KEYS
    assert payload["model_id"] == MODEL
    assert payload["current_version"] == 1
    assert payload["alerts"], "the affected pillow raises alerts"
    ranks = [SEVERITIES.index(alert["severity"]) for alert in payload["alerts"]]
    assert ranks == sorted(ranks)
    for alert in payload["alerts"]:
        assert set(alert) >= ALERT_KEYS
        assert alert["state"] == "open"
        assert alert["kind"] == "package_advisory"
        assert set(alert["cause"]) >= CAUSE_KEYS
        assert isinstance(alert["cause"]["aliases"], list)
        assert isinstance(alert["cause"]["fixed"], list)
        _check_evidence(alert["evidence"])
        assert alert["evidence"][0]["source"] == "osv.dev"
    kinds = [event["kind"] for event in payload["watch_events"]]
    assert kinds == ["pickle_format"]
    for event in payload["watch_events"]:
        assert set(event) >= WATCH_KEYS
        assert event["identifier"].startswith("sha256:")
        _check_evidence(event["evidence"])
    assert set(payload["last_check"]) == {"run_id", "trigger", "sources"}
    assert payload["last_check"]["sources"] == {"osv": "ok", "picklescan": "ok"}


def test_alert_show_reaches_the_evidence_in_one_step(
    checked: Callable[..., tuple[int, Any]],
) -> None:
    _, listed = checked("alerts", MODEL)
    first = listed["alerts"][0]
    code, shown = checked("alert", "show", str(first["alert_id"]))
    assert code == EXIT_OK
    assert shown["evidence"] == first["evidence"]


def test_history_json_matches_the_contract(
    checked: Callable[..., tuple[int, Any]], tmp_path: Path
) -> None:
    code, empty = checked("history", MODEL)
    assert code == EXIT_OK
    assert set(empty) == HISTORY_KEYS
    assert empty["history"] == []

    _, opened = checked("alerts", MODEL)
    v2 = _manifest(tmp_path / "v2", "fixed.txt")
    assert checked("register", str(v2), "--model-id", MODEL)[0] == EXIT_OK

    code, payload = checked("history", MODEL)
    assert code == EXIT_OK
    assert set(payload) == HISTORY_KEYS
    assert payload["current_version"] == 2
    assert sorted(item["alert_id"] for item in payload["history"]) == sorted(
        alert["alert_id"] for alert in opened["alerts"]
    )
    for item in payload["history"]:
        assert set(item) == HISTORY_ITEM_KEYS
        assert item["outcome"] == "fixed"
        assert item["closed_by_version"] == 2
        assert item["closed_at"].endswith("Z")
        _check_evidence(item["evidence"])
        assert item["evidence"][-1]["source"] == "inventory"

    _, closed = checked("alerts", MODEL, "--state", "closed")
    assert [alert["state"] for alert in closed["alerts"]] == ["fixed"] * len(opened["alerts"])


def test_history_of_an_unknown_model_is_invalid_input(
    cli: Callable[..., tuple[int, Any]],
) -> None:
    code, payload = cli("history", "no-such-model")
    assert code == EXIT_INVALID_INPUT
    assert payload["error"]["exit_code"] == EXIT_INVALID_INPUT

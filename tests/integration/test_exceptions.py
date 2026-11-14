"""Accepting a reviewed global in one exact file, end to end (T019; spec US1, quickstart 2).

The pickles are crafted opcode bytes built into ``tmp_path`` (``craft.py``) and are never loaded.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from model_dependabot.cli import EXIT_INVALID_INPUT, EXIT_OK, main, make_handlers
from model_dependabot.sources.fetcher import RecordedFetcher

GETATTR = "__builtin__.getattr"
Cli = Callable[..., tuple[int, Any]]


class Clock:
    def __init__(self) -> None:
        self.at = datetime(2026, 11, 13, 9, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.at


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def cli(tmp_path: Path, capsys: pytest.CaptureFixture[str], clock: Clock) -> Cli:
    db = tmp_path / "db" / "md.db"
    handlers = make_handlers(fetcher=RecordedFetcher(tmp_path / "none"), now=clock)

    def invoke(*argv: str) -> tuple[int, Any]:
        code = main([*argv, "--db", str(db), "--json"], handlers=handlers)
        out = capsys.readouterr().out
        return code, json.loads(out) if out.strip() else None

    return invoke


def register(cli: Cli, root: Path, model_id: str, files: dict[str, bytes]) -> dict[str, str]:
    """Register a model with these weight files; the SHA-256 of each, by name."""
    root.mkdir(parents=True)
    lines = ["[model]", f'id = "{model_id}"']
    for name, data in files.items():
        (root / name).write_bytes(data)
        lines += ["", "[[weights]]", f'path = "{name}"']
    (root / "model.toml").write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert cli("register", str(root / "model.toml"))[0] == EXIT_OK
    return {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}


def record(cli: Cli, global_name: str, sha256: str, *extra: str) -> dict[str, Any]:
    code, made = cli(
        "exception", "record", "--global", global_name, "--sha256", sha256,
        "--reason", "reviewed: attribute lookup on layer classes only", "--by", "Owner", *extra,
    )  # fmt: skip
    assert code == EXIT_OK, made
    return made


def check(cli: Cli, *argv: str) -> dict[str, Any]:
    code, payload = cli("check", *argv)
    assert code == EXIT_OK, payload
    return payload


def scan_alerts(cli: Cli, model_id: str) -> dict[str, list[dict[str, Any]]]:
    _, listed = cli("alerts", model_id)
    return {
        "open": [a for a in listed["alerts"] if a["kind"] == "weight_file_scan"],
        "excepted": [a for a in listed["excepted"] if a["kind"] == "weight_file_scan"],
        "events": listed["watch_events"],
    }


def test_independent_test_only_the_excepted_bytes_are_excepted(
    cli: Cli, tmp_path: Path, craft: ModuleType
) -> None:
    pickle = craft.protocol2_getattr()
    zipped = craft.pytorch_zip(pickle)  # the same global, other bytes
    a = register(cli, tmp_path / "a", "model-a", {"pose.pkl": pickle})["pose.pkl"]
    register(cli, tmp_path / "b", "model-b", {"pose.pt": zipped})
    check(cli, "--all", "--source", "picklescan")
    assert len(scan_alerts(cli, "model-a")["open"]) == 1
    assert len(scan_alerts(cli, "model-b")["open"]) == 1

    made = record(cli, GETATTR, a)
    check(cli, "--all", "--source", "picklescan")
    # Scenario 1: excepted, with the exception as its evidence, and no longer counted as open.
    found = scan_alerts(cli, "model-a")
    assert found["open"] == []
    [excepted] = found["excepted"]
    assert excepted["state"] == "excepted"
    [cited] = excepted["cause"]["excepted"]
    assert cited == {
        "global": GETATTR,
        "exception_id": made["exception_id"],
        "accepted_by": "Owner",
        "recorded_at": "2026-11-13T09:00:00Z",
        "expires_on": None,
    }
    exception_evidence = [e for e in excepted["evidence"] if e["source"] == "exception"]
    assert [e["url"] for e in exception_evidence] == [f"exception:{made['exception_id']}"]
    # Scenario 2: other bytes with the same global raise the finding as normal.
    assert len(scan_alerts(cli, "model-b")["open"]) == 1
    # Scenario 3: the other globals of the file are unaffected (still a suspicious watch event).
    suspicious = [e for e in found["events"] if e["kind"] == "scan_suspicious"]
    assert suspicious and "torch.Size" in suspicious[0]["detail"]["suspicious"]

    # The same bytes under a third model are excepted too.
    register(cli, tmp_path / "c", "model-c", {"weights.pkl": pickle})
    check(cli, "model-c", "--source", "picklescan")
    assert [a["state"] for a in scan_alerts(cli, "model-c")["excepted"]] == ["excepted"]
    _, listed = cli("exception", "list")
    [item] = listed["exceptions"]
    assert {(x["model_id"], x["location"]) for x in item["applies_to"]} == {
        ("model-a", "pose.pkl"),
        ("model-c", "weights.pkl"),
    }
    assert item["in_use"] is True


def test_one_exception_of_two_dangerous_globals_keeps_the_alert_open(
    cli: Cli, tmp_path: Path, craft: ModuleType
) -> None:
    sha = register(cli, tmp_path / "m", "two", {"two.pkl": craft.two_dangerous()})["two.pkl"]
    check(cli, "two", "--source", "picklescan")
    made = record(cli, "os.system", sha)
    check(cli, "two", "--source", "picklescan")
    found = scan_alerts(cli, "two")
    assert found["excepted"] == []
    [alert] = found["open"]
    assert alert["state"] == "open"
    assert [x["global"] for x in alert["cause"]["excepted"]] == ["os.system"]
    assert alert["cause"]["excepted"][0]["exception_id"] == made["exception_id"]


def test_an_exception_takes_effect_only_at_a_check_that_asks_a_weight_source(
    cli: Cli, tmp_path: Path, craft: ModuleType
) -> None:
    sha = register(cli, tmp_path / "m", "pose", {"pose.pkl": craft.protocol2_getattr()})["pose.pkl"]
    check(cli, "pose", "--source", "picklescan")
    record(cli, GETATTR, sha)
    assert len(scan_alerts(cli, "pose")["open"]) == 1  # recording changes no alert
    check(cli, "pose", "--source", "osv")
    assert len(scan_alerts(cli, "pose")["open"]) == 1  # FR-010: osv does not apply it
    check(cli, "pose", "--source", "format-check")
    assert len(scan_alerts(cli, "pose")["excepted"]) == 1


def test_revocation_and_expiry_return_the_finding_on_the_same_alert(
    cli: Cli, tmp_path: Path, craft: ModuleType, clock: Clock
) -> None:
    sha = register(cli, tmp_path / "m", "pose", {"pose.pkl": craft.protocol2_getattr()})["pose.pkl"]
    check(cli, "pose", "--source", "picklescan")
    made = record(cli, GETATTR, sha)
    check(cli, "pose", "--source", "picklescan")
    [excepted] = scan_alerts(cli, "pose")["excepted"]

    clock.at = datetime(2026, 11, 14, 9, 0, tzinfo=UTC)
    argv = ("--reason", "new review", "--by", "Lead")
    assert cli("exception", "revoke", str(made["exception_id"]), *argv)[0] == EXIT_OK
    check(cli, "pose", "--source", "picklescan")
    found = scan_alerts(cli, "pose")
    assert found["excepted"] == []
    [back] = found["open"]
    assert back["alert_id"] == excepted["alert_id"]
    assert back["cause"]["released"] == [
        {
            "global": GETATTR,
            "exception_id": made["exception_id"],
            "why": "revoked",
            "at": "2026-11-14T09:00:00Z",
        }
    ]
    assert "excepted" not in back["cause"] or back["cause"]["excepted"] == []
    revocation = [e for e in back["evidence"] if e["source"] == "exception"]
    assert len(revocation) == 2  # the record and its revocation

    expiring = record(cli, GETATTR, sha, "--expires", "2026-11-20")
    check(cli, "pose", "--source", "picklescan")
    assert [a["alert_id"] for a in scan_alerts(cli, "pose")["excepted"]] == [back["alert_id"]]
    clock.at = datetime(2026, 11, 21, 0, 0, tzinfo=UTC)
    check(cli, "pose", "--source", "picklescan")
    [again] = scan_alerts(cli, "pose")["open"]
    assert again["alert_id"] == back["alert_id"]
    assert again["cause"]["released"][-1] == {
        "global": GETATTR,
        "exception_id": expiring["exception_id"],
        "why": "expired",
        "at": "2026-11-21T00:00:00Z",
    }


def test_an_exception_not_in_use(cli: Cli, tmp_path: Path, craft: ModuleType) -> None:
    sha = register(cli, tmp_path / "m", "pose", {"pose.pkl": craft.protocol2_getattr()})["pose.pkl"]
    check(cli, "pose", "--source", "picklescan")
    record(cli, "builtins.eval", sha)  # a global the file does not contain
    hub_bin = "f9343d7d7ec5c3d8bcced056c438fc9f1d3819e9ca3d42418a40857050e10e20"
    record(cli, GETATTR, hub_bin)  # a hash no local scan has seen
    _, listed = cli("exception", "list")
    assert [item["in_use"] for item in listed["exceptions"]] == [False, False]
    assert listed["exceptions"][0]["applies_to"] == [
        {"model_id": "pose", "version": 1, "location": "pose.pkl"}
    ]
    check(cli, "pose", "--source", "picklescan")
    assert len(scan_alerts(cli, "pose")["open"]) == 1


def test_an_unresolved_global_cannot_be_excepted(
    cli: Cli, tmp_path: Path, craft: ModuleType
) -> None:
    sha = register(cli, tmp_path / "m", "odd", {"odd.pkl": craft.unresolved()})["odd.pkl"]
    check(cli, "odd", "--source", "picklescan")
    [alert] = scan_alerts(cli, "odd")["open"]
    assert alert["cause"]["dangerous"] == ["unknown.eval"]
    code, payload = cli(
        "exception", "record", "--global", "unknown.eval", "--sha256", sha,
        "--reason", "r", "--by", "Owner",
    )  # fmt: skip
    assert code == EXIT_INVALID_INPUT
    assert "unknown" in payload["error"]["message"]
    check(cli, "odd", "--source", "picklescan")
    assert [a["alert_id"] for a in scan_alerts(cli, "odd")["open"]] == [alert["alert_id"]]


def test_an_excepted_alert_can_be_dismissed(cli: Cli, tmp_path: Path, craft: ModuleType) -> None:
    sha = register(cli, tmp_path / "m", "pose", {"pose.pkl": craft.protocol2_getattr()})["pose.pkl"]
    check(cli, "pose", "--source", "picklescan")
    record(cli, GETATTR, sha)
    check(cli, "pose", "--source", "picklescan")
    [excepted] = scan_alerts(cli, "pose")["excepted"]
    argv = ("--reason", "risk_accepted", "--by", "Owner")
    code, dismissed = cli("alert", "dismiss", str(excepted["alert_id"]), *argv)
    assert code == EXIT_OK
    assert dismissed["state"] == "dismissed"
    assert scan_alerts(cli, "pose")["excepted"] == []

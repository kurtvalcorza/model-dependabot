"""The ``exception`` commands and ``alerts --state excepted`` (T018, contracts/cli.md)."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from model_dependabot.cli import EXIT_INVALID_INPUT, EXIT_OK, main, make_handlers
from model_dependabot.sources.fetcher import RecordedFetcher

NOW = datetime(2026, 11, 13, 9, 0, tzinfo=UTC)
ITEM = {
    "exception_id",
    "global",
    "module",
    "name",
    "sha256",
    "reason",
    "accepted_by",
    "recorded_at",
    "expires_on",
    "state",
    "revoked",
    "applies_to",
    "in_use",
}
Cli = Callable[..., tuple[int, Any]]


@pytest.fixture
def cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> Cli:
    db = tmp_path / "db" / "md.db"
    handlers = make_handlers(fetcher=RecordedFetcher(tmp_path / "none"), now=lambda: NOW)

    def invoke(*argv: str) -> tuple[int, Any]:
        code = main([*argv, "--db", str(db), "--json"], handlers=handlers)
        out = capsys.readouterr().out
        return code, json.loads(out) if out.strip() else None

    return invoke


@pytest.fixture
def registered(cli: Cli, tmp_path: Path, craft: ModuleType) -> str:
    """A model whose one pickle imports ``__builtin__.getattr``, checked once; its SHA-256."""
    model = tmp_path / "model"
    model.mkdir()
    data = craft.protocol2_getattr()
    (model / "pose.pkl").write_bytes(data)
    manifest = model / "model.toml"
    manifest.write_text('[model]\nid = "pose"\n\n[[weights]]\npath = "pose.pkl"\n', "utf-8")
    assert cli("register", str(manifest))[0] == EXIT_OK
    assert cli("check", "pose", "--source", "picklescan")[0] == EXIT_OK
    import hashlib

    return hashlib.sha256(data).hexdigest()


def _record(cli: Cli, sha256: str, *extra: str) -> tuple[int, Any]:
    return cli(
        "exception",
        "record",
        "--global",
        "__builtin__.getattr",
        "--sha256",
        sha256,
        "--reason",
        "reviewed",
        "--by",
        "Owner",
        *extra,
    )


def test_record_prints_the_exception(cli: Cli, registered: str) -> None:
    code, made = _record(cli, f"sha256:{registered}", "--expires", "2027-01-31")
    assert code == EXIT_OK
    assert set(made) == ITEM
    assert (made["global"], made["module"], made["name"]) == (
        "__builtin__.getattr",
        "__builtin__",
        "getattr",
    )
    assert (made["sha256"], made["state"], made["revoked"]) == (registered, "active", None)
    assert made["expires_on"] == "2027-01-31"
    assert made["applies_to"] == [{"model_id": "pose", "version": 1, "location": "pose.pkl"}]
    assert made["in_use"] is True


@pytest.mark.parametrize(
    "argv",
    [
        ("--global", "getattr", "--sha256", "a" * 64, "--reason", "r", "--by", "O"),
        ("--global", "os.system", "--sha256", "a" * 63, "--reason", "r", "--by", "O"),
        ("--global", "os.system", "--sha256", "a" * 64, "--reason", " ", "--by", "O"),
        ("--global", "os.system", "--sha256", "a" * 64, "--reason", "r", "--by", ""),
        ("--global", "unknown.eval", "--sha256", "a" * 64, "--reason", "r", "--by", "O"),
        (
            "--global",
            "os.system",
            "--sha256",
            "a" * 64,
            "--reason",
            "r",
            "--by",
            "O",
            "--expires",
            "2026-01-01",
        ),
        ("--global", "os.system", "--sha256", "a" * 64, "--reason", "r"),
    ],
)
def test_record_refusals_exit_1(cli: Cli, argv: tuple[str, ...]) -> None:
    code, payload = cli("exception", "record", *argv)
    assert code == EXIT_INVALID_INPUT
    assert payload["error"]["message"]
    assert cli("exception", "list", "--all")[1] == {"exceptions": []}


def test_a_duplicate_active_exception_exits_1(cli: Cli, registered: str) -> None:
    assert _record(cli, registered)[0] == EXIT_OK
    code, payload = _record(cli, registered)
    assert code == EXIT_INVALID_INPUT
    assert "active exception" in payload["error"]["message"]


def test_list_shows_active_ones_unless_all(cli: Cli, registered: str) -> None:
    _, first = _record(cli, registered)
    other = "b" * 64
    _record(cli, other)
    code, listed = cli("exception", "list")
    assert code == EXIT_OK
    assert [item["exception_id"] for item in listed["exceptions"]] == [
        first["exception_id"],
        first["exception_id"] + 1,
    ]
    assert all(set(item) == ITEM for item in listed["exceptions"])
    assert listed["exceptions"][1]["in_use"] is False
    assert listed["exceptions"][1]["applies_to"] == []
    _, only = cli("exception", "list", "--sha256", f"sha256:{other}")
    assert [item["sha256"] for item in only["exceptions"]] == [other]

    code, revoked = cli(
        "exception", "revoke", str(first["exception_id"]), "--reason", "new review", "--by", "Lead"
    )
    assert code == EXIT_OK
    assert set(revoked) == ITEM
    assert revoked["state"] == "revoked"
    assert revoked["revoked"] == {
        "at": "2026-11-13T09:00:00Z",
        "by": "Lead",
        "reason": "new review",
    }
    assert [item["sha256"] for item in cli("exception", "list")[1]["exceptions"]] == [other]
    states = [item["state"] for item in cli("exception", "list", "--all")[1]["exceptions"]]
    assert states == ["revoked", "active"]


@pytest.mark.parametrize(
    "argv",
    [
        ("999", "--reason", "r", "--by", "O"),
        ("1", "--reason", "", "--by", "O"),
        ("1", "--reason", "r", "--by", " "),
    ],
)
def test_revoke_refusals_exit_1(cli: Cli, registered: str, argv: tuple[str, ...]) -> None:
    _record(cli, registered)
    assert cli("exception", "revoke", *argv)[0] == EXIT_INVALID_INPUT


def test_revoking_twice_exits_1(cli: Cli, registered: str) -> None:
    _, made = _record(cli, registered)
    argv = ("exception", "revoke", str(made["exception_id"]), "--reason", "r", "--by", "O")
    assert cli(*argv)[0] == EXIT_OK
    assert cli(*argv)[0] == EXIT_INVALID_INPUT


def test_list_refuses_a_malformed_hash(cli: Cli) -> None:
    assert cli("exception", "list", "--sha256", "xyz")[0] == EXIT_INVALID_INPUT


def test_alerts_state_excepted(cli: Cli, registered: str) -> None:
    _record(cli, registered)
    assert cli("check", "pose", "--source", "picklescan")[0] == EXIT_OK
    code, default = cli("alerts", "pose")
    assert code == EXIT_OK
    assert default["alerts"] == []
    [excepted] = default["excepted"]
    assert (excepted["kind"], excepted["state"]) == ("weight_file_scan", "excepted")
    code, only = cli("alerts", "pose", "--state", "excepted")
    assert code == EXIT_OK
    assert only["alerts"] == []
    assert [alert["alert_id"] for alert in only["excepted"]] == [excepted["alert_id"]]
    assert cli("alerts", "pose", "--state", "closed")[1]["excepted"] == []
    _, every = cli("alerts", "pose", "--state", "all")
    assert [alert["alert_id"] for alert in every["excepted"]] == [excepted["alert_id"]]
    assert every["alerts"] == []
    _, shown = cli("alert", "show", str(excepted["alert_id"]))
    assert shown["state"] == "excepted"

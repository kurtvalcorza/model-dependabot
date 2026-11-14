"""PR #17 review round 2: one test per finding (M1 to M5).

Pickles are crafted opcode bytes built at test time; nothing is ever loaded.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from model_dependabot import lifecycle
from model_dependabot.cli import EXIT_GATE, EXIT_OK, main, make_handlers
from model_dependabot.sources.doi_ra import doi_ra_url
from model_dependabot.sources.fetcher import RecordedFetcher

NOW = datetime(2026, 11, 14, 9, 0, tzinfo=UTC)
DISMISS = ("--reason", "risk_accepted", "--by", "Owner")
ALPHA = ("model_dependabot_fixture.layers", "Alpha")
BETA = ("model_dependabot_fixture.layers", "Beta")
UNREAD = "10.9999/model-dependabot-fixture-unread"


def _global(module: str, name: str) -> bytes:
    return b"c" + module.encode() + b"\n" + name.encode() + b"\n"


def two_suspicious() -> bytes:
    """Imports two globals on neither scanner list (protocol 2 opcodes, built here)."""
    return b"\x80\x02" + _global(*ALPHA) + b"0" + _global(*BETA) + b"0."


class Clock:
    def __init__(self) -> None:
        self.at = NOW

    def __call__(self) -> datetime:
        return self.at


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def cli(tmp_path: Path, capsys: pytest.CaptureFixture[str], clock: Clock) -> Callable[..., Any]:
    db = tmp_path / "db" / "md.db"

    def invoke(*argv: str, recordings: Path | None = None, as_json: bool = True) -> tuple[int, Any]:
        handlers = make_handlers(
            fetcher=RecordedFetcher(recordings or tmp_path / "none"), now=clock
        )
        code = main([*argv, "--db", str(db), *(["--json"] if as_json else [])], handlers=handlers)
        out = capsys.readouterr().out
        if not as_json:
            return code, out
        return code, json.loads(out) if out.strip() else None

    return invoke


def _model(cli: Any, root: Path, model_id: str, lines: list[str], files: dict[str, bytes]) -> None:
    root.mkdir(parents=True, exist_ok=True)
    for name, data in files.items():
        (root / name).write_bytes(data)
    text = "\n".join(["[model]", f'id = "{model_id}"', "", *lines]) + "\n"
    (root / "model.toml").write_text(text, encoding="utf-8")


def _register(cli: Any, root: Path, model_id: str, data: bytes, **kwargs: Any) -> str:
    _model(cli, root, model_id, ["[[weights]]", 'path = "w.pkl"'], {"w.pkl": data})
    code, payload = cli("register", str(root / "model.toml"), **kwargs)
    assert code == EXIT_OK, payload
    return hashlib.sha256(data).hexdigest()


def _policy_alerts(cli: Any, model_id: str, state: str = "open") -> list[dict[str, Any]]:
    _, listed = cli("alerts", model_id, "--state", state)
    return [a for a in listed["alerts"] + listed["excepted"] if a["kind"] == "globals_policy"]


# --- M1: a checked model prints no "not checked" line --------------------------------------------


def test_m1_the_text_of_a_checked_model(cli: Any, tmp_path: Path, craft: Any) -> None:
    _register(cli, tmp_path / "m", "m", craft.innocuous())
    code, text = cli("check", "m", "--source", "picklescan", as_json=False)
    assert code == EXIT_OK
    assert "m v1: checked" in text
    assert "not checked" not in text
    code, text = cli("run", "show", "1", as_json=False)
    assert "not checked" not in text


# --- M2: the list at dismissal decides -----------------------------------------------------------


def test_m2_a_revoked_exception_reopens_a_dismissed_globals_alert(cli: Any, tmp_path: Path) -> None:
    sha = _register(cli, tmp_path / "m", "m", two_suspicious())
    cli("policy", "m", "--globals", "strict", "--by", "Owner")
    cli("check", "m", "--source", "picklescan")
    [first] = _policy_alerts(cli, "m")
    assert len(first["cause"]["unlisted"]) == 2
    alpha = ".".join(ALPHA)
    _, made = cli("exception", "record", "--global", alpha, "--sha256", sha,
                  "--reason", "r", "--by", "O")  # fmt: skip
    cli("check", "m", "--source", "picklescan")
    [carried] = _policy_alerts(cli, "m")
    assert carried["cause"]["unlisted"] == [".".join(BETA)]
    cli("alert", "dismiss", str(carried["alert_id"]), *DISMISS)
    cli("exception", "revoke", str(made["exception_id"]), "--reason", "no", "--by", "O")
    code, _ = cli("check", "m", "--source", "picklescan", "--fail-on", "LOW")
    assert code == EXIT_GATE
    [reopened] = _policy_alerts(cli, "m")
    assert alpha in reopened["cause"]["unlisted"]
    assert reopened["cause"]["reopens"]["alert_id"] == carried["alert_id"]


# --- M3: the scan is evidence of a globals_policy alert too --------------------------------------


def test_m3_another_scanner_version_reopens_a_dismissed_globals_alert(
    cli: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _register(cli, tmp_path / "m", "m", two_suspicious())
    cli("policy", "m", "--globals", "strict", "--by", "Owner")
    cli("check", "m", "--source", "picklescan")
    [first] = _policy_alerts(cli, "m")
    cli("alert", "dismiss", str(first["alert_id"]), *DISMISS)
    _, checked = cli("check", "m", "--source", "picklescan")
    assert checked["models"][0]["dismissals_held"] == [first["alert_id"]]
    scan_handle = lifecycle.pickle_scan.scan_handle

    def newer(handle: Any, name: str) -> Any:
        return dataclasses.replace(scan_handle(handle, name), scanner_version="9.9.9")

    monkeypatch.setattr(lifecycle.pickle_scan, "scan_handle", newer)
    cli("check", "m", "--source", "picklescan")
    [reopened] = _policy_alerts(cli, "m")
    assert reopened["cause"]["reopens"]["alert_id"] == first["alert_id"]


# --- M4: a lapsed exception returns a globals finding at any check -------------------------------


def test_m4_an_expired_exception_returns_the_globals_finding_at_an_osv_check(
    cli: Any, tmp_path: Path, craft: Any, clock: Clock
) -> None:
    sha = _register(cli, tmp_path / "m", "m", craft.suspicious())
    cli("policy", "m", "--globals", "strict", "--by", "Owner")
    layer = "model_dependabot_fixture.layers.CustomLayer"
    cli("exception", "record", "--global", layer, "--sha256", sha, "--reason", "r",
        "--by", "O", "--expires", "2026-11-15")  # fmt: skip
    cli("check", "m", "--source", "picklescan")
    assert _policy_alerts(cli, "m") == []
    clock.at = NOW + timedelta(days=30)
    code, checked = cli("check", "m", "--source", "osv", "--fail-on", "LOW")
    assert code == EXIT_GATE
    assert [a["kind"] for a in checked["gate"]["alerts"]] == ["globals_policy"]
    [back] = _policy_alerts(cli, "m")
    assert back["cause"]["unlisted"] == [layer]


def test_m4_a_new_exception_still_waits_for_a_weight_source(
    cli: Any, tmp_path: Path, craft: Any
) -> None:
    sha = _register(cli, tmp_path / "m", "m", craft.suspicious())
    cli("policy", "m", "--globals", "strict", "--by", "Owner")
    cli("check", "m", "--source", "picklescan")
    layer = "model_dependabot_fixture.layers.CustomLayer"
    cli("exception", "record", "--global", layer, "--sha256", sha, "--reason", "r", "--by", "O")
    cli("check", "m", "--source", "osv")
    assert len(_policy_alerts(cli, "m")) == 1  # FR-010: only a weight check applies it


def test_m4_a_policy_set_strict_still_waits_for_a_weight_source(
    cli: Any, tmp_path: Path, craft: Any
) -> None:
    _register(cli, tmp_path / "m", "m", craft.suspicious())
    cli("check", "m", "--source", "picklescan")
    cli("policy", "m", "--globals", "strict", "--by", "Owner")
    cli("check", "m", "--source", "osv")
    assert _policy_alerts(cli, "m") == []


# --- M5: an uncheckable DOI through the real path ------------------------------------------------


def _unread_recordings(derive_upstream: Callable[..., Path]) -> Path:
    agency = {"url": doi_ra_url(UNREAD), "status": 200, "body": [{"DOI": UNREAD, "RA": "mEDRA"}]}
    return derive_upstream(extra={"ra-unread": agency})


def test_m5_an_uncheckable_doi_is_listed_stored_and_does_not_trip_the_gate(
    cli: Any, tmp_path: Path, craft: Any, derive_upstream: Callable[..., Path]
) -> None:
    root = tmp_path / "m"
    lines = ["[[weights]]", 'path = "w.pkl"', "", "[[datasets]]", f'doi = "{UNREAD}"']
    _model(cli, root, "m", lines, {"w.pkl": craft.innocuous()})
    recordings = _unread_recordings(derive_upstream)
    assert cli("register", str(root / "model.toml"), recordings=recordings)[0] == EXIT_OK
    argv = ("check", "m", "--source", "picklescan,datacite", "--fail-on", "CRITICAL")
    code, checked = cli(*argv, recordings=recordings)
    assert code == EXIT_OK, checked["gate"]
    [model] = checked["overview"]["models"]
    assert model["checked"] is True
    [item] = model["uncheckable"]
    assert (item["kind"], item["identifier"]) == ("dataset_unreachable", UNREAD)
    assert "mEDRA" in item["reason"]
    assert all(row["source"] != "uncheckable" for row in model["sources"])
    assert all(row["source"] != "uncheckable" for row in checked["overview"]["sources"])
    _, shown = cli("run", "show", str(checked["run_id"]))
    assert shown["overview"]["models"][0]["uncheckable"] == [item]
    _, text = cli("run", "show", str(checked["run_id"]), as_json=False)
    lines = text.splitlines()
    checked_at = lines.index("m v1: checked")
    assert f"  uncheckable: dataset_unreachable {UNREAD}: {item['reason']}" in lines[checked_at:]


def test_m5_an_uncheckable_item_alone_is_not_coverage(
    cli: Any, tmp_path: Path, derive_upstream: Callable[..., Path]
) -> None:
    root = tmp_path / "d"
    _model(cli, root, "d", ["[[datasets]]", f'doi = "{UNREAD}"'], {})
    recordings = _unread_recordings(derive_upstream)
    assert cli("register", str(root / "model.toml"), recordings=recordings)[0] == EXIT_OK
    argv = ("check", "d", "--source", "datacite", "--fail-on", "CRITICAL")
    code, checked = cli(*argv, recordings=recordings)
    assert code == EXIT_GATE
    assert checked["gate"]["unchecked"] == ["d"]
    [model] = checked["overview"]["models"]
    assert model["checked"] is False
    assert [item["identifier"] for item in model["uncheckable"]] == [UNREAD]

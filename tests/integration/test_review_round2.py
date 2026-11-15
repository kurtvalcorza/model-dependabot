"""PR #17 review round 2: one test per finding (M1 to M5).

Pickles are crafted opcode bytes built at test time; nothing is ever loaded.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import sqlite3
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


def test_m4_a_lapse_does_not_apply_a_new_exception_at_an_osv_check(
    cli: Any, tmp_path: Path
) -> None:
    sha = _register(cli, tmp_path / "m", "m", two_suspicious())
    alpha, beta = ".".join(ALPHA), ".".join(BETA)
    cli("policy", "m", "--globals", "strict", "--by", "Owner")
    _, old = cli("exception", "record", "--global", alpha, "--sha256", sha,
                 "--reason", "r", "--by", "O")  # fmt: skip
    cli("check", "m", "--source", "picklescan")
    [before] = _policy_alerts(cli, "m")
    assert before["cause"]["unlisted"] == [beta]
    cli("exception", "record", "--global", beta, "--sha256", sha, "--reason", "r", "--by", "O")
    cli("exception", "revoke", str(old["exception_id"]), "--reason", "no", "--by", "O")
    cli("check", "m", "--source", "osv")
    [after] = _policy_alerts(cli, "m")
    # FR-010: the lapsed global is back, while the new exception waits for a weight source
    assert after["cause"]["unlisted"] == [alpha, beta]
    assert after["cause"]["excepted"] == []
    cli("check", "m", "--source", "picklescan")
    [applied] = _policy_alerts(cli, "m")
    assert applied["cause"]["unlisted"] == [alpha]


def test_m4_a_policy_set_strict_still_waits_for_a_weight_source(
    cli: Any, tmp_path: Path, craft: Any
) -> None:
    _register(cli, tmp_path / "m", "m", craft.suspicious())
    cli("check", "m", "--source", "picklescan")
    cli("policy", "m", "--globals", "strict", "--by", "Owner")
    cli("check", "m", "--source", "osv")
    assert _policy_alerts(cli, "m") == []


# --- PR #19 review 3: a check without a weight source acts only on a lapse since the last one ---

ALPHA_NAME, BETA_NAME = ".".join(ALPHA), ".".join(BETA)


def _except(cli: Any, sha: str, name: str) -> int:
    code, made = cli("exception", "record", "--global", name, "--sha256", sha,
                     "--reason", "r", "--by", "O")  # fmt: skip
    assert code == EXIT_OK, made
    return int(made["exception_id"])


def _revoke(cli: Any, exception_id: int) -> None:
    code, _ = cli("exception", "revoke", str(exception_id), "--reason", "no", "--by", "O")
    assert code == EXIT_OK


def test_r3_a_reopened_alert_waits_for_the_new_exception(cli: Any, tmp_path: Path) -> None:
    sha = _register(cli, tmp_path / "m", "m", two_suspicious())
    cli("policy", "m", "--globals", "strict", "--by", "Owner")
    alpha = _except(cli, sha, ALPHA_NAME)
    cli("check", "m", "--source", "picklescan")
    [listed] = _policy_alerts(cli, "m")
    assert listed["cause"]["unlisted"] == [BETA_NAME]
    cli("alert", "dismiss", str(listed["alert_id"]), *DISMISS)
    _except(cli, sha, BETA_NAME)
    _revoke(cli, alpha)
    cli("check", "m", "--source", "osv")
    [back] = _policy_alerts(cli, "m")
    assert back["cause"]["unlisted"] == [ALPHA_NAME, BETA_NAME]
    assert back["cause"]["excepted"] == []


def test_r3_a_lapse_opens_an_alert_while_its_new_exception_waits(cli: Any, tmp_path: Path) -> None:
    sha = _register(cli, tmp_path / "m", "m", two_suspicious())
    cli("policy", "m", "--globals", "strict", "--by", "Owner")
    alpha = _except(cli, sha, ALPHA_NAME)
    _except(cli, sha, BETA_NAME)
    cli("check", "m", "--source", "picklescan")
    assert _policy_alerts(cli, "m") == []
    _revoke(cli, alpha)
    _except(cli, sha, ALPHA_NAME)
    cli("check", "m", "--source", "osv")
    [opened] = _policy_alerts(cli, "m")
    assert opened["cause"]["unlisted"] == [ALPHA_NAME]
    cli("check", "m", "--source", "picklescan")
    assert _policy_alerts(cli, "m") == []


def test_r3_a_policy_set_strict_ignores_an_older_lapse(cli: Any, tmp_path: Path) -> None:
    sha = _register(cli, tmp_path / "m", "m", two_suspicious())
    _revoke(cli, _except(cli, sha, ALPHA_NAME))
    cli("check", "m", "--source", "picklescan")
    cli("policy", "m", "--globals", "strict", "--by", "Owner")
    _, checked = cli("check", "m", "--source", "osv", "--fail-on", "moderate")
    assert [a["kind"] for a in checked["gate"]["alerts"]] == []
    assert _policy_alerts(cli, "m") == []
    cli("check", "m", "--source", "picklescan")
    assert len(_policy_alerts(cli, "m")) == 1


def test_r3_a_policy_set_strict_waits_even_for_a_fresh_lapse(cli: Any, tmp_path: Path) -> None:
    sha = _register(cli, tmp_path / "m", "m", two_suspicious())
    alpha = _except(cli, sha, ALPHA_NAME)
    cli("check", "m", "--source", "picklescan")
    cli("policy", "m", "--globals", "strict", "--by", "Owner")
    _revoke(cli, alpha)
    _, checked = cli("check", "m", "--source", "osv", "--fail-on", "moderate")
    assert [a["kind"] for a in checked["gate"]["alerts"]] == []
    assert _policy_alerts(cli, "m") == []


def test_r3_an_alert_the_default_policy_cleared_stays_cleared(cli: Any, tmp_path: Path) -> None:
    sha = _register(cli, tmp_path / "m", "m", two_suspicious())
    cli("policy", "m", "--globals", "strict", "--by", "Owner")
    alpha = _except(cli, sha, ALPHA_NAME)
    cli("check", "m", "--source", "picklescan")
    _revoke(cli, alpha)
    cli("check", "m", "--source", "osv")
    cli("policy", "m", "--globals", "default", "--by", "Owner")
    cli("check", "m", "--source", "picklescan")
    assert _policy_alerts(cli, "m") == []
    cli("policy", "m", "--globals", "strict", "--by", "Owner")
    cli("check", "m", "--source", "osv")
    assert _policy_alerts(cli, "m") == []


def test_r3_without_a_mark_a_lapse_waits_for_a_weight_check(cli: Any, tmp_path: Path) -> None:
    sha = _register(cli, tmp_path / "m", "m", two_suspicious())
    cli("policy", "m", "--globals", "strict", "--by", "Owner")
    alpha = _except(cli, sha, ALPHA_NAME)
    cli("check", "m", "--source", "picklescan")
    with sqlite3.connect(tmp_path / "db" / "md.db") as conn:
        conn.execute("DROP TABLE IF EXISTS weight_check_marks")  # a store from before the mark
    _revoke(cli, alpha)
    cli("check", "m", "--source", "osv")
    [untouched] = _policy_alerts(cli, "m")
    assert untouched["cause"]["unlisted"] == [BETA_NAME]
    cli("check", "m", "--source", "picklescan")
    [listed] = _policy_alerts(cli, "m")
    assert listed["cause"]["unlisted"] == [ALPHA_NAME, BETA_NAME]


# --- PR #19 review 4: the policy value, and only the files and scans the weight check judged ----

GAMMA = ("model_dependabot_fixture.layers", "Gamma")


def one_suspicious() -> bytes:
    """Imports one global on neither scanner list (protocol 2 opcodes, built here)."""
    return b"\x80\x02" + _global(*GAMMA) + b"0."


def _version(cli: Any, root: Path, model_id: str, data: bytes) -> None:
    """Register a new version of a model that is already registered."""
    _model(cli, root, model_id, ["[[weights]]", 'path = "w.pkl"'], {"w.pkl": data})
    code, payload = cli("register", str(root / "model.toml"), "--model-id", model_id)
    assert code == EXIT_OK, payload


def _two_alerts(cli: Any, model_id: str, sha: str) -> list[dict[str, Any]]:
    return [a for a in _policy_alerts(cli, model_id) if a["cause"]["identifier"] == f"sha256:{sha}"]


def test_r4_strict_set_again_later_still_lets_a_lapse_act(
    cli: Any, tmp_path: Path, clock: Clock
) -> None:
    sha = _register(cli, tmp_path / "m", "m", two_suspicious())
    cli("policy", "m", "--globals", "strict", "--by", "Owner")
    alpha = _except(cli, sha, ALPHA_NAME)
    cli("check", "m", "--source", "picklescan")
    clock.at += timedelta(minutes=5)
    cli("policy", "m", "--globals", "strict", "--by", "Owner")
    clock.at += timedelta(minutes=5)
    _revoke(cli, alpha)
    cli("check", "m", "--source", "osv")
    [back] = _policy_alerts(cli, "m")
    assert back["cause"]["unlisted"] == [ALPHA_NAME, BETA_NAME]


def test_r4_strict_default_strict_without_a_check_lets_a_lapse_act(
    cli: Any, tmp_path: Path, clock: Clock
) -> None:
    sha = _register(cli, tmp_path / "m", "m", two_suspicious())
    cli("policy", "m", "--globals", "strict", "--by", "Owner")
    alpha = _except(cli, sha, ALPHA_NAME)
    cli("check", "m", "--source", "picklescan")
    for policy in ("default", "strict"):
        clock.at += timedelta(minutes=5)
        cli("policy", "m", "--globals", policy, "--by", "Owner")
    clock.at += timedelta(minutes=5)
    _revoke(cli, alpha)
    cli("check", "m", "--source", "osv")
    [back] = _policy_alerts(cli, "m")
    assert back["cause"]["unlisted"] == [ALPHA_NAME, BETA_NAME]


def test_r4_bytes_gained_by_registration_wait_for_a_weight_check(cli: Any, tmp_path: Path) -> None:
    _register(cli, tmp_path / "m1", "m", one_suspicious())
    cli("policy", "m", "--globals", "strict", "--by", "Owner")
    sha = _register(cli, tmp_path / "n", "n", two_suspicious())
    cli("check", "n", "--source", "picklescan")
    alpha = _except(cli, sha, ALPHA_NAME)
    _except(cli, sha, BETA_NAME)
    cli("check", "m", "--source", "picklescan")
    _version(cli, tmp_path / "m2", "m", two_suspicious())
    cli("check", "m", "--source", "osv")
    _revoke(cli, alpha)
    cli("check", "m", "--source", "osv")
    assert _two_alerts(cli, "m", sha) == []
    cli("check", "m", "--source", "picklescan")
    assert [a["cause"]["unlisted"] for a in _two_alerts(cli, "m", sha)] == [[ALPHA_NAME]]


def test_r4_a_scan_newer_than_the_weight_check_waits(cli: Any, tmp_path: Path) -> None:
    sha = _register(cli, tmp_path / "m", "m", two_suspicious())
    alpha = _except(cli, sha, ALPHA_NAME)
    cli("policy", "m", "--globals", "strict", "--by", "Owner")
    cli("check", "m", "--source", "hf-scan")  # a weight check that reads no scan of the file
    _register(cli, tmp_path / "n", "n", two_suspicious())
    cli("check", "n", "--source", "picklescan")
    _revoke(cli, alpha)
    cli("check", "m", "--source", "osv")
    assert _policy_alerts(cli, "m") == []


def test_r4_a_lapse_before_the_weight_check_never_acts(cli: Any, tmp_path: Path) -> None:
    sha = _register(cli, tmp_path / "m1", "m", two_suspicious())
    _revoke(cli, _except(cli, sha, ALPHA_NAME))
    cli("policy", "m", "--globals", "strict", "--by", "Owner")
    cli("check", "m", "--source", "picklescan")
    _version(cli, tmp_path / "m2", "m", one_suspicious())
    _version(cli, tmp_path / "m3", "m", two_suspicious())
    cli("check", "m", "--source", "osv")
    assert _two_alerts(cli, "m", sha) == []


# --- PR #19 review 5: an identical scan read elsewhere is the scan the weight check judged -------


def _from_record(cli: Any, root: Path, model_id: str, data: bytes, *extra: str) -> None:
    """Record the weights in one folder, then register a copy without them from the record."""
    _model(cli, root / "src", model_id, ["[[weights]]", 'path = "w.pkl"'], {"w.pkl": data})
    record = root / "src" / "model.record.json"
    code, payload = cli("record", str(root / "src" / "model.toml"), "--out", str(record))
    assert code == EXIT_OK, payload
    (root / "ci").mkdir()
    for name in ("model.toml", "model.record.json"):
        (root / "ci" / name).write_bytes((root / "src" / name).read_bytes())
    code, payload = cli(
        "register", str(root / "ci" / "model.toml"), "--from-record",
        str(root / "ci" / "model.record.json"), *extra,
    )  # fmt: skip
    assert code == EXIT_OK, payload


def _strict_with_alpha_excepted(cli: Any, tmp_path: Path) -> tuple[str, int]:
    sha = _register(cli, tmp_path / "m", "m", two_suspicious())
    cli("policy", "m", "--globals", "strict", "--by", "Owner")
    alpha = _except(cli, sha, ALPHA_NAME)
    cli("check", "m", "--source", "picklescan")
    [listed] = _policy_alerts(cli, "m")
    assert listed["cause"]["unlisted"] == [BETA_NAME]
    return sha, alpha


def test_r5_another_model_scanning_the_same_bytes_lets_a_lapse_act(
    cli: Any, tmp_path: Path
) -> None:
    _, alpha = _strict_with_alpha_excepted(cli, tmp_path)
    _register(cli, tmp_path / "n", "n", two_suspicious())
    cli("check", "n", "--source", "picklescan")
    _revoke(cli, alpha)
    cli("check", "m", "--source", "osv")
    [back] = _policy_alerts(cli, "m")
    assert back["cause"]["unlisted"] == [ALPHA_NAME, BETA_NAME]


def test_r5_another_model_from_a_record_lets_a_lapse_act(cli: Any, tmp_path: Path) -> None:
    _, alpha = _strict_with_alpha_excepted(cli, tmp_path)
    _from_record(cli, tmp_path / "n", "n", two_suspicious())
    _revoke(cli, alpha)
    cli("check", "m", "--source", "osv")
    [back] = _policy_alerts(cli, "m")
    assert back["cause"]["unlisted"] == [ALPHA_NAME, BETA_NAME]


def test_r5_the_same_model_again_from_a_record_lets_a_lapse_act(cli: Any, tmp_path: Path) -> None:
    _, alpha = _strict_with_alpha_excepted(cli, tmp_path)
    _from_record(cli, tmp_path / "m2", "m", two_suspicious(), "--model-id", "m")
    _revoke(cli, alpha)
    cli("check", "m", "--source", "osv")
    [back] = _policy_alerts(cli, "m")
    assert back["cause"]["unlisted"] == [ALPHA_NAME, BETA_NAME]


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


_DIGEST_SCAN: dict[str, Any] = {
    "scanner": "picklescan",
    "scanner_version": "1.0.0",
    "complete": 1,
    "globals": [
        {"module": "os", "name": "system", "safety": "dangerous"},
        {"module": "collections", "name": "OrderedDict", "safety": "innocuous"},
    ],
}


def test_r6_the_scan_digest_is_pinned_and_covers_what_a_scan_saw() -> None:
    """Review 6: the mark's digest is fixed, ignores order and changes with every field it covers.

    A change to the formula would make every model's lapse wait once for a weight check, so it is
    pinned here; each field the spec counts as the scan's content must move it.
    """
    digest = lifecycle._scan_digest(_DIGEST_SCAN)
    assert digest == "2c2dc147d9d07d71bb0ce0b3401516d331cc2fda349a3153e562b6d4d8e04720"
    reordered = {**_DIGEST_SCAN, "complete": True, "globals": _DIGEST_SCAN["globals"][::-1]}
    assert lifecycle._scan_digest(reordered) == digest
    first, second = _DIGEST_SCAN["globals"]
    changed = [
        {**_DIGEST_SCAN, "scanner": "other"},
        {**_DIGEST_SCAN, "scanner_version": "1.0.1"},
        {**_DIGEST_SCAN, "complete": 0},
        {**_DIGEST_SCAN, "globals": [first]},
        {**_DIGEST_SCAN, "globals": [{**first, "safety": "innocuous"}, second]},
    ]
    assert all(lifecycle._scan_digest(scan) != digest for scan in changed)

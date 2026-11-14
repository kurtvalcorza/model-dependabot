"""PR #17 review round 1: one test per finding (X1 to X4, K1 to K6).

Pickles are crafted opcode bytes (``craft.py``) or the plain opcode string below; nothing is ever
loaded.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from model_dependabot import lifecycle
from model_dependabot.assurance import overview
from model_dependabot.cli import EXIT_GATE, EXIT_INVALID_INPUT, EXIT_OK, main, make_handlers
from model_dependabot.lifecycle import run_check
from model_dependabot.sources.fetcher import RecordedFetcher
from model_dependabot.store import Store

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
NOW = datetime(2026, 11, 14, 9, 0, tzinfo=UTC)
PICKLE_0 = b"cos\nsystem\n(S'echo hi'\ntR."  # read as data only, never loaded
DISMISS = ("--reason", "risk_accepted", "--by", "Owner")


class NoNetwork:
    def get(self, url: str, **kwargs: Any) -> Any:
        raise AssertionError(f"unexpected request: {url}")

    get_range = post = get


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

    def invoke(*argv: str, recordings: Path | None = None, db_path: Path = db) -> tuple[int, Any]:
        fetcher = RecordedFetcher(recordings or tmp_path / "none")
        handlers = make_handlers(fetcher=fetcher, now=clock)
        code = main([*argv, "--db", str(db_path), "--json"], handlers=handlers)
        out = capsys.readouterr().out
        return code, json.loads(out) if out.strip() else None

    return invoke


def _model(cli: Any, root: Path, model_id: str, files: dict[str, bytes]) -> dict[str, str]:
    root.mkdir(parents=True, exist_ok=True)
    lines = ["[model]", f'id = "{model_id}"']
    for name, data in files.items():
        (root / name).write_bytes(data)
        lines += ["", "[[weights]]", f'path = "{name}"']
    (root / "model.toml").write_text("\n".join(lines) + "\n", encoding="utf-8")
    code, payload = cli("register", str(root / "model.toml"), "--model-id", model_id)
    assert code == EXIT_OK, payload
    return {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}


def _alerts(cli: Any, model_id: str, kind: str, state: str = "all") -> list[dict[str, Any]]:
    _, listed = cli("alerts", model_id, "--state", state)
    return [a for a in listed["alerts"] + listed["excepted"] if a["kind"] == kind]


# --- X1: the overview counts the entries as measured ---------------------------------------------


def test_x1_a_contradicted_code_free_claim_is_counted_as_a_pickle(tmp_path: Path) -> None:
    (tmp_path / "bom").mkdir()
    (tmp_path / "bom" / "claimed.safetensors").write_bytes(PICKLE_0)
    entry = {
        "kind": "weight_file",
        "identifier": "sha256:" + hashlib.sha256(PICKLE_0).hexdigest(),
        "pinned": True,
        "location": "claimed.safetensors",
        "format": "safetensors",
        "can_run_code": False,
        "format_origin": "import",
    }
    with Store(tmp_path / "db" / "md.db", now=lambda: NOW) as store:
        store.add_model("m")
        store.add_version("m", {}, "f" * 64, [entry], base_dir=tmp_path / "bom", origin="import")
        outcome = run_check(store, NoNetwork(), ["m"], ["picklescan", "format-check"])
        rows = overview.payload(store, outcome.run_id)["models"][0]["sources"]
    by_source = {row["source"]: row for row in rows}
    assert by_source["picklescan"]["state"] == "alerted"
    assert by_source["picklescan"]["alerts_open"] == 1
    assert by_source["policy"]["entries"] == 1


# --- X2: reopens survives every carry path -------------------------------------------------------


def test_x2_reopens_stays_on_a_carried_weight_alert(
    cli: Any, tmp_path: Path, craft: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    _model(cli, tmp_path / "w", "w", {"d.pkl": craft.dangerous()})
    cli("check", "w", "--source", "picklescan")
    [first] = _alerts(cli, "w", "weight_file_scan")
    cli("alert", "dismiss", str(first["alert_id"]), *DISMISS)
    # Another scanner version is new evidence for the dismissed alert.
    import dataclasses

    scan_handle = lifecycle.pickle_scan.scan_handle

    def newer(handle: Any, name: str) -> Any:
        return dataclasses.replace(scan_handle(handle, name), scanner_version="9.9.9")

    monkeypatch.setattr(lifecycle.pickle_scan, "scan_handle", newer)
    cli("check", "w", "--source", "picklescan")
    cli("check", "w", "--source", "picklescan")  # carried forward
    [reopened] = _alerts(cli, "w", "weight_file_scan", "open")
    assert reopened["cause"]["reopens"]["alert_id"] == first["alert_id"]


def test_x2_reopens_stays_on_a_carried_package_alert(
    cli: Any, tmp_path: Path, derive_osv: Callable[..., Path]
) -> None:
    root = tmp_path / "p"
    root.mkdir()
    shutil.copy(FIXTURES / "locks" / "vulnerable.txt", root / "requirements.txt")
    (root / "model.toml").write_text(
        '[model]\nid = "p"\n\n[environment]\nlock = "requirements.txt"\n', "utf-8"
    )
    cli("register", str(root / "model.toml"))
    cli("check", "p", "--source", "osv", recordings=derive_osv())
    first = next(
        a for a in _alerts(cli, "p", "package_advisory") if "GHSA-cp9v" in json.dumps(a["cause"])
    )
    cli("alert", "dismiss", str(first["alert_id"]), *DISMISS)
    changed = derive_osv(changes={"vuln-GHSA-cp9v-662q-vvx9": lambda b: b | {"details": "new"}})
    cli("check", "p", "--source", "osv", recordings=changed)
    cli("check", "p", "--source", "osv", recordings=changed)  # carried forward
    [reopened] = [
        a
        for a in _alerts(cli, "p", "package_advisory", "open")
        if "GHSA-cp9v" in json.dumps(a["cause"])
    ]
    assert reopened["cause"]["reopens"]["alert_id"] == first["alert_id"]


# --- X3: run show reads only ---------------------------------------------------------------------


def test_x3_run_show_neither_creates_nor_upgrades_a_database(cli: Any, tmp_path: Path) -> None:
    missing = tmp_path / "nowhere" / "md.db"
    code, _ = cli("run", "show", "1", db_path=missing)
    assert code == EXIT_INVALID_INPUT
    assert not missing.exists() and not missing.parent.exists()
    old = tmp_path / "old.db"
    conn = sqlite3.connect(old)
    conn.executescript((FIXTURES / "db" / "schema-pre-004.sql").read_text("utf-8"))
    conn.close()
    before = hashlib.sha256(old.read_bytes()).hexdigest()
    code, shown = cli("run", "show", "1", db_path=old)
    assert code == EXIT_OK
    assert shown["overview"]["sources"] == []
    assert hashlib.sha256(old.read_bytes()).hexdigest() == before


# --- X4: a globals_policy alert clears on default whatever its entry became ----------------------


def test_x4_policy_default_clears_an_alert_on_an_entry_no_longer_scanned(tmp_path: Path) -> None:
    sha = "ab" * 32
    hub = {
        "kind": "weight_file",
        "identifier": f"sha256:{sha}",
        "pinned": True,
        "hub_repo": "o/r",
        "hub_revision": "c" * 40,
        "hub_file": "m.bin",
        "format": "pytorch-pickle",
        "can_run_code": True,
    }
    with Store(tmp_path / "md.db", now=lambda: NOW) as store:
        store.add_model("m")
        store.add_version("m", {}, "f" * 64, [hub], origin="manifest")
        evidence = store.add_evidence(
            source="globals-policy", url="", retrieved_at=NOW,
            matched_identifier=f"sha256:{sha}", body=b"{}",
        )  # fmt: skip
        alert_id = store.insert_alert(
            model_id="m", kind="globals_policy", cause_key=f"globals_policy:sha256:{sha}",
            cause={"identifier": f"sha256:{sha}", "unlisted": ["x.Y"]}, severity="MODERATE",
            severity_origin="policy", opened_in_version=1, evidence_ids=[evidence],
        )  # fmt: skip
        run_check(store, NoNetwork(), ["m"], ["picklescan"])
        assert store.get_alert(alert_id)["state"] == "cleared"
        assert store.get_alert(alert_id)["note"] == "cleared: policy"


# --- K1: the policy row is not coverage ----------------------------------------------------------


def test_k1_a_model_no_asked_source_covers_trips_the_gate(
    cli: Any, tmp_path: Path, craft: ModuleType
) -> None:
    _model(cli, tmp_path / "m", "m", {"d.pkl": craft.dangerous()})
    cli("policy", "m", "--globals", "strict", "--by", "Owner")
    code, checked = cli("check", "m", "--source", "hf-scan", "--fail-on", "LOW")
    assert code == EXIT_GATE
    assert checked["gate"]["unchecked"] == ["m"]
    [model] = checked["overview"]["models"]
    assert model["checked"] is False


# --- K3: see tests/integration/test_review_round2.py (M5), which runs the real path -------------


# --- K4: identical bytes from another place hold the dismissal -----------------------------------


def test_k4_identical_bytes_from_another_folder_hold(
    cli: Any, tmp_path: Path, craft: ModuleType
) -> None:
    data = craft.dangerous()
    _model(cli, tmp_path / "one", "w", {"d.pkl": data})
    cli("check", "w", "--source", "picklescan")
    [alert] = _alerts(cli, "w", "weight_file_scan")
    cli("alert", "dismiss", str(alert["alert_id"]), *DISMISS)
    _model(cli, tmp_path / "two", "w", {"d.pkl": data})  # version 2 from another checkout
    code, checked = cli("check", "w", "--source", "picklescan", "--fail-on", "HIGH")
    assert code == EXIT_OK
    assert checked["models"][0]["dismissals_held"] == [alert["alert_id"]]


def test_k4_identical_bytes_from_a_fresh_record_hold(
    cli: Any, tmp_path: Path, craft: ModuleType, clock: Clock
) -> None:
    data = craft.dangerous()
    owner = tmp_path / "owner"
    owner.mkdir()
    (owner / "d.pkl").write_bytes(data)
    manifest = owner / "model.toml"
    manifest.write_text('[model]\nid = "rec"\n\n[[weights]]\npath = "d.pkl"\n', "utf-8")
    for round_ in (1, 2):
        out = tmp_path / f"out{round_}" / "model.record.json"
        assert cli("record", str(manifest), "--out", str(out))[0] == EXIT_OK
        ci = tmp_path / f"ci{round_}"
        ci.mkdir()
        shutil.copy(manifest, ci / "model.toml")
        shutil.copy(out, ci / "model.record.json")
        argv = ("register", str(ci / "model.toml"), "--from-record", str(ci / "model.record.json"))
        assert cli(*argv, "--model-id", "rec")[0] == EXIT_OK
        if round_ == 1:
            [alert] = _alerts(cli, "rec", "weight_file_scan")
            cli("alert", "dismiss", str(alert["alert_id"]), *DISMISS)
            clock.at = NOW + timedelta(days=1)
    assert [a["alert_id"] for a in _alerts(cli, "rec", "weight_file_scan")] == [alert["alert_id"]]


# --- K5: a lapsed exception returns the finding at any check -------------------------------------


def test_k5_an_expired_exception_returns_the_finding_without_a_weight_source(
    cli: Any, tmp_path: Path, craft: ModuleType, clock: Clock
) -> None:
    sha = _model(cli, tmp_path / "m", "m", {"d.pkl": craft.dangerous()})["d.pkl"]
    argv = ("--global", "os.system", "--sha256", sha, "--reason", "r", "--by", "O")
    cli("exception", "record", *argv, "--expires", "2026-11-15")
    cli("check", "m", "--source", "picklescan")
    assert [a["state"] for a in _alerts(cli, "m", "weight_file_scan")] == ["excepted"]
    clock.at = NOW + timedelta(days=30)
    code, checked = cli("check", "m", "--source", "osv", "--fail-on", "LOW")
    assert code == EXIT_GATE
    assert [a["kind"] for a in checked["gate"]["alerts"]] == ["weight_file_scan"]
    [back] = _alerts(cli, "m", "weight_file_scan")
    assert back["state"] == "open"
    assert back["cause"]["released"][0]["why"] == "expired"


def test_k5_a_new_exception_still_waits_for_a_weight_source(
    cli: Any, tmp_path: Path, craft: ModuleType
) -> None:
    sha = _model(cli, tmp_path / "m", "m", {"d.pkl": craft.dangerous()})["d.pkl"]
    cli("check", "m", "--source", "picklescan")
    cli("exception", "record", "--global", "os.system", "--sha256", sha,
        "--reason", "r", "--by", "O")  # fmt: skip
    cli("check", "m", "--source", "osv")
    assert [a["state"] for a in _alerts(cli, "m", "weight_file_scan")] == ["open"]  # FR-010


# --- K2: re-asserting the policy or a shrinking list is not new evidence -------------------------


def test_k2_policy_noise_and_a_shrinking_list_hold_the_dismissal(
    cli: Any, tmp_path: Path, craft: ModuleType, clock: Clock
) -> None:
    sha = _model(cli, tmp_path / "g", "g", {"m.pkl": craft.mixed()})["m.pkl"]
    cli("policy", "g", "--globals", "strict", "--by", "Owner")
    cli("check", "g", "--source", "picklescan")
    [policy] = _alerts(cli, "g", "globals_policy", "open")
    cli("alert", "dismiss", str(policy["alert_id"]), *DISMISS)
    clock.at = NOW + timedelta(hours=1)
    cli("policy", "g", "--globals", "strict", "--by", "Owner")  # the same value again
    _, checked = cli("check", "g", "--source", "picklescan")
    assert checked["models"][0]["dismissals_held"] == [policy["alert_id"]]
    cli("exception", "record", "--global", "os.system", "--sha256", sha,
        "--reason", "r", "--by", "O")  # fmt: skip
    _, checked = cli("check", "g", "--source", "picklescan")
    assert policy["alert_id"] in checked["models"][0]["dismissals_held"]
    assert _alerts(cli, "g", "globals_policy", "open") == []


def test_k2_reasserting_the_format_policy_holds_its_dismissal(
    cli: Any, tmp_path: Path, craft: ModuleType, clock: Clock
) -> None:
    _model(cli, tmp_path / "f", "f", {"i.pkl": craft.innocuous()})
    cli("policy", "f", "--format", "strict", "--by", "Owner")
    cli("check", "f", "--source", "picklescan")
    [alert] = _alerts(cli, "f", "format_policy", "open")
    cli("alert", "dismiss", str(alert["alert_id"]), *DISMISS)
    clock.at = NOW + timedelta(hours=1)
    cli("policy", "f", "--format", "strict", "--by", "Owner")
    cli("check", "f", "--source", "picklescan")
    assert _alerts(cli, "f", "format_policy", "open") == []


# --- K6: a held package alert stores no unlinked duplicate evidence ------------------------------


def test_k6_held_package_checks_add_no_evidence_rows(
    cli: Any, tmp_path: Path, derive_osv: Callable[..., Path]
) -> None:
    root = tmp_path / "p"
    root.mkdir()
    shutil.copy(FIXTURES / "locks" / "vulnerable.txt", root / "requirements.txt")
    (root / "model.toml").write_text(
        '[model]\nid = "p"\n\n[environment]\nlock = "requirements.txt"\n', "utf-8"
    )
    cli("register", str(root / "model.toml"))
    same = derive_osv()
    cli("check", "p", "--source", "osv", recordings=same)
    for alert in _alerts(cli, "p", "package_advisory", "open"):
        cli("alert", "dismiss", str(alert["alert_id"]), *DISMISS)

    def osv_rows() -> int:
        conn = sqlite3.connect(tmp_path / "db" / "md.db")
        try:
            return conn.execute(
                "SELECT count(*) FROM evidence WHERE source = 'osv.dev' AND url LIKE '%/vulns/%'"
            ).fetchone()[0]
        finally:
            conn.close()

    cli("check", "p", "--source", "osv", recordings=same)
    before = osv_rows()
    cli("check", "p", "--source", "osv", recordings=same)
    cli("check", "p", "--source", "osv", recordings=same)
    assert osv_rows() == before

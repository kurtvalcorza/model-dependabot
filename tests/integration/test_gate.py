"""The opt-in gate for pipelines end to end (T061; spec US5, quickstart 7, research S5, D8)."""

from __future__ import annotations

import hashlib
import json
import shutil
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from conftest import EICAR_COMMIT, EICAR_REPO
from model_dependabot.cli import EXIT_GATE, EXIT_OK, main, make_handlers
from model_dependabot.sources.fetcher import RecordedFetcher

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
HUB = f'hub = "hf:{EICAR_REPO}"\nrevision = "{EICAR_COMMIT}"\nfile = "pytorch_model.bin"'


@pytest.fixture
def cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> Callable[..., tuple[int, Any]]:
    db = tmp_path / "db" / "md.db"

    def invoke(*argv: str, recordings: Path | None = None) -> tuple[int, Any]:
        handlers = make_handlers(fetcher=RecordedFetcher(recordings or tmp_path / "none"))
        code = main([*argv, "--db", str(db), "--json"], handlers=handlers)
        out = capsys.readouterr().out
        return code, json.loads(out) if out.strip() else None

    return invoke


def _pickle_model(cli: Any, root: Path, data: bytes) -> str:
    root.mkdir(parents=True)
    (root / "d.pkl").write_bytes(data)
    (root / "model.toml").write_text('[model]\nid = "m"\n\n[[weights]]\npath = "d.pkl"\n', "utf-8")
    assert cli("register", str(root / "model.toml"))[0] == EXIT_OK
    return hashlib.sha256(data).hexdigest()


def gate(cli: Any, *argv: str, **kwargs: Any) -> tuple[int, dict[str, Any]]:
    code, checked = cli("check", *argv, **kwargs)
    return code, checked["gate"]


def test_independent_test_dismiss_then_pass(cli: Any, tmp_path: Path, craft: ModuleType) -> None:
    _pickle_model(cli, tmp_path / "m", craft.dangerous())
    code, found = gate(cli, "m", "--source", "picklescan", "--fail-on", "HIGH")
    assert code == EXIT_GATE
    [alert] = found["alerts"]
    assert cli("check", "m", "--source", "picklescan")[0] == EXIT_OK  # without it: 0 (SC-005)
    argv = ("--reason", "risk_accepted", "--by", "Owner")
    assert cli("alert", "dismiss", str(alert["alert_id"]), *argv)[0] == EXIT_OK
    code, found = gate(cli, "m", "--source", "picklescan", "--fail-on", "HIGH")
    assert (code, found["tripped"], found["decided_exit"]) == (EXIT_OK, False, True)
    _, checked = cli("check", "m", "--source", "picklescan", "--fail-on", "HIGH")
    assert checked["models"][0]["dismissals_held"] == [alert["alert_id"]]


def test_except_then_pass(cli: Any, tmp_path: Path, craft: ModuleType) -> None:
    sha = _pickle_model(cli, tmp_path / "m", craft.protocol2_getattr())
    assert gate(cli, "m", "--source", "picklescan", "--fail-on", "HIGH")[0] == EXIT_GATE
    argv = ("--global", "__builtin__.getattr", "--sha256", sha, "--reason", "r", "--by", "O")
    assert cli("exception", "record", *argv)[0] == EXIT_OK
    assert gate(cli, "m", "--source", "picklescan", "--fail-on", "HIGH")[0] == EXIT_OK


def test_an_alert_from_an_earlier_run_still_counts(
    cli: Any, tmp_path: Path, craft: ModuleType
) -> None:
    _pickle_model(cli, tmp_path / "m", craft.dangerous())
    assert cli("check", "m", "--source", "picklescan")[0] == EXIT_OK
    # A check asking only the policy-free hf-scan still judges the open HIGH alert.
    code, found = gate(cli, "m", "--source", "picklescan,hf-scan", "--fail-on", "HIGH")
    assert code == EXIT_GATE and found["alerts"]


def test_an_incomplete_scan_trips_critical(cli: Any, tmp_path: Path) -> None:
    root = tmp_path / "j"
    root.mkdir()
    shutil.copy(FIXTURES / "pickles" / "joblib-style.joblib", root / "m.joblib")
    (root / "model.toml").write_text(
        '[model]\nid = "j"\n\n[[weights]]\npath = "m.joblib"\n', "utf-8"
    )
    assert cli("register", str(root / "model.toml"))[0] == EXIT_OK
    code, found = gate(cli, "j", "--source", "picklescan", "--fail-on", "CRITICAL")
    assert code == EXIT_GATE
    assert found["alerts"] == [] and found["incomplete"] == [
        {"model_id": "j", "source": "picklescan"}
    ]


def test_absent_record_bytes_trip_every_run_until_picklescan_is_left_out(
    cli: Any, tmp_path: Path, derive_hf: Callable[..., Path]
) -> None:
    owner = tmp_path / "owner"
    (owner / "weights").mkdir(parents=True)
    shutil.copy(FIXTURES / "pickles" / "innocuous.pkl", owner / "weights" / "innocuous.pkl")
    manifest = owner / "model.toml"
    manifest.write_text(
        f'[model]\nid = "rec"\n\n[[weights]]\npath = "weights/innocuous.pkl"\n\n'
        f"[[weights]]\n{HUB}\n",
        "utf-8",
    )
    record = tmp_path / "out" / "model.record.json"
    assert cli("record", str(manifest), "--out", str(record))[0] == EXIT_OK
    ci = tmp_path / "ci"
    ci.mkdir()
    shutil.copy(manifest, ci / "model.toml")
    shutil.copy(record, ci / "model.record.json")
    clean = derive_hf()
    argv = ("register", str(ci / "model.toml"), "--from-record", str(ci / "model.record.json"))
    assert cli(*argv, recordings=clean)[0] == EXIT_OK
    for _ in range(2):
        code, found = gate(cli, "rec", "--source", "picklescan", "--fail-on", "CRITICAL")
        assert code == EXIT_GATE
        assert {"model_id": "rec", "source": "picklescan"} in found["incomplete"]
    code, found = gate(cli, "rec", "--source", "hf-scan", "--fail-on", "CRITICAL", recordings=clean)
    assert (code, found["tripped"]) == (EXIT_OK, False)


def test_fail_on_unknown_counts_every_severity(cli: Any, tmp_path: Path, craft: ModuleType) -> None:
    _pickle_model(cli, tmp_path / "m", craft.suspicious())
    assert cli("policy", "m", "--globals", "strict", "--by", "Owner")[0] == EXIT_OK
    code, found = gate(cli, "m", "--source", "picklescan", "--fail-on", "HIGH")
    assert code == EXIT_OK  # the MODERATE globals_policy alert is below HIGH
    assert gate(cli, "m", "--source", "picklescan", "--fail-on", "LOW")[0] == EXIT_GATE
    code, found = gate(cli, "m", "--source", "picklescan", "--fail-on", "UNKNOWN")
    assert code == EXIT_GATE
    assert [a["kind"] for a in found["alerts"]] == ["globals_policy"]

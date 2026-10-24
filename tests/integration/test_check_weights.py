"""Register and check weight files end to end, offline (T039; US3 Independent Test).

The dangerous pickle is built into ``tmp_path`` at test time and never committed; the hub answers
are the real recordings in ``tests/fixtures/hf`` or states derived from them by ``derive_hf``.
"""

from __future__ import annotations

import json
import shutil
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from conftest import EICAR_COMMIT, EICAR_REPO
from model_dependabot.cli import EXIT_OK, main, make_handlers
from model_dependabot.sources.fetcher import RecordedFetcher

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
PICKLES = FIXTURES / "pickles"
WEIGHTS = FIXTURES / "manifests" / "weights"


@pytest.fixture
def cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> Callable[..., tuple[int, Any]]:
    db = tmp_path / "db" / "md.db"

    def invoke(*argv: str, recordings: Path = tmp_path / "none") -> tuple[int, Any]:
        handlers = make_handlers(fetcher=RecordedFetcher(recordings))
        code = main([*argv, "--db", str(db), "--json"], handlers=handlers)
        out = capsys.readouterr().out
        return code, json.loads(out) if out.strip() else None

    return invoke


def manifest(directory: Path, model_id: str, weights: list[str]) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    lines = ["[model]", f'id = "{model_id}"', 'name = "Weights test model"', 'owner = "Owner"']
    for item in weights:
        lines += ["", "[[weights]]", item]
    path = directory / "model.toml"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def test_dangerous_benign_and_onnx(
    cli: Callable[..., tuple[int, Any]], tmp_path: Path, craft: ModuleType
) -> None:
    model = tmp_path / "model"
    model.mkdir()
    (model / "dangerous.pkl").write_bytes(craft.dangerous())
    shutil.copy(PICKLES / "innocuous.pkl", model / "innocuous.pkl")
    shutil.copy(WEIGHTS / "tiny.onnx", model / "tiny.onnx")
    weights = ['path = "dangerous.pkl"', 'path = "innocuous.pkl"', 'path = "tiny.onnx"']
    assert cli("register", str(manifest(model, "weights-model", weights)))[0] == EXIT_OK

    code, checked = cli("check", "weights-model")
    assert code == EXIT_OK
    assert checked["sources"] == {"osv": "ok", "picklescan": "ok", "hf-scan": "ok"}

    code, listed = cli("alerts", "weights-model")
    assert code == EXIT_OK
    [alert] = listed["alerts"]
    assert alert["kind"] == "weight_file_scan"
    assert (alert["severity"], alert["severity_origin"]) == ("HIGH", "policy")
    assert alert["cause"]["location"] == "dangerous.pkl"
    assert alert["cause"]["dangerous"] == ["os.system"]
    [evidence] = alert["evidence"]
    assert evidence["source"] == "picklescan"
    assert evidence["retrieved_at"].endswith("Z")
    events = listed["watch_events"]
    assert [event["kind"] for event in events] == ["pickle_format", "pickle_format"]
    assert {event["detail"]["location"] for event in events} == {"dangerous.pkl", "innocuous.pkl"}
    assert all(event["detail"]["location"] != "tiny.onnx" for event in events)

    code, shown = cli("alert", "show", str(alert["alert_id"]))
    assert code == EXIT_OK
    assert shown["evidence"] == alert["evidence"]


def test_joblib_file_is_code_capable_and_incompletely_scanned(
    cli: Callable[..., tuple[int, Any]], tmp_path: Path
) -> None:
    model = tmp_path / "model"
    model.mkdir()
    shutil.copy(PICKLES / "joblib-style.joblib", model / "model.joblib")
    assert cli("register", str(manifest(model, "joblib-model", ['path = "model.joblib"'])))[0] == 0
    _, shown = cli("inventory", "show", "joblib-model")
    [entry] = shown["entries"]
    assert (entry["format"], entry["can_run_code"]) == ("joblib", True)

    assert cli("check", "joblib-model")[0] == EXIT_OK
    _, listed = cli("alerts", "joblib-model")
    assert listed["alerts"] == []
    events = {event["kind"]: event for event in listed["watch_events"]}
    assert {"pickle_format", "scan_incomplete"} <= set(events)
    assert events["scan_incomplete"]["detail"]["scanner"] == "picklescan"
    assert events["scan_incomplete"]["detail"]["position"] == 43


def _flag_bin(info: Any) -> Any:
    issues = info["securityRepoStatus"]["filesWithIssues"]
    issues.append({"path": "pytorch_model.bin", "level": "unsafe"})
    return info


HUB_WEIGHT = f'hub = "hf:{EICAR_REPO}"\nrevision = "{EICAR_COMMIT}"\nfile = "pytorch_model.bin"'


def test_hub_verdicts_alert_only_for_unsafe_with_matching_hash(
    cli: Callable[..., tuple[int, Any]], tmp_path: Path, derive_hf: Callable[..., Path]
) -> None:
    clean = derive_hf()
    path = manifest(tmp_path / "hub", "hub-model", [HUB_WEIGHT])
    assert cli("register", str(path), recordings=clean)[0] == EXIT_OK

    assert cli("check", "hub-model", "--source", "hf-scan", recordings=clean)[0] == EXIT_OK
    assert cli("alerts", "hub-model")[1]["alerts"] == []

    unsafe = derive_hf(security=_flag_bin)
    code, checked = cli("check", "hub-model", "--source", "hf-scan", recordings=unsafe)
    assert (code, checked["sources"]) == (EXIT_OK, {"hf-scan": "ok"})
    [alert] = cli("alerts", "hub-model")[1]["alerts"]
    assert alert["kind"] == "hub_scan"
    assert alert["cause"]["verdict"] == "unsafe"
    assert alert["cause"]["identifier"].startswith("sha256:f9343d7d")

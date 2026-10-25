"""Weight-file findings in a check run (T038; FR-011, FR-013, research R4).

Dangerous fixtures are built into ``tmp_path`` at test time; nothing is ever unpickled.
"""

from __future__ import annotations

import hashlib
import shutil
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from model_dependabot.lifecycle import run_check
from model_dependabot.sources.fetcher import RecordedFetcher
from model_dependabot.store import Store

PICKLES = Path(__file__).resolve().parent.parent / "fixtures" / "pickles"
WEIGHTS = Path(__file__).resolve().parent.parent / "fixtures" / "manifests" / "weights"
MOMENT = datetime(2026, 10, 24, 8, 0, tzinfo=UTC)


def weight(directory: Path, name: str, data: bytes, file_format: str, code: bool) -> dict[str, Any]:
    (directory / name).write_bytes(data)
    return {
        "kind": "weight_file",
        "identifier": f"sha256:{hashlib.sha256(data).hexdigest()}",
        "pinned": True,
        "location": name,
        "size": len(data),
        "format": file_format,
        "can_run_code": code,
    }


@pytest.fixture
def store(tmp_path: Path) -> Store:
    with Store(tmp_path / "md.db", now=lambda: MOMENT) as opened:
        yield opened


def register(store: Store, model_id: str, entries: list[dict[str, Any]], base: Path) -> None:
    if store.get_model(model_id) is None:
        store.add_model(model_id)
    store.add_version(model_id, {}, "0" * 64, entries, base_dir=base)


def check(store: Store, tmp_path: Path, *model_ids: str) -> Any:
    return run_check(store, RecordedFetcher(tmp_path / "none"), list(model_ids), ["picklescan"])


@pytest.fixture
def files(tmp_path: Path, craft: ModuleType) -> dict[str, dict[str, Any]]:
    onnx = (WEIGHTS / "tiny.onnx").read_bytes()
    return {
        "dangerous": weight(tmp_path, "dangerous.pkl", craft.dangerous(), "pickle", True),
        "zip": weight(
            tmp_path, "dangerous.pt", craft.pytorch_zip(craft.dangerous()), "pytorch-zip", True
        ),
        "innocuous": weight(tmp_path, "innocuous.pkl", craft.innocuous(), "pickle", True),
        "suspicious": weight(tmp_path, "suspicious.pkl", craft.suspicious(), "pickle", True),
        "onnx": weight(tmp_path, "tiny.onnx", onnx, "onnx", False),
    }


def test_every_pickle_based_file_gets_a_pickle_format_watch_event(
    store: Store, tmp_path: Path, files: dict[str, dict[str, Any]]
) -> None:
    register(store, "m", [files["innocuous"], files["onnx"]], tmp_path)
    check(store, tmp_path, "m")
    [event] = store.watch_events("m")
    assert event["kind"] == "pickle_format"
    assert event["entry_identifier"] == files["innocuous"]["identifier"]
    assert event["detail"]["format"] == "pickle"
    assert "safetensors" in event["detail"]["suggestion"]
    assert event["detail"]["reason"] == "the format can run code when loaded"
    assert store.alerts_for("m") == []


def test_dangerous_scan_raises_a_weight_file_scan_alert(
    store: Store, tmp_path: Path, files: dict[str, dict[str, Any]]
) -> None:
    register(store, "m", [files["dangerous"]], tmp_path)
    outcome = check(store, tmp_path, "m")
    assert outcome.sources == {"picklescan": "ok"}
    [alert] = store.alerts_for("m")
    assert alert["kind"] == "weight_file_scan"
    assert (alert["severity"], alert["severity_origin"]) == ("HIGH", "policy")
    sha = files["dangerous"]["identifier"]
    assert alert["cause_key"] == f"weight_file_scan:{sha.removeprefix('sha256:')}"
    assert alert["cause"]["identifier"] == sha
    assert alert["cause"]["location"] == "dangerous.pkl"
    assert alert["cause"]["dangerous"] == ["os.system"]
    assert alert["cause"]["scanner"] == "picklescan"
    [evidence] = store.alert_evidence(alert["alert_id"])
    assert evidence["source"] == "picklescan"
    assert evidence["matched_identifier"] == sha
    assert evidence["retrieved_at"] == "2026-10-24T08:00:00Z"
    assert evidence["url"] == (tmp_path / "dangerous.pkl").resolve().as_uri()
    assert evidence["detail"]["dangerous"] == ["os.system"]
    assert len(evidence["body_sha256"]) == 64
    assert outcome.models[0]["opened"] == [alert["alert_id"]]


def test_pytorch_zip_wrapped_dangerous_pickle_raises_an_alert(
    store: Store, tmp_path: Path, files: dict[str, dict[str, Any]]
) -> None:
    register(store, "m", [files["zip"]], tmp_path)
    check(store, tmp_path, "m")
    [alert] = store.alerts_for("m")
    assert alert["cause"]["format"] == "pytorch-zip"
    assert alert["cause"]["dangerous"] == ["os.system"]


def test_suspicious_adds_a_watch_event(
    store: Store, tmp_path: Path, files: dict[str, dict[str, Any]]
) -> None:
    register(store, "m", [files["suspicious"]], tmp_path)
    check(store, tmp_path, "m")
    kinds = {event["kind"]: event for event in store.watch_events("m")}
    assert set(kinds) == {"pickle_format", "scan_suspicious"}
    assert kinds["scan_suspicious"]["detail"]["suspicious"] == [
        "model_dependabot_fixture.layers.CustomLayer"
    ]
    assert store.alerts_for("m") == []


def test_code_free_formats_get_nothing(
    store: Store, tmp_path: Path, files: dict[str, dict[str, Any]]
) -> None:
    shutil.copy(WEIGHTS / "tiny.safetensors", tmp_path / "tiny.safetensors")
    data = (tmp_path / "tiny.safetensors").read_bytes()
    safetensors = weight(tmp_path, "tiny.safetensors", data, "safetensors", False)
    register(store, "m", [files["onnx"], safetensors], tmp_path)
    check(store, tmp_path, "m")
    assert store.watch_events("m") == []
    assert store.alerts_for("m") == []


def test_same_dangerous_pickle_in_two_models_gives_each_its_own_alert(
    store: Store, tmp_path: Path, files: dict[str, dict[str, Any]]
) -> None:
    register(store, "a", [files["dangerous"]], tmp_path)
    register(store, "b", [files["dangerous"]], tmp_path)
    check(store, tmp_path, "a", "b")
    [first] = store.alerts_for("a")
    [second] = store.alerts_for("b")
    assert first["alert_id"] != second["alert_id"]
    assert first["cause_key"] == second["cause_key"]


def test_a_second_run_carries_the_alert_forward(
    store: Store, tmp_path: Path, files: dict[str, dict[str, Any]]
) -> None:
    register(store, "m", [files["dangerous"]], tmp_path)
    check(store, tmp_path, "m")
    outcome = check(store, tmp_path, "m")
    [alert] = store.alerts_for("m")
    assert outcome.models[0]["carried_forward"] == [alert["alert_id"]]
    assert len(store.alert_evidence(alert["alert_id"])) == 1  # identical evidence is reused
    assert len(store.watch_events("m")) == 1


def test_a_file_that_no_longer_matches_its_hash_is_not_scanned(
    store: Store, tmp_path: Path, files: dict[str, dict[str, Any]], craft: ModuleType
) -> None:
    register(store, "m", [files["innocuous"]], tmp_path)
    (tmp_path / "innocuous.pkl").write_bytes(craft.dangerous())
    check(store, tmp_path, "m")
    kinds = {event["kind"]: event for event in store.watch_events("m")}
    assert set(kinds) == {"pickle_format", "hash_mismatch"}
    assert kinds["hash_mismatch"]["detail"]["inventory_sha256"] == files["innocuous"][
        "identifier"
    ].removeprefix("sha256:")
    assert store.alerts_for("m") == []

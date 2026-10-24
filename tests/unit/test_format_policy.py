"""The owner's format policy (T039a; FR-021, constitution I 1.0.2)."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from model_dependabot.cli import EXIT_INVALID_INPUT, EXIT_OK, main, make_handlers
from model_dependabot.lifecycle import run_check
from model_dependabot.sources.fetcher import RecordedFetcher
from model_dependabot.store import Store

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
        opened.add_model("m")
        yield opened


def check(store: Store, tmp_path: Path, entries: list[dict[str, Any]]) -> None:
    store.add_version("m", {}, "0" * 64, entries, base_dir=tmp_path)
    run_check(store, RecordedFetcher(tmp_path / "none"), ["m"], ["picklescan", "hf-scan"])


def test_default_policy_gives_only_the_watch_event(
    store: Store, tmp_path: Path, craft: ModuleType
) -> None:
    check(store, tmp_path, [weight(tmp_path, "model.pkl", craft.innocuous(), "pickle", True)])
    assert [event["kind"] for event in store.watch_events("m")] == ["pickle_format"]
    assert store.alerts_for("m") == []


def test_strict_policy_raises_a_format_policy_alert(
    store: Store, tmp_path: Path, craft: ModuleType
) -> None:
    store.set_format_policy("m", "strict", set_by="Model owner")
    entry = weight(tmp_path, "model.pkl", craft.innocuous(), "pickle", True)
    check(store, tmp_path, [entry])
    [alert] = store.alerts_for("m")
    assert alert["kind"] == "format_policy"
    assert (alert["severity"], alert["severity_origin"]) == ("MODERATE", "policy")
    assert alert["cause"]["policy"] == "strict"
    assert alert["cause"]["identifier"] == entry["identifier"]
    [evidence] = store.alert_evidence(alert["alert_id"])
    assert evidence["source"] == "format-policy"
    assert evidence["url"] == ""
    assert evidence["matched_identifier"] == entry["identifier"]
    assert evidence["detail"] == {
        "format": "pickle",
        "policy": "strict",
        "set_by": "Model owner",
        "set_at": "2026-10-24T08:00:00Z",
        "location": "model.pkl",
    }
    stored = json.loads(store.read_body(evidence["body_sha256"]))
    assert stored == {
        "model_id": "m",
        "format_policy": "strict",
        "set_by": "Model owner",
        "set_at": "2026-10-24T08:00:00Z",
    }
    assert [event["kind"] for event in store.watch_events("m")] == ["pickle_format"]


def test_a_code_free_sibling_suppresses_the_policy_alert(
    store: Store, tmp_path: Path, craft: ModuleType
) -> None:
    store.set_format_policy("m", "strict", set_by="Model owner")
    pickled = weight(tmp_path, "model.pkl", craft.innocuous(), "pickle", True)
    sibling = weight(tmp_path, "model.safetensors", b"{}", "safetensors", False)
    check(store, tmp_path, [pickled, sibling])
    assert store.alerts_for("m") == []
    assert [event["kind"] for event in store.watch_events("m")] == ["pickle_format"]


def test_policy_command_records_who_and_when(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    db = tmp_path / "md.db"
    with Store(db) as store:
        store.add_model("m")
    handlers = make_handlers(fetcher=RecordedFetcher(tmp_path))
    argv = ["policy", "m", "--format", "strict", "--by", "Model owner", "--db", str(db), "--json"]
    assert main(argv, handlers=handlers) == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["format_policy"] == "strict"
    assert payload["set_by"] == "Model owner"
    assert payload["set_at"].endswith("Z")
    with Store(db) as store:
        model = store.get_model("m")
    assert (model["format_policy"], model["format_policy_set_by"]) == ("strict", "Model owner")
    assert model["format_policy_set_at"] == payload["set_at"]

    unknown = ["policy", "none", "--format", "strict", "--by", "x", "--db", str(db)]
    assert main(unknown, handlers=handlers) == EXIT_INVALID_INPUT
    bad = ["policy", "m", "--format", "lenient", "--by", "x", "--db", str(db)]
    assert main(bad, handlers=handlers) == EXIT_INVALID_INPUT

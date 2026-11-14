"""The strict globals policy end to end (T030; spec US2, quickstart 3, research S7).

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

from model_dependabot.assurance import globals_policy
from model_dependabot.cli import EXIT_OK, main, make_handlers
from model_dependabot.sources.fetcher import RecordedFetcher

LAYER = "model_dependabot_fixture.layers.CustomLayer"
NOW = datetime(2026, 11, 14, 9, 0, tzinfo=UTC)
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


def ok(cli: Cli, *argv: str) -> Any:
    code, payload = cli(*argv)
    assert code == EXIT_OK, payload
    return payload


def register(cli: Cli, root: Path, model_id: str, files: dict[str, bytes]) -> dict[str, str]:
    root.mkdir(parents=True, exist_ok=True)
    lines = ["[model]", f'id = "{model_id}"']
    for name, data in files.items():
        (root / name).write_bytes(data)
        lines += ["", "[[weights]]", f'path = "{name}"']
    (root / "model.toml").write_text("\n".join(lines) + "\n", encoding="utf-8")
    ok(cli, "register", str(root / "model.toml"), "--model-id", model_id)
    return {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}


def strict(cli: Cli, model_id: str) -> None:
    ok(cli, "policy", model_id, "--globals", "strict", "--by", "Owner")


def scan(cli: Cli, model_id: str, *sources: str) -> None:
    ok(cli, "check", model_id, "--source", ",".join(sources or ("picklescan",)))


def alerts(cli: Cli, model_id: str, kind: str, state: str = "open") -> list[dict[str, Any]]:
    payload = ok(cli, "alerts", model_id, "--state", state)
    return [a for a in payload["alerts"] + payload["excepted"] if a["kind"] == kind]


def test_independent_test_with_a_mixed_file(cli: Cli, tmp_path: Path, craft: ModuleType) -> None:
    sha = register(cli, tmp_path / "m", "mixed", {"mixed.pkl": craft.mixed()})["mixed.pkl"]
    strict(cli, "mixed")
    scan(cli, "mixed")
    [high] = alerts(cli, "mixed", "weight_file_scan")
    assert (high["severity"], high["cause"]["dangerous"]) == ("HIGH", ["os.system"])
    [policy] = alerts(cli, "mixed", "globals_policy")
    assert (policy["severity"], policy["severity_origin"]) == ("MODERATE", "policy")
    cause = policy["cause"]
    assert cause["identifier"] == f"sha256:{sha}"
    assert cause["unlisted"] == [LAYER, "os.system"]
    assert "collections.OrderedDict" not in json.dumps(cause["unlisted"])
    assert cause["excepted"] == []
    assert (cause["policy"], cause["set_by"], cause["set_at"]) == (
        "strict",
        "Owner",
        "2026-11-14T09:00:00Z",
    )
    assert cause["safe_list_version"] == 1
    assert len(cause["safe_list_sha256"]) == 64
    assert cause["scan"]["complete"] is True
    assert cause["location"] == "mixed.pkl"
    record = next(e for e in policy["evidence"] if e["source"] == "globals-policy")
    assert record["detail"]["unlisted"] == [LAYER, "os.system"]
    assert record["detail"]["excepted"] == []
    assert any(e["source"] == "picklescan" for e in policy["evidence"])

    # One exception for (os.system, hash) excepts the HIGH alert and leaves the policy alert's list.
    ok(cli, "exception", "record", "--global", "os.system", "--sha256", sha,
       "--reason", "reviewed", "--by", "Owner")  # fmt: skip
    scan(cli, "mixed")
    [high] = alerts(cli, "mixed", "weight_file_scan")
    assert high["state"] == "excepted"
    [again] = alerts(cli, "mixed", "globals_policy")
    assert again["alert_id"] == policy["alert_id"]
    assert again["cause"]["unlisted"] == [LAYER]
    assert [x["global"] for x in again["cause"]["excepted"]] == ["os.system"]
    records = [e for e in again["evidence"] if e["source"] == "globals-policy"]
    assert records[-1]["detail"]["excepted"] == ["os.system"]

    # Back to default: nothing changes until a check that asks a weight source.
    ok(cli, "policy", "mixed", "--globals", "default", "--by", "Owner")
    assert len(alerts(cli, "mixed", "globals_policy")) == 1
    scan(cli, "mixed", "osv")
    assert len(alerts(cli, "mixed", "globals_policy")) == 1
    scan(cli, "mixed")
    assert alerts(cli, "mixed", "globals_policy") == []
    [cleared] = alerts(cli, "mixed", "globals_policy", "closed")
    assert cleared["state"] == "cleared"
    assert cleared["note"] == "cleared: policy"


def test_the_default_policy_raises_no_globals_alert(
    cli: Cli, tmp_path: Path, craft: ModuleType
) -> None:
    register(cli, tmp_path / "m", "mixed", {"mixed.pkl": craft.mixed()})
    scan(cli, "mixed")
    assert alerts(cli, "mixed", "globals_policy", "all") == []


def test_an_exception_clears_the_last_unlisted_global(
    cli: Cli, tmp_path: Path, craft: ModuleType
) -> None:
    sha = register(cli, tmp_path / "m", "layer", {"s.pkl": craft.suspicious()})["s.pkl"]
    strict(cli, "layer")
    scan(cli, "layer")
    [policy] = alerts(cli, "layer", "globals_policy")
    assert policy["cause"]["unlisted"] == [LAYER]
    ok(cli, "exception", "record", "--global", LAYER, "--sha256", sha,
       "--reason", "our own layer", "--by", "Owner")  # fmt: skip
    scan(cli, "layer")
    [cleared] = alerts(cli, "layer", "globals_policy", "closed")
    assert cleared["note"] == "cleared: exception"
    assert any(e["source"] == "exception" for e in cleared["evidence"])


def test_a_newer_safe_list_clears_the_alert(
    cli: Cli, tmp_path: Path, craft: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    register(cli, tmp_path / "m", "layer", {"s.pkl": craft.suspicious()})
    strict(cli, "layer")
    scan(cli, "layer")
    assert len(alerts(cli, "layer", "globals_policy")) == 1
    newer = tmp_path / "safe-globals.toml"
    newer.write_text(
        'version = 2\n\n[[entries]]\nmodule = "model_dependabot_fixture.layers"\n'
        'name = "CustomLayer"\nwhy = "test"\nadded_in = 2\n\n'
        '[[changes]]\nversion = 2\ndate = "2026-11-14"\nsummary = "test"\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(globals_policy, "SAFE_LIST_PATH", newer)
    scan(cli, "layer")
    [cleared] = alerts(cli, "layer", "globals_policy", "closed")
    assert cleared["note"] == "cleared: safe_list"
    record = next(e for e in reversed(cleared["evidence"]) if e["source"] == "globals-policy")
    assert record["detail"]["safe_list_version"] == 2


def test_an_incomplete_scan_is_not_clean(cli: Cli, tmp_path: Path) -> None:
    root = tmp_path / "m"
    root.mkdir()
    data = (Path(__file__).resolve().parent.parent / "fixtures" / "pickles").joinpath(
        "joblib-style.joblib"
    )
    register(cli, root, "jl", {"model.joblib": data.read_bytes()})
    strict(cli, "jl")
    scan(cli, "jl")
    [policy] = alerts(cli, "jl", "globals_policy")
    assert policy["cause"]["scan"]["complete"] is False
    _, listed = cli("alerts", "jl")
    assert "scan_incomplete" in {e["kind"] for e in listed["watch_events"]}


def test_a_version_without_the_file_fixes_the_alert(
    cli: Cli, tmp_path: Path, craft: ModuleType
) -> None:
    register(cli, tmp_path / "m", "layer", {"s.pkl": craft.suspicious()})
    strict(cli, "layer")
    scan(cli, "layer")
    [policy] = alerts(cli, "layer", "globals_policy")
    register(cli, tmp_path / "m2", "layer", {"i.pkl": craft.innocuous()})
    [fixed] = alerts(cli, "layer", "globals_policy", "closed")
    assert (fixed["alert_id"], fixed["state"]) == (policy["alert_id"], "fixed")

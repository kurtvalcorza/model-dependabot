"""The exit-code table with and without ``--fail-on`` (T060, contracts/cli.md of 004, SC-005)."""

from __future__ import annotations

import json
import shutil
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from model_dependabot.cli import (
    EXIT_GATE,
    EXIT_INVALID_INPUT,
    EXIT_OK,
    EXIT_SOURCE_FAILED,
    EXIT_UNEXPECTED,
    main,
    make_handlers,
)
from model_dependabot.sources.fetcher import RecordedFetcher

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
GATE = {"fail_on", "tripped", "decided_exit", "alerts", "incomplete", "unchecked", "empty_scope"}


@pytest.fixture
def cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> Callable[..., tuple[int, Any]]:
    db = tmp_path / "db" / "md.db"

    def invoke(*argv: str, recordings: Path | None = None) -> tuple[int, Any]:
        handlers = make_handlers(fetcher=RecordedFetcher(recordings or tmp_path / "none"))
        code = main([*argv, "--db", str(db), "--json"], handlers=handlers)
        out = capsys.readouterr().out
        return code, json.loads(out) if out.strip() else None

    return invoke


def _register(cli: Any, root: Path, model_id: str, name: str, data: bytes) -> None:
    root.mkdir(parents=True)
    (root / name).write_bytes(data)
    (root / "model.toml").write_text(
        f'[model]\nid = "{model_id}"\n\n[[weights]]\npath = "{name}"\n', "utf-8"
    )
    assert cli("register", str(root / "model.toml"))[0] == EXIT_OK


@pytest.fixture
def high(cli: Any, tmp_path: Path, craft: ModuleType) -> Any:
    """One model with one open HIGH alert and every asked source complete."""
    _register(cli, tmp_path / "h", "high", "d.pkl", craft.dangerous())
    return cli


def test_without_fail_on_findings_still_exit_0(high: Any) -> None:
    code, checked = high("check", "high", "--source", "picklescan")
    assert code == EXIT_OK
    assert "gate" not in checked


def test_without_fail_on_a_failed_source_exits_2(high: Any, derive_osv: Callable) -> None:
    down = derive_osv(errors={"querybatch-vulnerable": "timed out"})
    code, _ = high("check", "high", "--source", "picklescan,hf-scan", recordings=down)
    assert code in (EXIT_OK, EXIT_SOURCE_FAILED)  # no hub file, so hf-scan has nothing to ask


@pytest.mark.parametrize("argv", [("check", "nobody"), ("check",), ("policy", "high", "--by", "O")])
def test_invalid_input_exits_1(high: Any, argv: tuple[str, ...]) -> None:
    assert high(*argv)[0] == EXIT_INVALID_INPUT


def test_the_gate_by_severity(high: Any) -> None:
    code, checked = high("check", "high", "--source", "picklescan", "--fail-on", "CRITICAL")
    assert code == EXIT_OK
    assert set(checked["gate"]) == GATE
    assert (checked["gate"]["tripped"], checked["gate"]["decided_exit"]) == (False, True)
    assert checked["gate"]["fail_on"] == "CRITICAL"
    code, checked = high("check", "high", "--source", "picklescan", "--fail-on", "high")
    assert code == EXIT_GATE
    gate = checked["gate"]
    assert (gate["fail_on"], gate["tripped"], gate["decided_exit"]) == ("HIGH", True, True)
    [alert] = gate["alerts"]
    assert set(alert) == {"alert_id", "model_id", "rule_id", "kind", "severity"}
    assert (alert["rule_id"], alert["severity"]) == ("MDB101", "HIGH")


def test_an_invalid_severity_exits_1(high: Any) -> None:
    code, payload = high("check", "high", "--fail-on", "SEVERE")
    assert code == EXIT_INVALID_INPUT
    assert "--fail-on" in payload["error"]["message"]


def test_an_incomplete_source_trips_the_gate(cli: Any, tmp_path: Path) -> None:
    data = (FIXTURES / "pickles" / "joblib-style.joblib").read_bytes()
    _register(cli, tmp_path / "j", "partial", "m.joblib", data)
    code, checked = cli("check", "partial", "--source", "picklescan", "--fail-on", "CRITICAL")
    assert code == EXIT_GATE
    assert checked["gate"]["incomplete"] == [{"model_id": "partial", "source": "picklescan"}]
    assert checked["gate"]["alerts"] == []


def test_an_unchecked_model_trips_the_gate(cli: Any, tmp_path: Path) -> None:
    root = tmp_path / "o"
    root.mkdir()
    shutil.copy(FIXTURES / "manifests" / "weights" / "tiny.onnx", root / "t.onnx")
    (root / "model.toml").write_text(
        '[model]\nid = "onnx"\n\n[[weights]]\npath = "t.onnx"\n', "utf-8"
    )
    assert cli("register", str(root / "model.toml"))[0] == EXIT_OK
    code, checked = cli("check", "onnx", "--source", "picklescan", "--fail-on", "LOW")
    assert code == EXIT_GATE
    assert checked["gate"]["unchecked"] == ["onnx"]


def test_an_empty_scope_trips_the_gate(cli: Any) -> None:
    code, checked = cli("check", "--all", "--source", "osv", "--fail-on", "LOW")
    assert code == EXIT_GATE
    assert checked["gate"]["empty_scope"] is True


def test_a_failed_source_wins_over_the_gate(
    cli: Any, tmp_path: Path, craft: ModuleType, derive_hf: Callable[..., Path]
) -> None:
    hub = (
        'hub = "hf:mcpotato/42-eicar-street"\nrevision = "8fb61c4d511e9aaff0ea55396a124aa292830efc"'
    )
    root = tmp_path / "x"
    root.mkdir()
    (root / "d.pkl").write_bytes(craft.dangerous())
    (root / "model.toml").write_text(
        f'[model]\nid = "x"\n\n[[weights]]\npath = "d.pkl"\n\n'
        f'[[weights]]\n{hub}\nfile = "pytorch_model.bin"\n',
        "utf-8",
    )
    assert cli("register", str(root / "model.toml"), recordings=derive_hf())[0] == EXIT_OK
    down = derive_hf(errors={"eicar-security": "HTTP 503"})
    code, checked = cli(
        "check", "x", "--source", "picklescan,hf-scan", "--fail-on", "HIGH", recordings=down
    )
    assert code == EXIT_SOURCE_FAILED
    assert (checked["gate"]["tripped"], checked["gate"]["decided_exit"]) == (True, False)


def test_an_unexpected_error_wins_over_everything(
    high: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    from model_dependabot import lifecycle

    def boom(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr(lifecycle, "_apply_globals_rules", boom)
    code, payload = high("check", "high", "--source", "picklescan", "--fail-on", "LOW")
    assert code == EXIT_UNEXPECTED
    assert "gate" not in payload

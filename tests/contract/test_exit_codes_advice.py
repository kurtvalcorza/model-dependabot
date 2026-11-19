"""``--advice`` changes no exit code (T035, FR-017, US4 scenarios 2 and 3)."""

from __future__ import annotations

import importlib.util
import io
import json
import shutil
import sys
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import ModuleType

import pytest

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
BASELINE = json.loads((FIXTURES / "cli_baseline" / "pre-010-baseline.json").read_text("utf-8"))


def _scenarios() -> ModuleType:
    name = "cli_baseline_scenarios"
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(
            name, FIXTURES / "cli_baseline" / "scenarios.py"
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


@pytest.fixture(scope="module")
def built(tmp_path_factory: pytest.TempPathFactory, craft: ModuleType):
    scenarios = _scenarios()
    baseline = scenarios.Baseline(tmp_path_factory.mktemp("advice-exit"), craft)
    scenarios.build(baseline)
    return baseline


def test_every_alerts_and_alert_show_invocation_exits_the_same(built) -> None:
    for item in BASELINE["invocations"]:
        if item["argv"][0] not in ("alerts", "alert"):
            continue
        code, _, _ = built.run([*item["argv"], "--advice"])
        assert code == item["exit_code"], item["name"]


def test_check_gates_the_same_after_advice_of_every_alert(built) -> None:
    for model in ("weights-model", "pillow-model"):
        assert built.run(["alerts", model, "--state", "all", "--advice", "--json"])[0] == 0
    target = built.db("gate-after-advice")
    shutil.copytree(built.db("md").parent, target.parent)
    argv = ["check", "weights-model", "--source", "picklescan", "--fail-on", "HIGH"]
    recorded = next(
        i for i in BASELINE["invocations"] if i["name"] == "check --fail-on HIGH --json"
    )
    code, out, _ = built.run([*argv, "--json"], db="gate-after-advice")
    assert code == recorded["exit_code"] == 4
    now, then = json.loads(out), json.loads(recorded["stdout"])
    assert now["gate"] == then["gate"]


@pytest.mark.parametrize(
    "argv",
    [["check", "weights-model"], ["history", "weights-model"], ["run", "show", "1"]],
)
def test_other_commands_refuse_advice(built, argv: list[str]) -> None:
    code, _, err = built.run([*argv, "--advice"])
    assert code == 1
    assert "--advice" in err


def test_an_unknown_model_or_alert_exits_1_with_and_without_advice(built) -> None:
    for argv in (["alerts", "no-such-model"], ["alert", "show", "999"]):
        for extra in ([], ["--advice"], ["--json"], ["--advice", "--json"]):
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                code = built.run([*argv, *extra])[0]
            assert code == 1

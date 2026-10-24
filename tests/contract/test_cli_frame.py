"""Contract tests for the command frame: shared options and exit codes (contracts/cli.md)."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

import pytest

from model_dependabot.cli import (
    COMMANDS,
    EXIT_INVALID_INPUT,
    EXIT_OK,
    EXIT_SOURCE_FAILED,
    EXIT_UNEXPECTED,
    CommandResult,
    InvalidInputError,
    main,
)

# One valid invocation per command in contracts/cli.md.
INVOCATIONS = {
    "register": ["register", "model.toml", "--model-id", "m"],
    "import": ["import", "bom.json", "--model-id", "m"],
    "inventory show": ["inventory", "show", "m", "--version", "2"],
    "inventory export": ["inventory", "export", "m", "-o", "out.json"],
    "check": ["check", "m", "--source", "osv,picklescan,hf-scan"],
    "policy": ["policy", "m", "--format", "strict", "--by", "Owner"],
    "alerts": ["alerts", "m", "--state", "all"],
    "alert show": ["alert", "show", "17"],
    "alert dismiss": ["alert", "dismiss", "17", "--reason", "risk_accepted", "--by", "Owner"],
    "history": ["history", "m"],
}


class Recorder:
    """A handler that records the arguments it was called with and returns a fixed result."""

    def __init__(self, result: CommandResult | Exception | None = None) -> None:
        self.result = result or CommandResult(payload={"ok": True}, text="done")
        self.args: argparse.Namespace | None = None

    def __call__(self, args: argparse.Namespace) -> CommandResult:
        self.args = args
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def handlers_for(command: str, recorder: Recorder) -> dict[str, Recorder]:
    return {command: recorder}


def test_the_frame_knows_every_command_of_the_contract() -> None:
    assert set(COMMANDS) == set(INVOCATIONS)


def test_exit_code_values() -> None:
    assert (EXIT_OK, EXIT_INVALID_INPUT, EXIT_SOURCE_FAILED, EXIT_UNEXPECTED) == (0, 1, 2, 3)


@pytest.mark.parametrize("command", sorted(INVOCATIONS))
def test_every_command_accepts_db_and_json_after_it(command: str, tmp_path: Path) -> None:
    recorder = Recorder()
    db = str(tmp_path / "x.db")
    code = main(
        [*INVOCATIONS[command], "--db", db, "--json"], handlers=handlers_for(command, recorder)
    )
    assert code == EXIT_OK
    assert recorder.args is not None
    assert recorder.args.db == db
    assert recorder.args.json is True


@pytest.mark.parametrize("command", sorted(INVOCATIONS))
def test_every_command_accepts_db_and_json_before_it(command: str, tmp_path: Path) -> None:
    recorder = Recorder()
    db = str(tmp_path / "x.db")
    code = main(
        ["--db", db, "--json", *INVOCATIONS[command]], handlers=handlers_for(command, recorder)
    )
    assert code == EXIT_OK
    assert recorder.args.db == db
    assert recorder.args.json is True


def test_db_defaults_to_the_working_directory() -> None:
    recorder = Recorder()
    assert main(INVOCATIONS["history"], handlers=handlers_for("history", recorder)) == EXIT_OK
    assert recorder.args.db == "./model-dependabot.db"
    assert recorder.args.json is False


def test_text_output_by_default(capsys: pytest.CaptureFixture[str]) -> None:
    recorder = Recorder(CommandResult(payload={"model_id": "m"}, text="model m"))
    assert main(INVOCATIONS["history"], handlers=handlers_for("history", recorder)) == EXIT_OK
    assert capsys.readouterr().out.strip() == "model m"


def test_json_output_with_json(capsys: pytest.CaptureFixture[str]) -> None:
    recorder = Recorder(CommandResult(payload={"model_id": "m", "alerts": []}, text="model m"))
    code = main([*INVOCATIONS["alerts"], "--json"], handlers=handlers_for("alerts", recorder))
    assert code == EXIT_OK
    assert json.loads(capsys.readouterr().out) == {"model_id": "m", "alerts": []}


@pytest.mark.parametrize(
    "argv",
    [
        ["no-such-command"],
        [],
        ["register"],
        ["import", "bom.json"],
        ["inventory", "export", "m"],
        ["inventory", "show", "m", "--version", "two"],
        ["check"],
        ["check", "m", "--all"],
        ["check", "--all", "--source", "osv,rumours"],
        ["policy", "m", "--format", "lenient", "--by", "Owner"],
        ["policy", "m", "--format", "strict"],
        ["alerts", "m", "--state", "maybe"],
        ["alert", "show", "seventeen"],
        ["alert", "dismiss", "17", "--reason", "bored", "--by", "Owner"],
        ["alert", "dismiss", "17", "--reason", "risk_accepted"],
        ["history", "m", "--unknown-flag"],
    ],
)
def test_invalid_arguments_exit_1(argv: list[str], capsys: pytest.CaptureFixture[str]) -> None:
    recorder = Recorder()
    handlers = {command: recorder for command in INVOCATIONS}
    assert main(argv, handlers=handlers) == EXIT_INVALID_INPUT
    assert recorder.args is None
    assert capsys.readouterr().err


def test_check_accepts_all_without_an_id() -> None:
    recorder = Recorder()
    assert main(["check", "--all"], handlers=handlers_for("check", recorder)) == EXIT_OK
    assert recorder.args.all is True
    assert recorder.args.sources == ["osv", "picklescan", "hf-scan"]


def test_invalid_input_from_a_command_exits_1(capsys: pytest.CaptureFixture[str]) -> None:
    recorder = Recorder(InvalidInputError("model.id is required"))
    assert main(INVOCATIONS["register"], handlers=handlers_for("register", recorder)) == 1
    assert "model.id is required" in capsys.readouterr().err


def test_invalid_input_in_json_mode_is_reported_as_json(capsys: pytest.CaptureFixture[str]) -> None:
    recorder = Recorder(InvalidInputError("model.id is required"))
    argv = [*INVOCATIONS["register"], "--json"]
    assert main(argv, handlers=handlers_for("register", recorder)) == 1
    error = json.loads(capsys.readouterr().out)["error"]
    assert error == {"exit_code": 1, "message": "model.id is required"}


def test_a_failed_source_exits_2_and_still_prints(capsys: pytest.CaptureFixture[str]) -> None:
    result = CommandResult(
        payload={"sources": {"osv": "failed: timeout"}}, text="osv failed", sources_failed=True
    )
    code = main([*INVOCATIONS["check"], "--json"], handlers=handlers_for("check", Recorder(result)))
    assert code == EXIT_SOURCE_FAILED
    assert json.loads(capsys.readouterr().out) == {"sources": {"osv": "failed: timeout"}}


def test_an_unexpected_error_exits_3_without_a_traceback(
    capsys: pytest.CaptureFixture[str],
) -> None:
    recorder = Recorder(RuntimeError("disk on fire"))
    assert main(INVOCATIONS["history"], handlers=handlers_for("history", recorder)) == 3
    err = capsys.readouterr().err
    assert "disk on fire" in err
    assert "Traceback" not in err


def test_a_command_without_a_handler_exits_3(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(INVOCATIONS["history"], handlers={}) == EXIT_UNEXPECTED
    assert "no handler for the history command" in capsys.readouterr().err


def test_help_exits_0(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--help"]) == EXIT_OK
    assert "register" in capsys.readouterr().out


def test_the_module_runs_as_a_process_with_the_same_exit_codes() -> None:
    process = subprocess.run(
        [sys.executable, "-m", "model_dependabot.cli", "no-such-command"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert process.returncode == EXIT_INVALID_INPUT

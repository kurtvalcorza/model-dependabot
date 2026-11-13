"""``run show RUN_ID`` (T039, contracts/cli.md of 004, owner's ruling D5)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from model_dependabot.cli import EXIT_INVALID_INPUT, EXIT_OK, main, make_handlers
from model_dependabot.sources.fetcher import RecordedFetcher

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


@pytest.fixture
def cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    db = tmp_path / "md.db"
    handlers = make_handlers(fetcher=RecordedFetcher(tmp_path / "none"))

    def invoke(*argv: str, as_json: bool = True) -> tuple[int, Any]:
        code = main([*argv, "--db", str(db), *(["--json"] if as_json else [])], handlers=handlers)
        out = capsys.readouterr().out
        return code, (json.loads(out) if as_json and out.strip() else out)

    model = tmp_path / "m"
    model.mkdir()
    (model / "i.pkl").write_bytes((FIXTURES / "pickles" / "innocuous.pkl").read_bytes())
    (model / "model.toml").write_text('[model]\nid = "m"\n\n[[weights]]\npath = "i.pkl"\n', "utf-8")
    assert invoke("register", str(model / "model.toml"))[0] == EXIT_OK
    return invoke


def test_run_show_matches_the_check(cli) -> None:
    code, checked = cli("check", "m", "--source", "picklescan")
    assert code == EXIT_OK
    code, shown = cli("run", "show", str(checked["run_id"]))
    assert code == EXIT_OK
    assert set(shown) == {
        "run_id", "scope", "trigger", "started_at", "finished_at", "sources", "overview",
    }  # fmt: skip
    assert (shown["run_id"], shown["scope"], shown["sources"]) == (
        checked["run_id"],
        "m",
        {"picklescan": "ok"},
    )
    assert shown["overview"] == checked["overview"]
    [model] = shown["overview"]["models"]
    assert set(model) == {"model_id", "version", "checked", "reason", "sources"}
    assert set(model["sources"][0]) == {
        "source", "state", "reason", "entries", "incomplete", "alerts_open",
        "alerts_excepted", "watch_events", "dismissals_held",
    }  # fmt: skip
    code, text = cli("run", "show", str(checked["run_id"]), as_json=False)
    assert code == EXIT_OK
    assert f"Overview of run {checked['run_id']} (m)" in text
    assert "m v1: checked" in text


def test_an_unknown_run_exits_1(cli) -> None:
    code, payload = cli("run", "show", "99")
    assert code == EXIT_INVALID_INPUT
    assert "no check run 99" in payload["error"]["message"]

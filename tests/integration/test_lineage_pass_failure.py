"""The lineage pass runs inside the check's error handling and adds no overview row (T061, R5)."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from lineage_support import Cli, manifest
from model_dependabot.cli import EXIT_OK, EXIT_UNEXPECTED
from model_dependabot.lineage import propagate
from model_dependabot.store import Store


@pytest.fixture
def cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> Cli:
    for name in ("chain-grandparent", "chain-parent"):
        Cli(tmp_path, capsys).ok("register", manifest(name))
    return Cli(tmp_path, capsys)


def test_a_failing_lineage_pass_still_finishes_the_run(
    cli: Cli, monkeypatch: pytest.MonkeyPatch, derive_upstream: Callable[..., Path]
) -> None:
    def broken(*args: object, **kwargs: object) -> list:
        raise RuntimeError("lineage pass broke")

    monkeypatch.setattr(propagate, "inherited", broken)
    code, _ = cli.run("check", "--all", "--source", "hf-hub", root=derive_upstream())
    assert code == EXIT_UNEXPECTED
    with Store(cli.db) as store:
        run = store.latest_check_run()
        assert run is not None and run["finished_at"] is not None
        assert run["sources"] == {"hf-hub": "ok"}  # the source had completed before the pass
        assert store.check_run_overview(run["run_id"])  # the overview was stored
        [alert] = store.alerts_for("example-grand", ["open"])
        assert alert["kind"] == "base_model_disabled"  # what was applied before is kept


def test_a_passing_lineage_pass_adds_no_overview_row(
    cli: Cli, derive_upstream: Callable[..., Path]
) -> None:
    code, payload = cli.run("check", "--all", "--source", "hf-hub", root=derive_upstream())
    assert code == EXIT_OK
    with Store(cli.db) as store:
        rows = store.check_run_overview(payload["run_id"])
    assert rows and {row["source"] for row in rows} <= {"hf-hub", None}
    mid = next(model for model in payload["models"] if model["model_id"] == "example-mid")
    assert len(mid["watch_events"]) == 1

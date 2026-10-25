"""``check --scheduled`` and the new source names (contracts/cli.md, tasks T017)."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from model_dependabot.cli import CHECK_SOURCES, EXIT_INVALID_INPUT, EXIT_OK, main, make_handlers
from model_dependabot.sources.fetcher import RecordedFetcher
from model_dependabot.store import Store

NEW_SOURCES = ("hf-hub", "hf-takedowns", "crossref", "datacite", "zenodo", "figshare")
Invoke = Callable[..., tuple[int, Any]]


@pytest.fixture
def db(tmp_path: Path) -> Path:
    return tmp_path / "db" / "md.db"


@pytest.fixture
def cli(tmp_path: Path, db: Path, capsys: pytest.CaptureFixture[str]) -> Invoke:
    empty = tmp_path / "recordings"
    empty.mkdir()
    handlers = make_handlers(fetcher=RecordedFetcher(empty))
    manifest = tmp_path / "model.toml"
    manifest.write_text('[model]\nid = "m"\n', encoding="utf-8")

    def invoke(*argv: str) -> tuple[int, Any]:
        code = main([*argv, "--db", str(db), "--json"], handlers=handlers)
        out = capsys.readouterr().out
        return code, json.loads(out) if out.strip() else None

    assert invoke("register", str(manifest))[0] == EXIT_OK
    return invoke


def _trigger(db: Path, run_id: int) -> str:
    with Store(db) as store:
        return store.get_check_run(run_id)["trigger"]


def test_check_all_scheduled_records_scheduled(cli: Invoke, db: Path) -> None:
    code, payload = cli("check", "--all", "--scheduled")
    assert code == EXIT_OK
    assert payload["trigger"] == "scheduled"
    assert _trigger(db, payload["run_id"]) == "scheduled"


@pytest.mark.parametrize(
    "argv", [("check", "--all"), ("check", "m"), ("check", "m", "--scheduled")]
)
def test_any_other_check_records_on_demand(cli: Invoke, db: Path, argv: tuple[str, ...]) -> None:
    code, payload = cli(*argv)
    assert code == EXIT_OK
    assert payload["trigger"] == "on_demand"
    assert _trigger(db, payload["run_id"]) == "on_demand"


def test_the_new_source_names_are_accepted(cli: Invoke) -> None:
    assert set(NEW_SOURCES) <= set(CHECK_SOURCES)
    assert {"osv", "picklescan", "hf-scan"} <= set(CHECK_SOURCES)
    code, payload = cli("check", "m", "--source", ",".join(NEW_SOURCES))
    assert code == EXIT_OK
    assert set(payload["sources"]) == set(NEW_SOURCES)


def test_omitting_source_runs_every_source(cli: Invoke) -> None:
    code, payload = cli("check", "--all", "--scheduled")
    assert code == EXIT_OK
    assert set(payload["sources"]) == set(CHECK_SOURCES)


def test_an_unknown_source_is_invalid_input(cli: Invoke) -> None:
    assert cli("check", "m", "--source", "orcid")[0] == EXIT_INVALID_INPUT

"""Register, show, export and import end to end, offline (T017, US1, SC-001, SC-005)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from model_dependabot.cli import EXIT_INVALID_INPUT, EXIT_OK, main, make_handlers
from model_dependabot.inventory.cyclonedx import validate
from model_dependabot.sources.fetcher import RecordedFetcher
from model_dependabot.store import Store

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
EXAMPLE = FIXTURES / "manifests" / "example.toml"


@pytest.fixture
def run(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    db = tmp_path / "md.db"
    handlers = make_handlers(fetcher=RecordedFetcher(FIXTURES / "hf"))

    def invoke(*argv: str) -> tuple[int, Any]:
        code = main([*argv, "--db", str(db), "--json"], handlers=handlers)
        out = capsys.readouterr().out
        return code, json.loads(out) if out.strip() else None

    invoke.db = db  # type: ignore[attr-defined]
    return invoke


def test_register_show_export_import(run, tmp_path: Path) -> None:
    code, registered = run("register", str(EXAMPLE))
    assert code == EXIT_OK
    assert (registered["model_id"], registered["version"]) == ("example-detector", 1)

    code, shown = run("inventory", "show", "example-detector")
    assert code == EXIT_OK
    assert shown["version"] == 1
    kinds = sorted({entry["kind"] for entry in shown["entries"]})
    assert kinds == ["base_model", "dataset", "package", "weight_file"]
    assert len(shown["entries"]) == 4 + 4 + 1 + 1
    assert all(entry["pinned"] for entry in shown["entries"])
    assert sorted((gap["kind"], gap["gap_reason"]) for gap in shown["gaps"]) == [
        ("package", "no exact version"),
        ("weight_file", "no revision"),
    ]

    out = tmp_path / "bom.json"
    code, exported = run("inventory", "export", "example-detector", "-o", str(out))
    assert code == EXIT_OK
    assert exported["output"] == str(out)
    document = json.loads(out.read_text(encoding="utf-8"))
    validate(document)
    with Store(run.db) as store:
        assert store.get_version("example-detector", 1)["inventory"] == document

    code, imported = run("import", str(out), "--model-id", "example-copy")
    assert code == EXIT_OK
    assert (imported["model_id"], imported["version"]) == ("example-copy", 1)
    code, copy_shown = run("inventory", "show", "example-copy")
    assert copy_shown["entries"] == shown["entries"]
    assert copy_shown["gaps"] == shown["gaps"]


def test_a_second_register_with_model_id_creates_version_2(run) -> None:
    assert run("register", str(EXAMPLE))[0] == EXIT_OK
    code, second = run("register", str(EXAMPLE), "--model-id", "example-detector")
    assert code == EXIT_OK
    assert second["version"] == 2
    code, shown = run("inventory", "show", "example-detector")
    assert shown["version"] == 2
    code, first = run("inventory", "show", "example-detector", "--version", "1")
    assert first["version"] == 1
    assert first["entries"] == shown["entries"]


def test_registering_the_same_model_id_again_without_model_id_is_refused(run) -> None:
    assert run("register", str(EXAMPLE))[0] == EXIT_OK
    assert run("register", str(EXAMPLE))[0] == EXIT_INVALID_INPUT


def test_unknown_models_and_bad_inventories_are_invalid_input(run, tmp_path: Path) -> None:
    assert run("inventory", "show", "nobody")[0] == EXIT_INVALID_INPUT
    out = tmp_path / "x.json"
    assert run("inventory", "export", "nobody", "-o", str(out))[0] == EXIT_INVALID_INPUT
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    assert run("import", str(bad), "--model-id", "m")[0] == EXIT_INVALID_INPUT
    bad.write_text(json.dumps({"bomFormat": "SPDX"}), encoding="utf-8")
    assert run("import", str(bad), "--model-id", "m")[0] == EXIT_INVALID_INPUT


def test_show_prints_gaps_with_their_reasons_for_people(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    db = tmp_path / "md.db"
    handlers = make_handlers(fetcher=RecordedFetcher(FIXTURES / "hf"))
    assert main(["register", str(EXAMPLE), "--db", str(db)], handlers=handlers) == EXIT_OK
    capsys.readouterr()
    assert main(["inventory", "show", "example-detector", "--db", str(db)], handlers=handlers) == 0
    text = capsys.readouterr().out
    assert "pkg:pypi/attrs@26.1.0" in text
    assert "no revision" in text
    assert "gap" in text.lower()

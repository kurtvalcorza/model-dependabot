"""Contract tests for ``discover`` (T041; contracts/cli.md, data-model.md Discovery result)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from model_dependabot.cli import EXIT_INVALID_INPUT, EXIT_OK, main, make_handlers

NOW = datetime(2026, 11, 13, 9, 0, tzinfo=UTC)
RESULT_KEYS = {
    "project",
    "observed_at",
    "upstream",
    "statement",
    "candidates",
    "declared_not_seen",
    "skipped",
    "limits",
    "output",
}
STATEMENT = (
    "These are dependencies proposed from the evidence available in the project. Discovery cannot"
    " establish complete training provenance."
)


def run(argv: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, Any, str]:
    code = main(argv, handlers=make_handlers(now=lambda: NOW))
    captured = capsys.readouterr()
    payload = json.loads(captured.out) if "--json" in argv and captured.out.strip() else None
    return code, payload, captured.out + captured.err


def test_the_json_shape(detector_project: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, payload, _ = run(["discover", str(detector_project), "--json"], capsys)
    assert code == EXIT_OK
    assert set(payload) == RESULT_KEYS
    assert payload["statement"] == STATEMENT
    assert payload["limits"] == {
        "entries": 50_000,
        "depth": 24,
        "weight_files": 2_000,
        "text_bytes": 1_048_576,
        "card_bytes": 262_144,
    }
    kinds = {"package", "weight_file", "base_model", "dataset", "licence", "environment"}
    statuses = {"verified", "declared-but-unverified", "conflicting", "unavailable"}
    for item in payload["candidates"]:
        assert {"kind", "identity", "origin", "status", "observed_at", "gaps"} <= set(item)
        assert item["kind"] in kinds
        assert item["status"] in statuses
        assert isinstance(item["gaps"], list)
    for item in payload["skipped"]:
        assert {"path", "reason"} <= set(item)


def test_text_output_leads_with_the_statement(
    detector_project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, _, out = run(["discover", str(detector_project)], capsys)
    assert code == EXIT_OK
    lines = out.splitlines()
    assert lines[0].startswith(f"Discovery of {detector_project}")
    assert "(no network requests)" in lines[0]
    assert lines[1] == STATEMENT
    assert any("runs/best.safetensors" in line and "pickle" in line for line in lines)


def test_a_path_that_is_not_a_directory_exits_1(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    file = tmp_path / "file.txt"
    file.write_text("x", encoding="utf-8")
    for path in (file, tmp_path / "missing"):
        code, _, out = run(["discover", str(path)], capsys)
        assert code == EXIT_INVALID_INPUT
        assert "is not a directory" in out


@pytest.mark.parametrize("text", [None, "[model\n", '[model]\nid = "m"\nsurprise = 1\n'])
def test_an_unreadable_or_invalid_manifest_exits_1(
    detector_project: Path, tmp_path: Path, text: str | None, capsys: pytest.CaptureFixture[str]
) -> None:
    manifest = tmp_path / "model.toml"
    if text is not None:
        manifest.write_text(text, encoding="utf-8")
    code, _, _ = run(["discover", str(detector_project), "--manifest", str(manifest)], capsys)
    assert code == EXIT_INVALID_INPUT


def test_an_existing_output_exits_1_without_force(
    detector_project: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "proposed.toml"
    out.write_text("mine\n", encoding="utf-8")
    code, _, out_text = run(["discover", str(detector_project), "-o", str(out)], capsys)
    assert code == EXIT_INVALID_INPUT
    assert "--force" in out_text
    assert out.read_text(encoding="utf-8") == "mine\n"
    code, _, _ = run(["discover", str(detector_project), "--force"], capsys)
    assert code == EXIT_INVALID_INPUT


def test_db_is_accepted_and_ignored(
    detector_project: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    db = tmp_path / "x.db"
    code, _, _ = run(["discover", str(detector_project), "--db", str(db), "--json"], capsys)
    assert code == EXIT_OK
    assert not db.exists()


def test_an_output_link_exits_1_and_writes_nothing(
    detector_project: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """PR #15 round 3, T1: refused before discovery, with or without --force."""
    from conftest import make_directory_link

    link = tmp_path / "proposed.toml"
    (tmp_path / "planted").mkdir()
    make_directory_link(link, tmp_path / "planted")
    (tmp_path / "planted").rmdir()  # the link now dangles
    for extra in ([], ["--force"]):
        code, _, out_text = run(
            ["discover", str(detector_project), "-o", str(link), *extra], capsys
        )
        assert code == EXIT_INVALID_INPUT
        assert "is a link" in out_text
    assert not (tmp_path / "planted").exists()


def test_an_output_through_a_link_folder_exits_1_and_writes_nothing(
    detector_project: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Issue #16: a link in a folder above the -o file, with or without --force."""
    from conftest import make_directory_link

    planted = tmp_path / "planted"
    planted.mkdir()
    make_directory_link(detector_project / "out-link", planted)
    output = detector_project / "out-link" / "planted.toml"
    for extra in ([], ["--force"]):
        code, _, out_text = run(
            ["discover", str(detector_project), "-o", str(output), *extra], capsys
        )
        assert code == EXIT_INVALID_INPUT
        assert "passes through the link" in out_text
    assert list(planted.iterdir()) == []


def test_a_relative_output_through_a_link_folder_exits_1(
    detector_project: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Issue #16: relative PATH and -o, with the working directory inside the project."""
    from conftest import make_directory_link

    planted = tmp_path / "planted"
    planted.mkdir()
    make_directory_link(detector_project / "out-link", planted)
    monkeypatch.chdir(detector_project)
    code, _, out_text = run(["discover", ".", "-o", "out-link/p.toml", "--force"], capsys)
    assert code == EXIT_INVALID_INPUT
    assert "passes through the link" in out_text
    assert list(planted.iterdir()) == []


def test_an_output_outside_the_project_below_a_link_exits_0(
    detector_project: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Review P2: like ``-o /tmp/proposed.toml`` on macOS, where ``/tmp`` is a link."""
    from conftest import make_directory_link

    real = tmp_path / "private-tmp"
    real.mkdir()
    make_directory_link(tmp_path / "tmp-link", real)
    code, _, _ = run(
        ["discover", str(detector_project), "-o", str(tmp_path / "tmp-link" / "p.toml")], capsys
    )
    assert code == EXIT_OK
    assert (real / "p.toml").is_file()

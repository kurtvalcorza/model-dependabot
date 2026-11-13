"""Discovery of the detector project, offline (T040; quickstart section 5, SC-004, SC-005, SC-006).

The default run blocks every socket, so a network request fails the test. Every file of the
project and of its surroundings is hashed and timed before and after: discovery changes none of
them and creates no database.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from model_dependabot.cli import EXIT_INVALID_INPUT, EXIT_OK, main, make_handlers
from model_dependabot.store import Store

NOW = datetime(2026, 11, 13, 9, 0, tzinfo=UTC)


def snapshot(root: Path) -> dict[str, tuple[str, int]]:
    """Every regular file under ``root``, not through links: its SHA-256 and mtime."""
    found = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or path.is_junction() or not path.is_file():
            continue
        if any(part.is_symlink() or part.is_junction() for part in path.parents):
            continue
        found[path.relative_to(root).as_posix()] = (
            hashlib.sha256(path.read_bytes()).hexdigest(),
            path.stat().st_mtime_ns,
        )
    return found


@pytest.fixture
def invoke(capsys: pytest.CaptureFixture[str]):
    def run(*argv: str) -> tuple[int, Any]:
        code = main([*argv, "--json"], handlers=make_handlers(now=lambda: NOW))
        out = capsys.readouterr().out
        return code, json.loads(out) if out.strip() else None

    return run


def by(candidates: list[dict[str, Any]], kind: str) -> list[dict[str, Any]]:
    return [item for item in candidates if item["kind"] == kind]


def test_discovery_reports_what_quickstart_lists(
    detector_project: Path, invoke, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    work = detector_project.parent
    before = snapshot(work)
    db = tmp_path / "never.db"
    manifest = detector_project / "model.toml"
    argv = ("discover", str(detector_project), "--manifest", str(manifest), "--db", str(db))
    code, result = invoke(*argv)
    assert code == EXIT_OK
    assert snapshot(work) == before
    assert not db.exists()
    assert list(tmp_path.rglob("*.db")) == []

    assert result["upstream"] is False
    assert result["observed_at"] == "2026-11-13T09:00:00Z"
    assert "cannot establish complete training provenance" in result["statement"]
    candidates = result["candidates"]
    for item in candidates:  # SC-004
        assert item["origin"] and item["status"] and item["observed_at"] == result["observed_at"]

    packages = by(candidates, "package")
    locked = [p for p in packages if p["origin"]["file"] == "requirements.lock.txt"]
    assert {p["identity"]["name"] for p in locked} == {"numpy", "torch"}
    for item in locked:
        assert item["identity"]["hashes"]
        assert item["status"] in ("declared-but-unverified", "conflicting")
    torch = next(p for p in locked if p["identity"]["name"] == "torch")
    assert torch["status"] == "declared-but-unverified"
    pyproject = [p for p in packages if p["origin"]["file"] == "pyproject.toml"]
    assert {tuple(p["gaps"]) for p in pyproject} == {("not locked",), ("not a registry package",)}

    weights = {w["identity"]["path"]: w for w in by(candidates, "weight_file")}
    assert set(weights) == {"runs/best.safetensors", "weights/good.safetensors"}
    best = weights["runs/best.safetensors"]
    assert (best["status"], best["identity"]["format"]) == ("verified", "pickle")
    assert best["identity"]["can_run_code"] is True
    assert best["manifest"] == "matches"

    [base] = by(candidates, "base_model")
    assert base["identity"]["hub_repo"] == "openai-community/gpt2"
    assert base["gaps"] == ["no revision"]
    assert base["manifest"] == "conflicts"
    assert base["manifest_value"] == {"hub_repo": "example-org/other-base"}
    assert {d["identity"]["hub_repo"] for d in by(candidates, "dataset")} == {
        "yavon/muxue",
        "model-dependabot-fixture/does-not-exist",
    }
    names = json.dumps(candidates)
    for leaked in ("leaked", "secret.safetensors", "inside-venv", "buried", "huge", "prose"):
        assert leaked not in names

    skipped = {item["path"]: item["reason"] for item in result["skipped"]}
    assert skipped["link-out"] == "outside the project"
    assert skipped["../outside.txt"] == "outside the project"
    assert skipped["uv.lock"] == "lock format not read in this version"
    assert skipped[".venv"] == "environment directory not entered"
    assert skipped["big-requirements.txt"] == "larger than 1 MiB"
    assert any(reason == "deeper than 24 levels" for reason in skipped.values())
    assert result["limits"]["entries"] == 50_000
    assert result["output"] is None


def test_the_proposed_manifest_registers_only_what_is_measured_or_pinned(
    detector_project: Path, invoke, tmp_path: Path
) -> None:
    work = detector_project.parent
    before = snapshot(work)
    out = tmp_path / "out" / "proposed.toml"
    code, result = invoke("discover", str(detector_project), "-o", str(out))
    assert code == EXIT_OK
    assert result["output"] == {"path": str(out), "written": True}
    assert snapshot(work) == before

    db = tmp_path / "db" / "md.db"
    code, _ = invoke("register", str(out), "--model-id", "proposed-check", "--db", str(db))
    assert code == EXIT_OK
    with Store(db) as store:
        entries = store.entries("proposed-check", 1)
    # The lock pins numpy 2.1.0 while requirements-dev.txt pins 2.0.2, so the lock stays a
    # comment and registering the draft adopts no package (PR #15 round 3, T4).
    assert sorted({entry["kind"] for entry in entries}) == ["weight_file"]
    assert {e["location"] for e in entries if e["kind"] == "weight_file"} == {
        "../work/detector/runs/best.safetensors",
        "../work/detector/weights/good.safetensors",
    }

    code, _ = invoke("discover", str(detector_project), "-o", str(out))
    assert code == EXIT_INVALID_INPUT
    code, _ = invoke("discover", str(detector_project), "-o", str(out), "--force")
    assert code == EXIT_OK

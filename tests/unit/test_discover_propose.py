"""The proposed manifest written by ``discover -o`` (T039; FR-022, FR-023, research A10)."""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

import pytest

from model_dependabot.discover.candidate import candidate
from model_dependabot.discover.propose import (
    SEVERAL_LOCKS,
    OutputExistsError,
    render,
    toml_string,
    write,
)
from model_dependabot.manifest import ManifestError, load_manifest

NOW = "2026-11-13T00:00:00Z"
DECLARED = "declared-but-unverified"


def weight(path: str, status: str = "verified") -> dict[str, Any]:
    identity = {
        "path": path,
        "sha256": "a" * 64,
        "size": 3,
        "format": "pickle",
        "can_run_code": True,
    }
    return candidate("weight_file", identity, {"file": path}, status, NOW)


def lock(path: str) -> dict[str, Any]:
    return candidate("environment", {"lock": path, "packages": 2}, {"file": path}, DECLARED, NOW)


def result(*candidates: dict[str, Any], skipped: list | None = None) -> dict[str, Any]:
    return {"observed_at": NOW, "candidates": list(candidates), "skipped": skipped or []}


@pytest.fixture
def project(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    (root / "runs").mkdir(parents=True)
    (root / "runs" / "best.safetensors").write_bytes(b"\x80\x04K\x01.")
    (root / "same.pt").write_bytes(b"\x80\x04K\x01.")
    (root / "requirements.lock.txt").write_text(
        "torch==2.5.1 --hash=sha256:" + "1" * 64 + "\n", encoding="utf-8"
    )
    (root / "b.lock.txt").write_text("x==1 --hash=sha256:" + "2" * 64 + "\n", encoding="utf-8")
    return root


def written(project: Path, out: Path, found: dict[str, Any], model_id: str = "detector") -> str:
    text = render(found, model_id, project, out)
    write(text, out, force=False)
    return out.read_text(encoding="utf-8")


def test_only_measured_or_pinned_entries_are_active(project: Path, tmp_path: Path) -> None:
    base = candidate(
        "base_model",
        {"hub_repo": "org/base", "revision": None},
        {"file": "README.md", "key": "base_model"},
        DECLARED,
        NOW,
        ["no revision"],
    )
    data = candidate(
        "dataset", {"hub_repo": "org/data"}, {"file": "README.md", "key": "datasets"}, DECLARED, NOW
    )
    loose = candidate(
        "package",
        {"name": "numpy", "version": None, "hashes": [], "requirement": "numpy>=1.26"},
        {"file": "pyproject.toml", "key": "[project].dependencies"},
        DECLARED,
        NOW,
        ["not locked"],
    )
    found = result(
        weight("runs/best.safetensors"),
        lock("requirements.lock.txt"),
        base,
        data,
        loose,
        skipped=[{"path": "uv.lock", "reason": "lock format not read in this version"}],
    )
    out = tmp_path / "elsewhere" / "proposed.toml"
    text = written(project, out, found)
    data_loaded = tomllib.loads(text)
    assert set(data_loaded) == {"model", "weights", "environment"}
    assert data_loaded["model"] == {"id": "detector"}
    manifest = load_manifest(out)
    assert [spec.path for spec in manifest.weights] == [
        (project / "runs/best.safetensors").resolve()
    ]
    assert manifest.lock == (project / "requirements.lock.txt").resolve()
    assert manifest.base_model is None
    assert manifest.datasets == ()
    lines = text.splitlines()
    assert lines[0].startswith("# Proposed by model-dependabot discover on 2026-11-13T00:00:00Z")
    assert "# Discovery cannot establish complete training provenance." in lines[2]
    assert (
        "# base_model: declared-but-unverified, from README.md (base_model); gaps: no revision"
        in lines
    )
    assert '# hub = "hf:org/base"' in lines
    assert '# hub = "hf:datasets/org/data"' in lines
    assert any("numpy>=1.26" in line and line.startswith("#") for line in lines)
    assert "# skipped: uv.lock (lock format not read in this version)" in lines


def test_several_locks_are_all_comments(project: Path, tmp_path: Path) -> None:
    out = tmp_path / "proposed.toml"
    text = written(project, out, result(lock("requirements.lock.txt"), lock("b.lock.txt")))
    assert "environment" not in tomllib.loads(text)
    assert f"# {SEVERAL_LOCKS}" in text.splitlines()


def test_conflicting_weights_are_comments(project: Path, tmp_path: Path) -> None:
    out = tmp_path / "proposed.toml"
    found = result(weight("runs/best.safetensors", "conflicting"), weight("same.pt", "conflicting"))
    assert "weights" not in tomllib.loads(written(project, out, found))


def test_an_existing_output_is_refused_without_force(project: Path, tmp_path: Path) -> None:
    out = tmp_path / "proposed.toml"
    out.write_text("keep me\n", encoding="utf-8")
    text = render(result(), "detector", project, out)
    with pytest.raises(OutputExistsError):
        write(text, out, force=False)
    assert out.read_text(encoding="utf-8") == "keep me\n"
    write(text, out, force=True)
    assert tomllib.loads(out.read_text(encoding="utf-8"))["model"]["id"] == "detector"
    assert sorted(path.name for path in tmp_path.iterdir() if path.is_file()) == ["proposed.toml"]


def test_a_text_that_does_not_load_is_never_renamed(tmp_path: Path) -> None:
    out = tmp_path / "proposed.toml"
    with pytest.raises(ManifestError):
        write("[model]\n", out, force=False)
    assert list(tmp_path.iterdir()) == []


def test_awkward_names_are_escaped(project: Path, tmp_path: Path) -> None:
    model_id = 'odd "name"\\with\nbreaks'
    out = tmp_path / "proposed.toml"
    text = written(project, out, result(), model_id=model_id)
    assert tomllib.loads(text)["model"]["id"] == model_id
    assert tomllib.loads(f"x = {toml_string(chr(1) + 'é')}")["x"] == "\x01é"


def test_the_lock_packages_are_not_commented_again(project: Path, tmp_path: Path) -> None:
    def package(name: str, file: str, gaps: list[str]) -> dict[str, Any]:
        identity = {"name": name, "version": "1.0", "hashes": [], "requirement": f"{name}==1.0"}
        return candidate("package", identity, {"file": file, "line": 1}, DECLARED, NOW, gaps)

    found = result(
        lock("requirements.lock.txt"),
        package("torch", "requirements.lock.txt", []),
        package("pytest", "requirements-dev.txt", ["not locked"]),
    )
    out = tmp_path / "proposed.toml"
    comments = [line for line in written(project, out, found).splitlines() if line.startswith("#")]
    assert not any("torch" in line for line in comments)
    assert (
        "# package: declared-but-unverified, from requirements-dev.txt line 1: pytest==1.0;"
        " gaps: not locked" in comments
    )

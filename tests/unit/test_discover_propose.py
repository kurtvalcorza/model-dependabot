"""The proposed manifest written by ``discover -o`` (T039; FR-022, FR-023, research A10)."""

from __future__ import annotations

import os
import tomllib
from pathlib import Path
from typing import Any

import pytest

from conftest import make_directory_link
from model_dependabot.discover.candidate import candidate
from model_dependabot.discover.project import discover, write_proposal
from model_dependabot.discover.propose import (
    LOCK_CONFLICTS,
    SEVERAL_LOCKS,
    OutputExistsError,
    OutputLinkError,
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


def _other_spelling(folder: Path) -> Path:
    """``folder`` spelled differently from its resolved path: its 8.3 short name on Windows,
    else through a link to it."""
    if os.name == "nt":
        import ctypes

        buffer = ctypes.create_unicode_buffer(32768)
        size = ctypes.windll.kernel32.GetShortPathNameW(str(folder), buffer, len(buffer))
        if size and Path(buffer.value) != folder.resolve():
            return Path(buffer.value)
        pytest.skip("the volume gives this folder no short name")
    link = folder.parent / f"{folder.name}-link"
    make_directory_link(link, folder)
    return link


def test_paths_are_relative_to_where_the_output_really_is(tmp_path: Path) -> None:
    """Review F9: an output spelled differently from the project folder (a short name or a link)
    gets paths relative to the folder it resolves to, never a climb out through the other one."""
    real = tmp_path / "real"
    project = real / "proj"
    project.mkdir(parents=True)
    (project / "requirements.lock.txt").write_text(
        "torch==2.5.1 --hash=sha256:" + "1" * 64 + "\n", encoding="utf-8"
    )
    output = _other_spelling(real) / "proposed.toml"
    write_proposal(discover(project), output, model_id="m", force=False)
    proposal = tomllib.loads(output.read_text(encoding="utf-8"))
    assert proposal["environment"]["lock"] == "proj/requirements.lock.txt"
    assert (
        load_manifest(output, weights_present=False).lock
        == (project / "requirements.lock.txt").resolve()
    )


def _project(tmp_path: Path) -> Path:
    project = tmp_path / "proj"
    project.mkdir()
    (project / "requirements.lock.txt").write_text(
        "torch==2.5.1 --hash=sha256:" + "1" * 64 + "\n", encoding="utf-8"
    )
    return project


def _file_link(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("this platform does not let the test create a symbolic link to a file")


@pytest.mark.parametrize("force", [False, True])
def test_an_output_link_to_an_existing_file_is_refused(tmp_path: Path, force: bool) -> None:
    """PR #15 round 3, T1 (owner ruling): a link is never followed, with or without --force."""
    project = _project(tmp_path)
    (tmp_path / "elsewhere").mkdir()
    target = tmp_path / "elsewhere" / "out.toml"
    target.write_text("old\n", encoding="utf-8")
    link = tmp_path / "out.toml"
    _file_link(link, target)
    with pytest.raises(OutputLinkError):
        write_proposal(discover(project), link, model_id="m", force=force)
    assert target.read_text(encoding="utf-8") == "old\n"
    assert link.is_symlink()


def test_a_dangling_output_link_is_refused_and_nothing_is_created(tmp_path: Path) -> None:
    project = _project(tmp_path)
    target = tmp_path / "outside" / "deep" / "planted.toml"
    link = project / "proposed.toml"
    _file_link(link, target)
    with pytest.raises(OutputLinkError):
        write_proposal(discover(project), link, model_id="m", force=False)
    assert not (tmp_path / "outside").exists()


def test_an_output_junction_is_refused(tmp_path: Path) -> None:
    """A link the platform makes without privilege: a junction on Windows, else a symlink."""
    project = _project(tmp_path)
    link = project / "proposed.toml"
    (tmp_path / "outside").mkdir()
    make_directory_link(link, tmp_path / "outside")
    (tmp_path / "outside").rmdir()  # the link now dangles
    with pytest.raises(OutputLinkError):
        write_proposal(discover(project), link, model_id="m", force=True)
    with pytest.raises(OutputLinkError):
        write('[model]\nid = "m"\n', link, force=True)
    assert not (tmp_path / "outside").exists()


@pytest.mark.parametrize("force", [False, True])
def test_an_output_through_a_link_folder_is_refused(tmp_path: Path, force: bool) -> None:
    """Issue #16: a link in a folder above the output file is refused too, not followed.

    A symbolic link where the platform allows one, else a junction (Windows without privilege).
    """
    project = _project(tmp_path)
    (tmp_path / "outside").mkdir()
    make_directory_link(project / "out", tmp_path / "outside")
    output = project / "out" / "planted.toml"
    with pytest.raises(OutputLinkError, match="passes through the link"):
        write_proposal(discover(project), output, model_id="m", force=force)
    with pytest.raises(OutputLinkError, match="passes through the link"):
        write('[model]\nid = "m"\n', output, force=force)
    assert list((tmp_path / "outside").iterdir()) == []


def test_an_output_below_a_link_folder_not_yet_created_is_refused(tmp_path: Path) -> None:
    """Issue #16: folders still to be made under a link do not hide it, nor does ``..``."""
    project = _project(tmp_path)
    (tmp_path / "outside").mkdir()
    make_directory_link(project / "out", tmp_path / "outside")
    for output in (
        project / "out" / "new" / "deeper" / "planted.toml",
        project / "out" / ".." / "planted.toml",
    ):
        with pytest.raises(OutputLinkError, match="passes through the link"):
            write_proposal(discover(project), output, model_id="m", force=True)
    assert list((tmp_path / "outside").iterdir()) == []
    assert not (project / "planted.toml").exists()


def test_an_output_through_a_dangling_link_folder_is_refused(tmp_path: Path) -> None:
    project = _project(tmp_path)
    (tmp_path / "outside").mkdir()
    make_directory_link(project / "out", tmp_path / "outside")
    (tmp_path / "outside").rmdir()  # the link now dangles
    with pytest.raises(OutputLinkError, match="passes through the link"):
        write_proposal(discover(project), project / "out" / "p.toml", model_id="m", force=True)
    assert not (tmp_path / "outside").exists()


def test_an_output_in_a_new_plain_folder_is_written(tmp_path: Path) -> None:
    """No link anywhere: folders that do not exist yet are made and the file is written."""
    project = _project(tmp_path)
    output = project / "drafts" / "new" / "proposed.toml"
    write_proposal(discover(project), output, model_id="m", force=False)
    assert load_manifest(output, weights_present=False)


def test_a_lock_that_pins_a_conflicting_package_is_only_a_comment(
    project: Path, tmp_path: Path
) -> None:
    """PR #15 round 3, T4: registering the draft must not adopt a conflicting pin (FR-022)."""
    identity = {"name": "numpy", "version": "2.1.0", "hashes": [], "requirement": "numpy==2.1.0"}
    origin = {"file": "requirements.lock.txt", "line": 2}
    pinned = candidate("package", identity, origin, "conflicting", NOW)
    found = result(lock("requirements.lock.txt"), pinned)
    out = tmp_path / "proposed.toml"
    text = written(project, out, found)
    assert "environment" not in tomllib.loads(text)
    comments = [line for line in text.splitlines() if line.startswith("#")]
    assert f"# {LOCK_CONFLICTS}" in comments
    assert any("environment:" in line and "requirements.lock.txt" in line for line in comments)
    assert any("numpy==2.1.0" in line for line in comments)

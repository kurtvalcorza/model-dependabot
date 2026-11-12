"""Python dependency declarations found by discovery (T035; FR-016, research A7)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from model_dependabot.discover.python_deps import LOCK_NOT_READ, discover_python, is_requirements
from model_dependabot.discover.walk import LIMITS, Limits, walk

NOW = "2026-11-13T00:00:00Z"
H1, H2 = "sha256:" + "1" * 64, "sha256:" + "2" * 64


def run(root: Path, limits: Limits = LIMITS) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    return discover_python(walk(root, limits), NOW, limits)


def write(root: Path, name: str, text: str) -> None:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


@pytest.mark.parametrize(
    ("name", "matches"),
    [
        ("requirements.txt", True),
        ("requirements-dev.txt", True),
        ("dev-requirements.txt", True),
        ("constraints.txt", True),
        ("env.lock.txt", True),
        ("Requirements.TXT", True),
        ("requirements.in", False),
        ("notes.txt", False),
    ],
)
def test_which_files_are_requirements_files(name: str, matches: bool) -> None:
    assert is_requirements(name) is matches


def test_a_hash_locked_file_gives_declared_packages_and_an_environment(tmp_path: Path) -> None:
    write(
        tmp_path,
        "requirements.lock.txt",
        f"numpy==2.1.0 \\\n    --hash={H1}\n# a comment\ntorch==2.5.1 --hash={H2}\n",
    )
    candidates, skipped = run(tmp_path)
    assert skipped == []
    environment, numpy, torch = candidates
    assert environment["kind"] == "environment"
    assert environment["identity"] == {"lock": "requirements.lock.txt", "packages": 2}
    assert numpy["identity"] == {"name": "numpy", "version": "2.1.0", "hashes": [H1]}
    assert numpy["origin"] == {"file": "requirements.lock.txt", "line": 1}
    assert torch["origin"]["line"] == 4
    for item in candidates:
        assert item["status"] == "declared-but-unverified"
        assert item["gaps"] == []
        assert item["observed_at"] == NOW


def test_an_unlocked_file_gives_gaps(tmp_path: Path) -> None:
    write(
        tmp_path, "requirements.txt", f"numpy==2.1.0\nscipy>=1.11\nrequests==2.32.0 --hash={H1}\n"
    )
    candidates, _ = run(tmp_path)
    assert [item["kind"] for item in candidates] == ["package"] * 3
    gaps = {item["identity"]["name"]: item["gaps"] for item in candidates}
    assert gaps == {
        "numpy": ["not locked"],
        "scipy": ["no exact version"],
        "requests": ["not locked"],
    }
    assert candidates[1]["identity"]["requirement"] == "scipy>=1.11"


def test_url_and_vcs_requirements_are_text_with_a_gap(tmp_path: Path) -> None:
    write(
        tmp_path,
        "requirements.txt",
        "tool @ https://example.org/tool-1.0.tar.gz\n"
        "git+https://example.org/repo.git#egg=repo\n"
        "-e ./local-package\n",
    )
    candidates, _ = run(tmp_path)
    assert [item["gaps"] for item in candidates] == [["not a registry package"]] * 3
    assert candidates[0]["identity"]["name"] == "tool"
    assert candidates[2]["identity"]["requirement"] == "./local-package"


def test_pyproject_dependencies_are_never_locked(tmp_path: Path) -> None:
    write(
        tmp_path,
        "pyproject.toml",
        '[project]\nname = "x"\ndependencies = ["numpy>=1.26", "torch==2.5.1"]\n'
        '[project.optional-dependencies]\ndev = ["pytest"]\n',
    )
    candidates, skipped = run(tmp_path)
    assert skipped == []
    assert [(item["identity"]["name"], item["gaps"]) for item in candidates] == [
        ("numpy", ["not locked"]),
        ("torch", ["not locked"]),
        ("pytest", ["not locked"]),
    ]
    assert candidates[0]["origin"] == {"file": "pyproject.toml", "key": "[project].dependencies"}
    assert candidates[2]["origin"]["key"] == "[project.optional-dependencies].dev"
    assert candidates[1]["identity"]["version"] == "2.5.1"


def test_invalid_pyproject_is_skipped(tmp_path: Path) -> None:
    write(tmp_path, "pyproject.toml", "[project\n")
    candidates, skipped = run(tmp_path)
    assert candidates == []
    assert skipped[0]["path"] == "pyproject.toml"
    assert skipped[0]["reason"].startswith("not valid TOML")


@pytest.mark.parametrize("name", ["uv.lock", "poetry.lock", "Pipfile.lock", "pylock.toml"])
def test_lock_formats_not_read_are_listed(tmp_path: Path, name: str) -> None:
    write(tmp_path, name, "anything\n")
    assert run(tmp_path) == ([], [{"path": name, "reason": LOCK_NOT_READ}])


def test_includes_are_followed_only_inside_the_project(tmp_path: Path) -> None:
    root = tmp_path / "project"
    write(tmp_path, "outside.txt", f"leaked==1.0 --hash={H1}\n")
    write(root, "base.in", "inner==1.0\n")
    write(root, "sub/requirements.txt", "-r ../base.in\n-r ../../outside.txt\n-c /etc/c.txt\n")
    candidates, skipped = run(root)
    assert [item["identity"]["name"] for item in candidates] == ["inner"]
    assert candidates[0]["origin"] == {"file": "base.in", "line": 1}
    outside = {item["path"]: item for item in skipped}
    assert outside["../../outside.txt"]["reason"] == "outside the project"
    assert outside["../../outside.txt"]["named_in"] == {"file": "sub/requirements.txt", "line": 2}
    assert outside["/etc/c.txt"]["reason"] == "outside the project"


def test_an_include_loop_is_read_once(tmp_path: Path) -> None:
    write(tmp_path, "a-requirements.txt", "-r b-requirements.txt\none==1.0\n")
    write(tmp_path, "b-requirements.txt", "-r a-requirements.txt\ntwo==1.0\n")
    candidates, _ = run(tmp_path)
    assert sorted(item["identity"]["name"] for item in candidates) == ["one", "two"]


def test_an_oversized_requirements_file_is_skipped(tmp_path: Path) -> None:
    write(tmp_path, "requirements.txt", "x==1.0\n" * 200)
    candidates, skipped = run(tmp_path, Limits(text_bytes=1024))
    assert candidates == []
    assert skipped == [{"path": "requirements.txt", "reason": "larger than 1 KiB"}]

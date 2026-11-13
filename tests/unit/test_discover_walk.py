"""The discovery walk's limits and its boundary (T034; FR-020, SC-006, research A8, A9)."""

from __future__ import annotations

from pathlib import Path

import pytest

from conftest import make_directory_link
from model_dependabot.discover.walk import (
    ENTRY_LIMIT,
    LIMITS,
    NOT_ENTERED,
    OUTSIDE,
    Limits,
    Walk,
    inside,
    read_text,
    walk,
)


def reasons(found: Walk) -> dict[str, str]:
    return {item["path"]: item["reason"] for item in found.skipped}


def test_the_published_limits() -> None:
    assert LIMITS.as_dict() == {
        "entries": 50_000,
        "depth": 24,
        "weight_files": 2_000,
        "text_bytes": 1 << 20,
        "card_bytes": 256 << 10,
    }


def test_directories_not_entered_are_each_listed_once(tmp_path: Path) -> None:
    for name in NOT_ENTERED:
        (tmp_path / name).mkdir()
        (tmp_path / name / "inside.txt").write_text("x", encoding="utf-8")
    (tmp_path / "src" / ".git").mkdir(parents=True)
    found = walk(tmp_path)
    assert found.files == []
    listed = [item["path"] for item in found.skipped]
    assert sorted(listed) == sorted([*NOT_ENTERED, "src/.git"])
    assert len(listed) == len(set(listed))
    assert reasons(found)[".venv"] == "environment directory not entered"
    assert set(NOT_ENTERED) == {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        ".tox",
        ".mypy_cache",
        ".ruff_cache",
        "site-packages",
    }


def test_depth_limit(tmp_path: Path) -> None:
    deep = tmp_path
    for level in range(5):
        deep = deep / f"d{level}"
    deep.mkdir(parents=True)
    (deep / "bottom.txt").write_text("x", encoding="utf-8")
    (tmp_path / "d0" / "shallow.txt").write_text("x", encoding="utf-8")
    found = walk(tmp_path, Limits(depth=3))
    assert found.files == ["d0/shallow.txt"]
    assert reasons(found) == {"d0/d1/d2/d3": "deeper than 3 levels"}


def test_entry_limit_stops_the_walk(tmp_path: Path) -> None:
    for index in range(10):
        (tmp_path / f"f{index}.txt").write_text("x", encoding="utf-8")
    found = walk(tmp_path, Limits(entries=5))
    assert found.files == []
    assert reasons(found) == {".": ENTRY_LIMIT}


def test_text_limit(tmp_path: Path) -> None:
    (tmp_path / "small.txt").write_text("ok", encoding="utf-8")
    (tmp_path / "large.txt").write_text("x" * 2048, encoding="utf-8")
    found = walk(tmp_path)
    assert read_text(found, "small.txt", 1024) == "ok"
    assert read_text(found, "large.txt", 1024) == {
        "path": "large.txt",
        "reason": "larger than 1 KiB",
    }


def test_a_directory_link_out_of_the_root_is_never_entered(tmp_path: Path) -> None:
    root = tmp_path / "project"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (outside / "secret.txt").write_text("secret", encoding="utf-8")
    make_directory_link(root / "link-out", outside)
    found = walk(root)
    assert found.files == []
    assert reasons(found) == {"link-out": OUTSIDE}


def test_a_directory_link_inside_the_root_is_not_followed(tmp_path: Path) -> None:
    (tmp_path / "real").mkdir()
    (tmp_path / "real" / "a.txt").write_text("x", encoding="utf-8")
    make_directory_link(tmp_path / "again", tmp_path / "real")
    found = walk(tmp_path)
    assert found.files == ["real/a.txt"]
    assert "not followed" in reasons(found)["again"]


def test_a_file_link_out_of_the_root_is_never_read(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    (tmp_path / "secret.txt").write_text("secret", encoding="utf-8")
    try:
        (root / "requirements.txt").symlink_to(tmp_path / "secret.txt")
    except OSError:
        pytest.skip("this platform does not let the test create a symbolic link to a file")
    found = walk(root)
    assert found.files == []
    assert reasons(found) == {"requirements.txt": OUTSIDE}


@pytest.mark.parametrize(
    ("base", "text", "expected"),
    [
        ("requirements.txt", "base.txt", "base.txt"),
        ("sub/requirements.txt", "../base.txt", "base.txt"),
        ("requirements.txt", "../outside.txt", None),
        ("sub/requirements.txt", "../../outside.txt", None),
        ("requirements.txt", "/etc/passwd", None),
        ("requirements.txt", "C:/Windows/win.ini", None),
        ("requirements.txt", "", None),
    ],
)
def test_paths_named_in_files_stay_inside(
    tmp_path: Path, base: str, text: str, expected: str | None
) -> None:
    assert inside(tmp_path, base, text) == expected

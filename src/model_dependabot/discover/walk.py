"""The project walk: which files discovery may read, within the published limits (research A8, A9).

The root is resolved once. Directories are walked with ``os.walk(followlinks=False)``, but a
directory that is a symbolic link or a junction is never entered (on Windows ``os.walk`` enters a
junction even with ``followlinks=False``), and a file that is a link is kept only when its
resolved target is inside the root. A path named inside a file (a ``-r`` include) goes through
``inside``: an absolute path, or one that resolves outside the root, is never opened. Everything
left out is listed under ``skipped`` with its reason (FR-020).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

OUTSIDE = "outside the project"
ENTRY_LIMIT = "entry limit reached"
LINK_NOT_FOLLOWED = "symbolic link to a directory inside the project, not followed"
UNREADABLE = "cannot be read"


@dataclass(frozen=True)
class Limits:
    """The published discovery limits (contracts/cli.md, Discovery limits)."""

    entries: int = 50_000
    depth: int = 24
    weight_files: int = 2_000
    text_bytes: int = 1 << 20
    card_bytes: int = 256 << 10

    def as_dict(self) -> dict[str, int]:
        return {
            "entries": self.entries,
            "depth": self.depth,
            "weight_files": self.weight_files,
            "text_bytes": self.text_bytes,
            "card_bytes": self.card_bytes,
        }


LIMITS = Limits()

_VCS = ("version control directory not entered", (".git", ".hg", ".svn"))
_ENVIRONMENTS = (
    "environment directory not entered",
    (".venv", "venv", "node_modules", "site-packages"),
)
_CACHES = (
    "cache directory not entered",
    ("__pycache__", ".tox", ".mypy_cache", ".ruff_cache"),
)
NOT_ENTERED = {name: reason for reason, names in (_VCS, _ENVIRONMENTS, _CACHES) for name in names}


def deeper_than(limit: int) -> str:
    return f"deeper than {limit} levels"


def larger_than(limit: int) -> str:
    if limit % (1 << 20) == 0:
        return f"larger than {limit >> 20} MiB"
    if limit % (1 << 10) == 0:
        return f"larger than {limit >> 10} KiB"
    return f"larger than {limit} bytes"


def skip(path: str, reason: str, **fields: Any) -> dict[str, Any]:
    return {"path": path, "reason": reason, **fields}


@dataclass
class Walk:
    """The files the walk kept, as project-relative POSIX paths, and what it left out."""

    root: Path
    files: list[str] = field(default_factory=list)
    skipped: list[dict[str, Any]] = field(default_factory=list)

    def path(self, relative: str) -> Path:
        """The real path of a kept file: resolved, and checked to be inside the root again."""
        resolved = (self.root / relative).resolve()
        if not resolved.is_relative_to(self.root):
            raise PermissionError(f"{relative} is {OUTSIDE}")
        return resolved


def _is_link(path: Path) -> bool:
    return os.path.islink(path) or os.path.isjunction(path)


def _relative(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix() or "."


def walk(root: Path, limits: Limits = LIMITS) -> Walk:
    """Every regular file under ``root`` discovery may read, in a stable (sorted) order."""
    root = root.resolve()
    found = Walk(root)
    visited = 0
    for directory, dirnames, filenames in os.walk(root, followlinks=False):
        here = Path(directory)
        rel_dir = _relative(root, here)
        depth = 0 if rel_dir == "." else len(PurePosixPath(rel_dir).parts)
        dirnames.sort()
        filenames.sort()
        visited += len(dirnames) + len(filenames)
        if visited > limits.entries:
            found.skipped.append(skip(rel_dir, ENTRY_LIMIT))
            dirnames[:] = []
            break
        kept: list[str] = []
        for name in dirnames:
            child = here / name
            rel = _relative(root, child)
            if _is_link(child):
                inside_root = child.resolve().is_relative_to(root)
                found.skipped.append(skip(rel, LINK_NOT_FOLLOWED if inside_root else OUTSIDE))
            elif name in NOT_ENTERED:
                found.skipped.append(skip(rel, NOT_ENTERED[name]))
            elif depth + 1 > limits.depth:
                found.skipped.append(skip(rel, deeper_than(limits.depth)))
            else:
                kept.append(name)
        dirnames[:] = kept
        for name in filenames:
            child = here / name
            rel = _relative(root, child)
            if _is_link(child):
                try:
                    target = child.resolve(strict=True)
                except OSError:
                    found.skipped.append(skip(rel, UNREADABLE))
                    continue
                if not target.is_relative_to(root):
                    found.skipped.append(skip(rel, OUTSIDE))
                    continue
                if not target.is_file():
                    found.skipped.append(skip(rel, UNREADABLE))
                    continue
            elif not child.is_file():
                continue  # a socket, device or other special file is never read
            found.files.append(rel)
    return found


def inside(root: Path, base: str, text: str) -> str | None:
    """The project-relative path a file names (``text``, relative to the file at ``base``), or
    ``None`` when it is absolute or resolves outside the root (research A9)."""
    if not text or os.path.isabs(text) or PurePosixPath(text).is_absolute() or ":" in text:
        return None
    root = root.resolve()
    resolved = (root / PurePosixPath(base).parent / text).resolve()
    if not resolved.is_relative_to(root):
        return None
    return _relative(root, resolved)


def read_bytes(found: Walk, relative: str, limit: int) -> bytes | dict[str, Any]:
    """Up to ``limit`` bytes of a kept file, or a ``skipped`` item saying why it was not read."""
    try:
        path = found.path(relative)
        with path.open("rb") as handle:
            data = handle.read(limit + 1)
    except PermissionError:
        return skip(relative, OUTSIDE)
    except OSError as error:
        return skip(relative, f"{UNREADABLE}: {error.strerror or error}")
    if len(data) > limit:
        return skip(relative, larger_than(limit))
    return data


def read_text(found: Walk, relative: str, limit: int) -> str | dict[str, Any]:
    """A kept text file's content as UTF-8, or a ``skipped`` item saying why it was not read."""
    data = read_bytes(found, relative, limit)
    if isinstance(data, dict):
        return data
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return skip(relative, "not UTF-8 text")

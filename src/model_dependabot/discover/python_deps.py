"""Python dependency declarations in a project (research A7; FR-016).

A requirements file (``*requirements*.txt``, ``*constraints*.txt``, ``*.lock.txt``) in which every
requirement is pinned with ``==`` and at least one ``--hash`` is the format registration accepts:
its packages are ``declared-but-unverified`` candidates with their versions and hashes, and the
file is an ``environment`` candidate a proposed manifest can name as its lock. In any other file
each requirement is a candidate with the gap ``not locked`` (or ``no exact version``).
``pyproject.toml`` dependencies and optional dependencies are read with ``tomllib`` and are never
locked. URL and VCS requirements are kept as text with the gap ``not a registry package`` and are
never fetched. ``-r`` and ``-c`` includes are followed only to files inside the project. Lock
formats this version does not read are listed under ``skipped`` so that coverage shows them.
"""

from __future__ import annotations

import re
import tomllib
from collections.abc import Callable, Iterable
from fnmatch import fnmatch
from pathlib import PurePosixPath
from typing import Any

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

from model_dependabot.discover.candidate import (
    DECLARED,
    NO_EXACT_VERSION,
    NOT_A_REGISTRY_PACKAGE,
    NOT_LOCKED,
    candidate,
)
from model_dependabot.discover.walk import OUTSIDE, Limits, Walk, inside, read_text, skip
from model_dependabot.lockfile import numbered_lines, parse_line

REQUIREMENT_PATTERNS = ("*requirements*.txt", "*constraints*.txt", "*.lock.txt")
UNREAD_LOCKS = ("uv.lock", "poetry.lock", "Pipfile.lock", "pylock.toml")
LOCK_NOT_READ = "lock format not read in this version"

_INCLUDE = re.compile(r"^(-r|--requirement|-c|--constraint)(?:[=\s]+)(\S+)")
_OPTION = re.compile(r"^-")
_URL = re.compile(r"^(?:[a-z]+\+)?[a-z][a-z0-9+.-]*://|^(?:git|hg|svn|bzr)\+", re.IGNORECASE)
_EDITABLE = re.compile(r"^(?:-e|--editable)(?:[=\s]+)(\S+)")


def _without_hashes(line: str) -> str:
    return re.sub(r"--hash[=\s]+\S+", "", line).strip()


def is_requirements(path: str) -> bool:
    name = PurePosixPath(path).name.lower()
    return any(fnmatch(name, pattern) for pattern in REQUIREMENT_PATTERNS)


def is_unread_lock(path: str) -> bool:
    name = PurePosixPath(path).name
    return name in UNREAD_LOCKS or fnmatch(name, "pylock.*.toml")


def _not_registry(text: str) -> bool:
    """A requirement that names a URL, a VCS checkout or a local path rather than a package."""
    if _URL.search(text) or text.startswith((".", "/", "\\")):
        return True
    try:
        return Requirement(text).url is not None
    except InvalidRequirement:
        return False


def _name_of(text: str) -> str | None:
    try:
        return canonicalize_name(Requirement(text).name)
    except InvalidRequirement:
        return None


def _gap_candidate(
    text: str, origin: dict[str, Any], observed_at: str, gap: str, name: str | None, version: Any
) -> dict[str, Any]:
    identity = {"name": name, "version": version, "hashes": [], "requirement": text}
    return candidate("package", identity, origin, DECLARED, observed_at, [gap])


def _requirements(
    found: Walk,
    relative: str,
    observed_at: str,
    limits: Limits,
    queue: Callable[[str], None],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    text = read_text(found, relative, limits.text_bytes)
    if isinstance(text, dict):
        return [], [text]
    skipped: list[dict[str, Any]] = []
    declared: list[tuple[int, str]] = []
    for number, line in numbered_lines(text):
        include = _INCLUDE.match(line)
        if include:
            target = inside(found.root, relative, include.group(2))
            if target is None:
                where = {"named_in": {"file": relative, "line": number}}
                skipped.append(skip(include.group(2), OUTSIDE, **where))
            else:
                queue(target)
            continue
        editable = _EDITABLE.match(line)
        if editable or not _OPTION.match(line):
            declared.append((number, line))
    entries = [(number, line, parse_line(line)) for number, line in declared]
    locked = bool(entries) and all(
        entry is not None and entry.pinned and not _not_registry(_without_hashes(line))
        for _, line, entry in entries
    )
    candidates: list[dict[str, Any]] = []
    for number, line, entry in entries:
        origin = {"file": relative, "line": number}
        requirement = _without_hashes(line)
        editable = _EDITABLE.match(line)
        if editable or _not_registry(requirement):
            shown = editable.group(1) if editable else requirement
            gap = NOT_A_REGISTRY_PACKAGE
            candidates.append(
                _gap_candidate(shown, origin, observed_at, gap, _name_of(requirement), None)
            )
            continue
        if entry is None:
            continue
        if locked:
            identity = {"name": entry.name, "version": entry.version, "hashes": list(entry.hashes)}
            candidates.append(candidate("package", identity, origin, DECLARED, observed_at))
            continue
        gap = NO_EXACT_VERSION if entry.version is None else NOT_LOCKED
        candidates.append(
            _gap_candidate(requirement, origin, observed_at, gap, entry.name, entry.version)
        )
    if locked:
        identity = {"lock": relative, "packages": len(entries)}
        lock = candidate("environment", identity, {"file": relative}, DECLARED, observed_at)
        candidates.insert(0, lock)
    return candidates, skipped


def _pyproject(
    found: Walk, relative: str, observed_at: str, limits: Limits
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    text = read_text(found, relative, limits.text_bytes)
    if isinstance(text, dict):
        return [], [text]
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        return [], [skip(relative, f"not valid TOML: {error}")]
    project = data.get("project")
    if not isinstance(project, dict):
        return [], []
    groups: list[tuple[str, Any]] = [("[project].dependencies", project.get("dependencies"))]
    optional = project.get("optional-dependencies")
    if isinstance(optional, dict):
        groups += [(f"[project.optional-dependencies].{k}", v) for k, v in optional.items()]
    candidates: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for key, values in groups:
        if values is None:
            continue
        if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
            skipped.append(skip(relative, f"{key} is not a list of requirements"))
            continue
        for value in values:
            origin = {"file": relative, "key": key}
            requirement = value.strip()
            gap = NOT_A_REGISTRY_PACKAGE if _not_registry(requirement) else NOT_LOCKED
            entry = parse_line(requirement)
            version = None if entry is None else entry.version
            name = _name_of(requirement)
            candidates.append(_gap_candidate(requirement, origin, observed_at, gap, name, version))
    return candidates, skipped


def discover_python(
    found: Walk, observed_at: str, limits: Limits, files: Iterable[str] | None = None
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """The package and environment candidates of a project, and what was skipped reading them."""
    files = list(found.files if files is None else files)
    candidates: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    pending = [path for path in files if is_requirements(path)]
    done: set[str] = set()

    def queue(path: str) -> None:
        if path not in done and path not in pending:
            pending.append(path)

    while pending:
        path = pending.pop(0)
        if path in done:
            continue
        done.add(path)
        if path not in found.files:
            skipped.append(skip(path, "named by a -r or -c include but not found in the project"))
            continue
        more, missed = _requirements(found, path, observed_at, limits, queue)
        candidates += more
        skipped += missed
    for path in files:
        if PurePosixPath(path).name == "pyproject.toml":
            more, missed = _pyproject(found, path, observed_at, limits)
            candidates += more
            skipped += missed
        elif is_unread_lock(path):
            skipped.append(skip(path, LOCK_NOT_READ))
    return candidates, skipped

"""The strict globals policy: the safe list and the unlisted globals of one file scan (US2).

Under ``policy ID --globals strict`` every global a scan of a pickle file reported, whatever the
scanner's label, that is neither on the safe list nor excepted for the file's SHA-256 is
*unlisted*, and one ``globals_policy`` alert per file names them all (FR-008, owner's ruling D3).
The safe list is the package data file ``safe_globals/safe-globals.toml``: versioned, exact
entries only (FR-009), none naming an import the scanner could not resolve (research S14).
Every alert cites the list's version and the SHA-256 of the file as read.
"""

from __future__ import annotations

import hashlib
import json
import tomllib
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from model_dependabot.assurance.exceptions import UNRESOLVED, covering

SAFE_LIST_PATH = Path(__file__).resolve().parent.parent / "safe_globals" / "safe-globals.toml"


class SafeListError(ValueError):
    """The safe list file breaks one of its rules."""


@dataclass(frozen=True)
class SafeList:
    version: int
    sha256: str
    entries: frozenset[tuple[str, str]]


def entries_sha256(entries: Iterable[tuple[str, str]]) -> str:
    """The SHA-256 of the entries alone, sorted, as compact JSON: what a version pins."""
    body = json.dumps(sorted([list(item) for item in entries]), separators=(",", ":"))
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def load_safe_list(path: Path | None = None) -> SafeList:
    """Read and check the safe list (``SAFE_LIST_PATH`` unless ``path`` is given)."""
    source = path or SAFE_LIST_PATH
    raw = source.read_bytes()
    data = tomllib.loads(raw.decode("utf-8"))
    version = data.get("version")
    if not isinstance(version, int) or version < 1:
        raise SafeListError(f"{source.name}: version must be a whole number from 1")
    seen: set[tuple[str, str]] = set()
    for item in data.get("entries", []):
        module, name = str(item.get("module", "")), str(item.get("name", ""))
        where = f"{source.name}: entry {module}.{name}"
        if not module or not name:
            raise SafeListError(f"{where} has an empty module or name")
        if "*" in module or "*" in name:
            raise SafeListError(f"{where} is a wildcard; entries are exact globals (FR-009)")
        if UNRESOLVED in module or UNRESOLVED in name:
            raise SafeListError(f"{where} contains '{UNRESOLVED}', the scanner's unresolved mark")
        if (module, name) in seen:
            raise SafeListError(f"{where} is listed twice")
        seen.add((module, name))
    return SafeList(version, hashlib.sha256(raw).hexdigest(), frozenset(seen))


def current_safe_list() -> SafeList:
    """The safe list the check applies (read on each call, so a test can point it elsewhere)."""
    return load_safe_list(SAFE_LIST_PATH)


def _names(file_scan: Mapping[str, Any]) -> list[tuple[str, str]]:
    return sorted({(g["module"], g["name"]) for g in file_scan["globals"]})


def _resolved(module: str, name: str) -> bool:
    return UNRESOLVED not in module and UNRESOLVED not in name


def unlisted(
    file_scan: Mapping[str, Any], safe_list: SafeList, active: Sequence[Mapping[str, Any]]
) -> list[str]:
    """Every global the scan reported that is neither safe-listed nor excepted, sorted."""
    return [
        f"{module}.{name}"
        for module, name in _names(file_scan)
        if not _resolved(module, name)
        or ((module, name) not in safe_list.entries and covering(active, module, name) is None)
    ]


def excepted(
    file_scan: Mapping[str, Any], safe_list: SafeList, active: Sequence[Mapping[str, Any]]
) -> list[Mapping[str, Any]]:
    """The active exceptions that take a global of this scan off the unlisted list."""
    found = []
    for module, name in _names(file_scan):
        if not _resolved(module, name) or (module, name) in safe_list.entries:
            continue
        record = covering(active, module, name)
        if record is not None:
            found.append(record)
    return found


def is_clean(
    file_scan: Mapping[str, Any], safe_list: SafeList, active: Sequence[Mapping[str, Any]]
) -> bool:
    """Nothing unlisted and the scan complete: an incomplete scan is never clean (US2 sc. 5)."""
    return bool(file_scan["complete"]) and not unlisted(file_scan, safe_list, active)

"""Hash-locked requirements files, as pip and uv write them (research R10).

An entry is ``name==version`` with one or more ``--hash=ALG:HEX`` options, possibly spread over
several lines with backslash continuations, and possibly with an environment marker. It is pinned
only with an exact ``==`` version and at least one hash; anything else is a gap (FR-003). Names are
normalised with ``packaging.utils.canonicalize_name``. Comment lines and global options (such as
``--index-url``) are not entries; an editable install (``-e``) is a gap with no exact version.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

NO_EXACT_VERSION = "no exact version"
NO_HASH = "no hash"

_HASH = re.compile(r"--hash[=\s]+([A-Za-z0-9]+):([0-9a-fA-F]+)")
_EDITABLE = re.compile(r"^(?:-e|--editable)[=\s]+(\S+)")


@dataclass(frozen=True)
class LockEntry:
    """One requirement from a lock file; ``hashes`` are ``alg:hex`` strings in file order."""

    name: str
    version: str | None
    hashes: tuple[str, ...]
    pinned: bool
    gap_reason: str | None

    @property
    def purl(self) -> str | None:
        """``pkg:pypi/<name>@<version>`` when the version is exact, else ``None``."""
        if self.version is None:
            return None
        return f"pkg:pypi/{self.name}@{quote(self.version, safe='.!-_~')}"


def _logical_lines(text: str) -> list[str]:
    """Join backslash continuations and drop comments and blank lines."""
    lines: list[str] = []
    current = ""
    for raw in text.splitlines():
        stripped = raw.strip()
        if not current and (not stripped or stripped.startswith("#")):
            continue
        if stripped.startswith("#"):
            continue
        if stripped.endswith("\\"):
            current += stripped[:-1] + " "
            continue
        current += stripped
        lines.append(current.strip())
        current = ""
    if current.strip():
        lines.append(current.strip())
    return lines


def _exact_version(requirement: Requirement) -> str | None:
    specifiers = list(requirement.specifier)
    if len(specifiers) != 1:
        return None
    (specifier,) = specifiers
    if specifier.operator != "==" or "*" in specifier.version:
        return None
    return specifier.version


def _entry(line: str) -> LockEntry | None:
    hashes = tuple(f"{alg.lower()}:{digest.lower()}" for alg, digest in _HASH.findall(line))
    editable = _EDITABLE.match(line)
    if editable:
        return LockEntry(editable.group(1), None, hashes, False, NO_EXACT_VERSION)
    if line.startswith("-"):
        return None
    text = _HASH.sub("", line).strip()
    try:
        requirement = Requirement(text)
    except InvalidRequirement:
        name = re.split(r"[\s=<>!~;\[@]", text, maxsplit=1)[0]
        return LockEntry(canonicalize_name(name), None, hashes, False, NO_EXACT_VERSION)
    name = canonicalize_name(requirement.name)
    version = _exact_version(requirement)
    if version is None:
        return LockEntry(name, None, hashes, False, NO_EXACT_VERSION)
    if not hashes:
        return LockEntry(name, version, hashes, False, NO_HASH)
    return LockEntry(name, version, hashes, True, None)


def parse_lock(text: str) -> list[LockEntry]:
    """Every requirement in a lock file's text, in file order."""
    return [entry for line in _logical_lines(text) if (entry := _entry(line)) is not None]


def read_lock(path: Path | str) -> list[LockEntry]:
    return parse_lock(Path(path).read_text(encoding="utf-8"))

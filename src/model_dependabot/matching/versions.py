"""Local evaluation of OSV affected ranges under PEP 440 (research R2).

OSV's own match is the first opinion; this module is the second. A version is affected when it is
listed in ``affected[].versions`` or falls inside an ``ECOSYSTEM`` range of ``affected[].ranges``:
events are walked in version order, ``introduced`` opening an interval, ``fixed`` closing it
(exclusive) and ``last_affected`` closing it (inclusive). Other range types (``GIT``,
``SEMVER``) do not describe PyPI versions and are ignored. Versions compare under PEP 440 with
``packaging``, so pre-releases sort before their release.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

ECOSYSTEM = "PyPI"
_EVENT_ORDER = {"introduced": 0, "fixed": 1, "last_affected": 2, "limit": 3}


def _version(text: str) -> Version | None:
    try:
        return Version(text)
    except InvalidVersion:
        return None


def _listed(version: str, parsed: Version | None, listed: list[str]) -> bool:
    for candidate in listed:
        if candidate == version:
            return True
        other = _version(candidate)
        if parsed is not None and other is not None and other == parsed:
            return True
    return False


def _event_key(event: Mapping[str, str]) -> tuple[int, Version, int]:
    kind, value = next(iter(event.items()))
    if kind == "introduced" and value == "0":
        return (0, Version("0"), 0)
    parsed = _version(value)
    if parsed is None:
        raise InvalidVersion(value)
    return (1, parsed, _EVENT_ORDER.get(kind, 9))


def _in_range(parsed: Version, events: list[Mapping[str, str]]) -> bool:
    try:
        ordered = sorted(events, key=_event_key)
    except InvalidVersion:
        return False
    affected = False
    for event in ordered:
        kind, value = next(iter(event.items()))
        if kind == "introduced":
            if value == "0" or parsed >= Version(value):
                affected = True
        elif kind == "fixed":
            if parsed >= Version(value):
                affected = False
        elif kind == "last_affected" and parsed > Version(value):
            affected = False
    return affected


def version_affected(version: str, affected: Mapping[str, Any]) -> bool:
    """Whether ``version`` is inside one ``affected[]`` entry of an OSV record."""
    parsed = _version(version)
    if _listed(version, parsed, list(affected.get("versions") or [])):
        return True
    if parsed is None:
        return False
    for range_ in affected.get("ranges") or []:
        if range_.get("type") == "ECOSYSTEM" and _in_range(parsed, range_.get("events") or []):
            return True
    return False


def _entries(advisory: Mapping[str, Any], name: str) -> list[Mapping[str, Any]]:
    wanted = canonicalize_name(name)
    return [
        entry
        for entry in advisory.get("affected") or []
        if entry.get("package", {}).get("ecosystem") == ECOSYSTEM
        and canonicalize_name(entry.get("package", {}).get("name", "")) == wanted
    ]


def advisory_affects(advisory: Mapping[str, Any], name: str, version: str) -> bool:
    """Whether the advisory affects the PyPI package ``name`` at exactly ``version``."""
    return any(version_affected(version, entry) for entry in _entries(advisory, name))


def fixed_versions(advisory: Mapping[str, Any], name: str) -> list[str]:
    """The published fixed versions for ``name``, in record order; empty when none is published."""
    found: list[str] = []
    for entry in _entries(advisory, name):
        for range_ in entry.get("ranges") or []:
            if range_.get("type") != "ECOSYSTEM":
                continue
            for event in range_.get("events") or []:
                value = event.get("fixed")
                if value is not None and value not in found:
                    found.append(value)
    return found


def affected_ranges(advisory: Mapping[str, Any], name: str) -> list[dict[str, Any]]:
    """The ``ECOSYSTEM`` ranges for ``name`` as published."""
    return [
        {"type": range_["type"], "events": [dict(event) for event in range_.get("events") or []]}
        for entry in _entries(advisory, name)
        for range_ in entry.get("ranges") or []
        if range_.get("type") == "ECOSYSTEM"
    ]

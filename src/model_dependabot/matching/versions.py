"""Local evaluation of OSV affected ranges under PEP 440 (research R2).

This is a consistency check on the OSV record that OSV itself matched, not a second source: it
re-reads the same record's ranges locally. A version is affected when it is listed in
``affected[].versions`` or falls inside an ``ECOSYSTEM`` range of ``affected[].ranges``, following
the OSV schema's evaluation rules: events are walked in version order, ``introduced`` opening an
interval (``"0"`` meaning before every version), ``fixed`` closing it (exclusive) and
``last_affected`` closing it (inclusive); a version is inside the range only if it is also below
at least one ``limit`` (exclusive; ``"*"`` means infinity, and no ``limit`` means an implicit
``"*"``). Other range types (``GIT``, ``SEMVER``) do not describe PyPI versions and are ignored.
Versions compare under PEP 440 with ``packaging``, so pre-releases sort before their release.

A range that cannot be evaluated (an event value that is not a PEP 440 version, an unknown event
kind or no ``introduced`` event) and a pinned version that is not a PEP 440 version are reported as
unevaluated, with the reason, rather than as "not affected".
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
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


def _range_problem(events: list[Mapping[str, str]]) -> str | None:
    """Why the range cannot be evaluated, or ``None`` when it can."""
    if not any(len(event) == 1 and "introduced" in event for event in events):
        return "range has no introduced event"
    for event in events:
        if len(event) != 1:
            return f"event {dict(event)!r} does not name exactly one kind"
        kind, value = next(iter(event.items()))
        if kind not in _EVENT_ORDER:
            return f"unknown event kind {kind!r}"
        if not isinstance(value, str):
            return f"{kind} value {value!r} is not a string"
        if kind == "introduced" and value == "0":
            continue
        if kind == "limit" and value == "*":
            continue
        if _version(value) is None:
            return f"{kind} value {value!r} is not a PEP 440 version"
    return None


def _before_limits(parsed: Version, events: list[Mapping[str, str]]) -> bool:
    limits = [event["limit"] for event in events if "limit" in event]
    if not limits:
        return True  # an implicit "*"
    return any(limit == "*" or parsed < Version(limit) for limit in limits)


def _in_range(parsed: Version, events: list[Mapping[str, str]]) -> bool:
    """OSV ``IncludedInRanges`` for one evaluable range (checked by ``_range_problem`` first)."""
    if not _before_limits(parsed, events):
        return False
    ordered = sorted((event for event in events if "limit" not in event), key=_event_key)
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


@dataclass(frozen=True)
class Evaluation:
    """The local reading of an OSV record for one pinned version.

    ``affected`` is true when some entry lists or covers the version. When it is false,
    ``evaluated`` says whether every range that could cover the version was read: false means
    "cannot say", with ``reasons`` naming why, not "not affected".
    """

    affected: bool
    evaluated: bool
    reasons: tuple[str, ...] = ()


def evaluate_affected(version: str, affected: Mapping[str, Any]) -> Evaluation:
    """Evaluate ``version`` against one ``affected[]`` entry of an OSV record."""
    parsed = _version(version)
    if _listed(version, parsed, list(affected.get("versions") or [])):
        return Evaluation(affected=True, evaluated=True)
    ranges = [r for r in affected.get("ranges") or [] if r.get("type") == "ECOSYSTEM"]
    if parsed is None:
        if not ranges:
            return Evaluation(affected=False, evaluated=True)
        return Evaluation(
            affected=False,
            evaluated=False,
            reasons=(f"pinned version {version!r} is not a PEP 440 version",),
        )
    reasons: list[str] = []
    for range_ in ranges:
        events = list(range_.get("events") or [])
        problem = _range_problem(events)
        if problem is not None:
            reasons.append(problem)
        elif _in_range(parsed, events):
            return Evaluation(affected=True, evaluated=True)
    return Evaluation(affected=False, evaluated=not reasons, reasons=tuple(reasons))


def version_affected(version: str, affected: Mapping[str, Any]) -> bool:
    """Whether ``version`` is inside one ``affected[]`` entry of an OSV record."""
    return evaluate_affected(version, affected).affected


def _entries(advisory: Mapping[str, Any], name: str) -> list[Mapping[str, Any]]:
    wanted = canonicalize_name(name)
    return [
        entry
        for entry in advisory.get("affected") or []
        if entry.get("package", {}).get("ecosystem") == ECOSYSTEM
        and canonicalize_name(entry.get("package", {}).get("name", "")) == wanted
    ]


def evaluate_advisory(advisory: Mapping[str, Any], name: str, version: str) -> Evaluation:
    """Evaluate the advisory for the PyPI package ``name`` at exactly ``version``."""
    reasons: list[str] = []
    for entry in _entries(advisory, name):
        result = evaluate_affected(version, entry)
        if result.affected:
            return result
        reasons.extend(reason for reason in result.reasons if reason not in reasons)
    return Evaluation(affected=False, evaluated=not reasons, reasons=tuple(reasons))


def advisory_affects(advisory: Mapping[str, Any], name: str, version: str) -> bool:
    """Whether the advisory affects the PyPI package ``name`` at exactly ``version``."""
    return evaluate_advisory(advisory, name, version).affected


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

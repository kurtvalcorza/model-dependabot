"""Which inventory entry an alert affects, how it relates to the model and its runtime use (010).

Feature 010, US1 (FR-005 to FR-008, research R2 and R3). Pure functions of stored rows: the alert,
and ``versions``, which maps each stored version of the alert's model to its origin and entries
(``model_versions``). An entry is matched only exactly, by identifier or, for an alert keyed by a
hub repository, by that repository; nothing is matched by name, similarity or prefix (FR-006).
Whether a cause is repository-wide and which repository an entry belongs to are decided by
``lifecycle.py``, whose helpers are imported unchanged.

Reading only: nothing here writes to the store.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from packaging.utils import canonicalize_name

from model_dependabot.lifecycle import (
    _hub_scope,
    _repository_of,
    _repository_scoped,
    base_model_repo,
    hub_dataset_repo,
)
from model_dependabot.rules import RELATIONSHIPS
from model_dependabot.store import Store

WEIGHT_ALERTS = ("weight_file_scan", "hub_scan", "format_policy", "globals_policy")
DATASET_ALERTS = ("dataset_retracted", "dataset_not_findable", "dataset_removed")
SECTIONS = {
    "weight_file": "[[weights]]",
    "package": "[environment] lock",
    "base_model": "[base_model]",
    "dataset": "[[datasets]]",
}
NO_HOLDER = "no stored version holds this identifier"
NO_IDENTIFIER = "the alert's cause does not name an identifier"
NO_VERSION = "the alert's model has no stored version"
UNKNOWN_WHY = "no source observes runtime use and the owner has not declared it for this alert"
NOT_USED = "not_used_at_runtime"
OWNER_ORIGINS = ("manifest", "record")

Versions = Mapping[int, Mapping[str, Any]]


def model_versions(store: Store, model_id: str) -> dict[int, dict[str, Any]]:
    """Every stored version of a model: ``{version: {"origin": ..., "entries": [...]}}``."""
    latest = store.latest_version(model_id)
    result: dict[int, dict[str, Any]] = {}
    for version in range(1, (latest or 0) + 1):
        stored = store.get_version(model_id, version)
        if stored is None:
            continue
        result[version] = {
            "origin": stored.get("origin"),
            "entries": store.entries(model_id, version),
        }
    return result


def _repository(alert: Mapping[str, Any]) -> tuple[str, str] | None:
    """The hub repository of a repository-keyed alert, as (entry kind, owner/name)."""
    cause = alert["cause"]
    if not _repository_scoped(alert["kind"], cause):
        return None
    if alert["kind"] in ("base_model_disabled", "base_model_unavailable") and cause.get("repo"):
        return ("base_model", str(cause["repo"]))
    if alert["kind"] == "dataset_removed" and cause.get("repo"):
        return ("dataset", str(cause["repo"]))
    return _repository_of(cause, [])


def _in_repository(entry: Mapping[str, Any], repository: tuple[str, str]) -> bool:
    kind, repo = repository
    if entry["kind"] != kind:
        return False
    scope = _hub_scope(entry)
    if kind == "base_model":
        return scope == base_model_repo({"name": repo})
    return scope == hub_dataset_repo(repo)


def _same_package(entry: Mapping[str, Any], cause: Mapping[str, Any]) -> bool:
    if entry["identifier"] == cause.get("identifier"):
        return True
    if not cause.get("package") or not entry.get("name"):
        return False
    same_name = canonicalize_name(entry["name"]) == canonicalize_name(str(cause["package"]))
    return same_name and entry.get("version") == cause.get("version")


def _matches(alert: Mapping[str, Any], entry: Mapping[str, Any]) -> str | None:
    """How ``entry`` matches the alert (``identifier`` or ``repository``), or ``None``."""
    kind, cause = alert["kind"], alert["cause"]
    identifier = cause.get("identifier")
    if kind in WEIGHT_ALERTS:
        matched = entry["kind"] == "weight_file" and entry["identifier"] == identifier
        return "identifier" if matched else None
    if kind == "package_advisory":
        return "identifier" if entry["kind"] == "package" and _same_package(entry, cause) else None
    repository = _repository(alert)
    if kind == "paper_retracted":
        if entry["kind"] != "dataset":
            return None
        if cause.get("paper_doi") not in (entry.get("paper_dois") or []):
            return None
        if repository is not None:
            return "repository" if _in_repository(entry, repository) else None
        dataset = cause.get("dataset") or identifier
        return "identifier" if entry["identifier"] == dataset else None
    if repository is not None:
        return "repository" if _in_repository(entry, repository) else None
    if kind in DATASET_ALERTS:
        matched = entry["kind"] == "dataset" and entry["identifier"] == identifier
        return "identifier" if matched else None
    if kind == "licence_changed":
        item = cause.get("item") or identifier
        matched = entry["kind"] in ("base_model", "dataset") and entry["identifier"] == item
        return "identifier" if matched else None
    return None


def matched_entries(alert: Mapping[str, Any], versions: Versions) -> list[dict[str, Any]]:
    """Every (version, entry) that holds the alert's dependency: version descending, then the
    order ``store.entries`` returns. Each item is ``{version, origin, entry, matched_by}``."""
    found = []
    for version in sorted(versions, reverse=True):
        stored = versions[version]
        for entry in stored["entries"]:
            how = _matches(alert, entry)
            if how is not None:
                found.append(
                    {
                        "version": version,
                        "origin": stored.get("origin"),
                        "entry": entry,
                        "matched_by": how,
                    }
                )
    return found


def _location(entry: Mapping[str, Any]) -> str | None:
    if entry.get("location"):
        return str(entry["location"])
    if entry["kind"] == "weight_file" and entry.get("hub_repo"):
        return f"hf:{entry['hub_repo']}/{entry['hub_file']}"
    return None


def _revision(entry: Mapping[str, Any]) -> str | None:
    if entry["kind"] in ("package", "base_model"):
        return entry.get("version")
    return entry.get("hub_revision")


def _place(match: Mapping[str, Any]) -> dict[str, Any]:
    entry, origin = match["entry"], match["origin"]
    return {
        "version": match["version"],
        "origin": origin,
        "section": None if origin == "import" else SECTIONS[entry["kind"]],
        "location": _location(entry),
        "revision": _revision(entry),
    }


def resolve_entry(alert: Mapping[str, Any], versions: Versions) -> dict[str, Any]:
    """The affected entry of data-model.md: resolved with its places, or unresolved with a
    reason (FR-006)."""
    cause = alert["cause"]
    identifier = cause.get("identifier")
    found = matched_entries(alert, versions) if versions and identifier else []
    reason = None
    if not versions:
        reason = NO_VERSION
    elif not identifier:
        reason = NO_IDENTIFIER
    elif not found:
        reason = NO_HOLDER
    latest = max(versions) if versions else None
    held = found[0]["version"] if found else None
    return {
        "status": "unresolved" if reason else "resolved",
        "reason": reason,
        "kind": found[0]["entry"]["kind"] if found else None,
        "identifier": identifier,
        "matched_by": found[0]["matched_by"] if found else None,
        "in_current_version": None if not found else held == latest,
        "last_held_in_version": held,
        "opened_in_version": alert["opened_in_version"],
        "closed_by_version": alert.get("closed_by_version"),
        "places": [_place(match) for match in found],
    }


def declared_by(origin: str | None) -> str:
    """``owner`` for a manifest or record version, ``imported`` for an import, else ``legacy``."""
    if origin in OWNER_ORIGINS:
        return "owner"
    return "imported" if origin == "import" else "legacy"


def relationship(
    entry: Mapping[str, Any], alert: Mapping[str, Any], places: Sequence[Mapping[str, Any]]
) -> dict[str, Any] | None:
    """The entry's relationship with the model, from ``rules.RELATIONSHIPS``, with its basis;
    ``None`` for an unresolved entry."""
    if entry["status"] != "resolved" or not places:
        return None
    found = RELATIONSHIPS[(entry["kind"], alert["kind"])]
    first = places[0]
    return {
        "value": found.value,
        "steps_from_model": found.steps_from_model,
        "basis": {
            "declared_by": declared_by(first["origin"]),
            "origin": first["origin"],
            "section": first["section"],
            "version": first["version"],
        },
    }


def runtime_use(alert: Mapping[str, Any], others: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Runtime use (FR-007, FR-008): ``declared`` ``not_used`` only from this alert's own
    ``not_used_at_runtime`` dismissal; otherwise ``unknown``, with the other alerts on the same
    identifier that were dismissed that way as context. Nothing produces ``observed``."""
    if alert["state"] == "dismissed" and alert.get("dismissal_reason") == NOT_USED:
        return {
            "state": "declared",
            "polarity": "not_used",
            "basis": {
                "by": alert.get("dismissed_by"),
                "at": alert.get("closed_at"),
                "note": alert.get("note"),
                "alert_id": alert["alert_id"],
            },
            "context": [],
        }
    context = [
        {
            "alert_id": other["alert_id"],
            "by": other.get("dismissed_by"),
            "at": other.get("closed_at"),
        }
        for other in sorted(others, key=lambda item: item["alert_id"])
        if other["alert_id"] != alert["alert_id"]
        and other["state"] == "dismissed"
        and other.get("dismissal_reason") == NOT_USED
    ]
    return {"state": "unknown", "polarity": None, "basis": {"why": UNKNOWN_WHY}, "context": context}

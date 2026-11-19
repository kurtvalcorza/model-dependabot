"""Which hub repository an upstream alert's cause is about, and whether an inventory holds it.

The identity and clearance rules of feature 002 (identity table): a disabled or unavailable base
model, a disabled hub dataset, a licence read from a base model's or hub dataset's info and a paper
tied to a hub dataset are states of a whole hub repository, so another revision of the same
repository carries them. ``lifecycle`` uses these when a new version is registered; feature 011's
``lineage.propagate`` uses ``in_inventory`` to decide which of a registered parent's alerts belong
to the version a child references (owner's ruling C5, review R4). Pure functions of stored rows.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any
from urllib.parse import unquote

from model_dependabot.inventory.build import HUB_DATASET_PREFIX

BASE_MODEL_DISABLED = "base_model_disabled"
BASE_MODEL_UNAVAILABLE = "base_model_unavailable"
DATASET_REMOVED = "dataset_removed"
LICENCE_CHANGED = "licence_changed"
PAPER_RETRACTED = "paper_retracted"
REPOSITORY_ALERTS = (BASE_MODEL_DISABLED, BASE_MODEL_UNAVAILABLE)


def repository_scoped(kind: str, cause: Mapping[str, Any]) -> bool:
    """Whether the cause is a state or observation of a whole hub repository (identity and
    clearance table): a disabled or unavailable base model, a disabled hub dataset, a licence
    read from a base model's or hub dataset's info, or a paper tied to a hub dataset."""
    identifier = str(cause.get("identifier") or "")
    on_hub = identifier.startswith((HUB_DATASET_PREFIX, "pkg:huggingface/"))
    return (
        kind in REPOSITORY_ALERTS
        or (kind == DATASET_REMOVED and cause.get("host") == "huggingface")
        or (kind == LICENCE_CHANGED and on_hub)
        or (kind == PAPER_RETRACTED and identifier.startswith(HUB_DATASET_PREFIX))
    )


def repository_of(
    cause: Mapping[str, Any], earlier: Sequence[Mapping[str, Any]]
) -> tuple[str, str] | None:
    """The hub repository the cause's item is in, as (entry kind, owner/name), if it is in one.

    Read from the earlier version's entry for the item, else from the cause itself (an alert
    written before causes named their repository).
    """
    for entry in earlier:
        if entry.get("identifier") != cause["identifier"]:
            continue
        if entry["kind"] == "base_model" and entry.get("name"):
            return ("base_model", entry["name"])
        if entry["kind"] == "dataset" and entry.get("hub_repo"):
            return ("dataset", entry["hub_repo"])
    identifier = str(cause["identifier"])
    if identifier.startswith(HUB_DATASET_PREFIX):
        return ("dataset", identifier.removeprefix(HUB_DATASET_PREFIX).rsplit("@", 1)[0])
    if cause.get("repo") and identifier.startswith("pkg:huggingface/"):
        return ("base_model", str(cause["repo"]))
    if identifier.startswith("pkg:huggingface/"):
        return (
            "base_model",
            unquote(identifier.removeprefix("pkg:huggingface/").rsplit("@", 1)[0]),
        )
    return None


def in_repository(entry: Mapping[str, Any], repository: tuple[str, str]) -> bool:
    kind, repo = repository
    if entry["kind"] != kind:
        return False
    return entry.get("name" if kind == "base_model" else "hub_repo") == repo


def in_inventory(kind: str, cause: Mapping[str, Any], entries: Sequence[Mapping[str, Any]]) -> bool:
    """Whether ``entries`` hold the item an alert of ``kind`` with ``cause`` is about.

    The cause's identifier is one of the entries' identifiers, or, for a repository-scoped cause,
    an entry is in that repository (any revision).
    """
    identifiers = {entry.get("identifier") for entry in entries if entry.get("identifier")}
    if cause.get("identifier") in identifiers:
        return True
    if not repository_scoped(kind, cause):
        return False
    repository = repository_of(cause, entries)
    return repository is not None and any(in_repository(entry, repository) for entry in entries)

"""Candidates against each other and against an existing manifest (FR-019).

Two dependency files naming one package at different exact versions make both candidates
``conflicting``. Given a manifest (read with ``load_manifest(path, weights_present=False)``, so
nothing it names is opened), each candidate gets ``manifest``: ``matches``,
``missing_from_manifest`` or ``conflicts`` with the manifest's value in ``manifest_value``; what
the manifest declares and discovery did not see goes to ``declared_not_seen``.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any

from model_dependabot.discover.candidate import CONFLICTING, NO_REVISION
from model_dependabot.discover.walk import OUTSIDE
from model_dependabot.manifest import Manifest

MATCHES = "matches"
MISSING = "missing_from_manifest"
CONFLICTS = "conflicts"


def mark_version_conflicts(candidates: list[dict[str, Any]]) -> None:
    """Packages declared at different exact versions in different places are all conflicting."""
    by_name: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in candidates:
        identity = item["identity"]
        if item["kind"] == "package" and identity.get("version") and identity.get("name"):
            by_name[identity["name"]].append(item)
    for same in by_name.values():
        versions = sorted({item["identity"]["version"] for item in same})
        if len(versions) < 2:
            continue
        for item in same:
            item["status"] = CONFLICTING
            item["note"] = f"declared at versions {', '.join(versions)}"


def _project_path(root: Path, path: Path | None) -> str | None:
    if path is None:
        return None
    resolved = path.resolve()
    if not resolved.is_relative_to(root):
        return None
    return resolved.relative_to(root).as_posix()


def _mark(item: dict[str, Any], state: str, value: dict[str, Any] | None = None) -> None:
    item["manifest"] = state
    if value is not None:
        item["manifest_value"] = value


def _not_seen(kind: str, identity: dict[str, Any], where: str, **fields: Any) -> dict[str, Any]:
    return {"kind": kind, "identity": identity, "origin": {"key": where}, **fields}


def compare(
    candidates: list[dict[str, Any]], manifest: Manifest, root: Path
) -> list[dict[str, Any]]:
    """Mark every candidate against ``manifest``; return the entries discovery did not see."""
    root = root.resolve()
    not_seen: list[dict[str, Any]] = []
    by_kind: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in candidates:
        by_kind[item["kind"]].append(item)

    # Local weight files, by their path inside the project; hub files are never seen locally.
    declared: dict[str, int] = {}
    for index, spec in enumerate(manifest.weights):
        where = f"weights[{index}]"
        if spec.hub_repo is not None:
            identity = {"hub_repo": spec.hub_repo, "file": spec.file, "revision": spec.revision}
            not_seen.append(_not_seen("weight_file", identity, where))
            continue
        relative = _project_path(root, spec.path)
        if relative is None:
            identity = {"path": spec.relative}
            not_seen.append(_not_seen("weight_file", identity, where, reason=OUTSIDE))
        else:
            declared[relative] = index
    seen: set[str] = set()
    for item in by_kind["weight_file"]:
        path = item["identity"]["path"]
        _mark(item, MATCHES if path in declared else MISSING)
        seen.add(path)
    for path, index in declared.items():
        if path not in seen:
            not_seen.append(_not_seen("weight_file", {"path": path}, f"weights[{index}]"))

    # The environment lock, and the packages of that lock file.
    lock = _project_path(root, manifest.lock)
    if manifest.lock is not None and lock is None:
        identity = {"lock": str(manifest.lock)}
        not_seen.append(_not_seen("environment", identity, "environment.lock", reason=OUTSIDE))
    environments = by_kind["environment"]
    for item in environments:
        if lock is None:
            _mark(item, MISSING)
        elif item["identity"]["lock"] == lock:
            _mark(item, MATCHES)
        else:
            _mark(item, CONFLICTS, {"lock": lock})
    if lock is not None and not any(item["identity"]["lock"] == lock for item in environments):
        not_seen.append(_not_seen("environment", {"lock": lock}, "environment.lock"))
    locked = {
        item["identity"]["name"]: item["identity"]["version"]
        for item in by_kind["package"]
        if item["origin"].get("file") == lock and not item["gaps"]
    }
    for item in by_kind["package"]:
        name = item["identity"].get("name")
        if name not in locked:
            _mark(item, MISSING)
        elif item["identity"].get("version") in (None, locked[name]):
            _mark(item, MATCHES)
        else:
            _mark(item, CONFLICTS, {"name": name, "version": locked[name]})

    # The base model.
    base = manifest.base_model
    base_models = by_kind["base_model"]
    if base is None:
        for item in base_models:
            _mark(item, MISSING)
    else:
        wanted = base.repo.lower()
        matched = [item for item in base_models if item["identity"]["hub_repo"].lower() == wanted]
        for item in base_models:
            if item in matched:
                _mark(item, MATCHES, {"hub_repo": base.repo, "revision": base.revision})
                if base.revision is not None and NO_REVISION in item["gaps"]:
                    item["gaps"].remove(NO_REVISION)  # the manifest supplies it (research A6)
            elif matched:
                _mark(item, MISSING)
            else:
                _mark(item, CONFLICTS, {"hub_repo": base.repo})
        if not base_models:
            identity = {"hub_repo": base.repo, "revision": base.revision}
            not_seen.append(_not_seen("base_model", identity, "base_model"))

    # Datasets: hub datasets by name; a DOI dataset is never seen by discovery.
    hub = {spec.hub.lower(): index for index, spec in enumerate(manifest.datasets) if spec.hub}
    seen_hub: set[str] = set()
    for item in by_kind["dataset"]:
        name = str(item["identity"].get("hub_repo", "")).lower()
        _mark(item, MATCHES if name in hub else MISSING)
        seen_hub.add(name)
    for index, spec in enumerate(manifest.datasets):
        if spec.hub and spec.hub.lower() in seen_hub:
            continue
        identity = {"hub_repo": spec.hub} if spec.hub else {"doi": spec.doi}
        not_seen.append(_not_seen("dataset", identity, f"datasets[{index}]"))

    # The manifest format has no licence: a licence is always missing from it.
    for item in by_kind["licence"]:
        _mark(item, MISSING)
    return not_seen

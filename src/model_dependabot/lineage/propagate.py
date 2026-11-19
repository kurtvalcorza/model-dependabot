"""Which findings of a registered parent travel to a child, and along which path (FR-015 to FR-020).

``TRAVELS`` is the closed relevance matrix of FR-017 (data-model.md): an alert kind maps to the
edge types it travels on, and a kind it does not list, including any added later, travels on none
(constitution IV). Watch events never travel. An ``unspecified`` edge passes only the kinds that
travel on all four types (FR-019); a parent reached over two edges of different types (an ambiguous
pair) passes the intersection (US4 AS3); a path passes a kind only when every hop does.

Which of a parent's alerts belong to the version a child references (owner's ruling C5, research
L7): those whose item is in that version's own stored inventory, open or fixed by a later version.

The walk is breadth first over resolved, owner-stated registered-model edges and visits each model
version at most once (FR-022). An imported (``unverified``) reference carries nothing (FR-010a).
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from model_dependabot.lineage import RELATIONSHIPS, UNSPECIFIED
from model_dependabot.lineage.edges import Edge, Exists
from model_dependabot.lineage.graph import Node, label, parent_node

ALL = frozenset(RELATIONSHIPS)
_WEIGHTS = frozenset({"adapter-for"})
TRAVELS: Mapping[str, frozenset[str]] = {
    "package_advisory": frozenset(),
    "weight_file_scan": _WEIGHTS,
    "hub_scan": _WEIGHTS,
    "format_policy": _WEIGHTS,
    "globals_policy": _WEIGHTS,
    "dataset_retracted": ALL,
    "paper_retracted": ALL,
    "dataset_removed": ALL,
    "dataset_not_findable": ALL,
    "licence_changed": ALL,
    "base_model_disabled": ALL,
    "base_model_unavailable": ALL,
}
LINEAGE_INHERITED = "lineage_inherited"


def travels_on(kind: str, relationship: str) -> bool:
    """Whether a parent alert of ``kind`` travels along one edge of ``relationship``."""
    allowed = TRAVELS.get(kind, frozenset())
    if relationship == UNSPECIFIED:
        return allowed == ALL
    return relationship in allowed


def travels(kind: str, relationships: Sequence[str] | set[str] | frozenset[str]) -> bool:
    """Whether ``kind`` passes one hop whose edges have ``relationships`` (the intersection)."""
    return bool(relationships) and all(travels_on(kind, r) for r in relationships)


def candidates(
    alerts: Sequence[Mapping[str, Any]], entries: Sequence[Mapping[str, Any]], version: int
) -> list[Mapping[str, Any]]:
    """The parent's alerts that belong to its version ``version`` (ruling C5, research L7).

    An alert belongs when its item is in the version's stored entries (by entry identifier, or for a
    repository-scoped cause by an entry in that repository) and it is open, or fixed by a version
    later than ``version``. ``opened_in_version`` and ``current_version`` play no part.
    """
    from model_dependabot import lifecycle  # the repository rules live with the check

    identifiers = {entry.get("identifier") for entry in entries if entry.get("identifier")}
    found = []
    for alert in alerts:
        state = alert["state"]
        closed_by = alert.get("closed_by_version")
        later_fix = state == "fixed" and closed_by is not None and closed_by > version
        if state != "open" and not later_fix:
            continue
        cause = alert["cause"]
        if cause.get("identifier") in identifiers:
            found.append(alert)
            continue
        if lifecycle._repository_scoped(alert["kind"], cause):
            repository = lifecycle._repository_of(cause, entries)
            if repository is not None and any(
                lifecycle._in_repository(entry, repository) for entry in entries
            ):
                found.append(alert)
    return found


def _hop(child: Node, parent: Node, edge: Edge) -> dict[str, Any]:
    return {
        "child": label(child),
        "parent": label(parent),
        "relationship": edge["relationship"],
        "origin": edge.get("origin"),
        "edge_id": edge.get("edge_id"),
    }


def inherited(
    child: Node,
    edges_of: Callable[[Node], Sequence[Edge]],
    alerts_of: Callable[[str], Sequence[Mapping[str, Any]]],
    entries_of: Callable[[Node], Sequence[Mapping[str, Any]]],
    exists: Exists,
) -> list[dict[str, Any]]:
    """The inherited findings of ``child``: one per parent alert that reaches it (FR-018).

    Each is ``{parent, parent_alert, reach, paths, relationship_unspecified}``; ``paths`` lists the
    ways the walk reached the parent (one per edge of the last hop when a parent is named twice),
    each a list of hops from the child upward.
    """
    visited = {child}
    queue: deque[tuple[Node, list[list[Edge]], list[Node]]] = deque([(child, [], [child])])
    findings: list[dict[str, Any]] = []
    while queue:
        node, hops, nodes = queue.popleft()
        by_parent: dict[Node, list[Edge]] = {}
        for edge in edges_of(node):
            if edge.get("state") != "owner":
                continue  # an imported reference carries nothing (FR-010a)
            parent = parent_node(edge, exists)
            if parent is not None:
                by_parent.setdefault(parent, []).append(edge)
        for parent in sorted(by_parent):
            if parent in visited:
                continue  # a cycle or a shared ancestor: each version once (FR-022)
            visited.add(parent)
            path_hops = [*hops, by_parent[parent]]
            path_nodes = [*nodes, parent]
            findings += _findings(parent, path_hops, path_nodes, alerts_of, entries_of)
            queue.append((parent, path_hops, path_nodes))
    return findings


def _findings(
    parent: Node,
    hops: list[list[Edge]],
    nodes: list[Node],
    alerts_of: Callable[[str], Sequence[Mapping[str, Any]]],
    entries_of: Callable[[Node], Sequence[Mapping[str, Any]]],
) -> list[dict[str, Any]]:
    found = []
    entries = entries_of(parent)
    prefix = [
        _hop(nodes[index], nodes[index + 1], group[0]) for index, group in enumerate(hops[:-1])
    ]
    paths = [[*prefix, _hop(nodes[-2], parent, edge)] for edge in hops[-1]]
    unspecified = any(edge["relationship"] == UNSPECIFIED for group in hops for edge in group)
    for alert in candidates(alerts_of(parent[0]), entries, parent[1]):
        kind = alert["kind"]
        if not all(travels(kind, {edge["relationship"] for edge in group}) for group in hops):
            continue
        found.append(
            {
                "parent": parent,
                "parent_alert": {
                    "alert_id": alert["alert_id"],
                    "model_id": parent[0],
                    "kind": kind,
                    "cause_key": alert["cause_key"],
                    "severity": alert["severity"],
                    "state": alert["state"],
                },
                "reach": "direct" if len(hops) == 1 else "transitive",
                "paths": paths,
                "relationship_unspecified": unspecified,
            }
        )
    return found


def entry_identifier(finding: Mapping[str, Any]) -> str:
    """``model:<parent id>@<parent version>/<parent cause key>`` (data-model.md)."""
    model_id, version = finding["parent"]
    return f"model:{model_id}@{version}/{finding['parent_alert']['cause_key']}"


def detail(finding: Mapping[str, Any]) -> dict[str, Any]:
    """The ``lineage_inherited`` watch event's detail (contracts/edge-evidence.md)."""
    return {
        "parent_alert": dict(finding["parent_alert"]),
        "parent": label(finding["parent"]),
        "reach": finding["reach"],
        "paths": finding["paths"],
        "relationship_unspecified": finding["relationship_unspecified"],
    }

"""Which findings of a registered parent travel to a child, and along which path (FR-015 to FR-020).

``TRAVELS`` is the closed relevance matrix of FR-017 (data-model.md): an alert kind maps to the
edge types it travels on, and a kind it does not list, including any added later, travels on none
(constitution IV). Watch events never travel. An ``unspecified`` edge passes only the kinds that
travel on all four types (FR-019); a parent reached over two edges of different types (an ambiguous
pair) passes the intersection (US4 AS3); a path passes a kind only when every hop does.

Which of a parent's alerts belong to the version a child references (owner's ruling C5, research
L7): those whose item is in that version's own stored inventory, open or fixed by a later version.

The walk is breadth first over resolved, owner-stated registered-model edges. A finding reaches the
child when at least one path passes it on every hop, whatever the order of model ids (owner's
ruling on review R1); the walk is bounded (FR-022): a version is expanded only for kinds no earlier
path brought it. An imported (``unverified``) reference carries nothing (FR-010a).
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from model_dependabot.lineage import RELATIONSHIPS, UNSPECIFIED
from model_dependabot.lineage.edges import Edge, Exists
from model_dependabot.lineage.graph import Node, label, parent_node
from model_dependabot.upstream.scope import in_inventory

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
    found = []
    for alert in alerts:
        state = alert["state"]
        closed_by = alert.get("closed_by_version")
        later_fix = state == "fixed" and closed_by is not None and closed_by > version
        if state != "open" and not later_fix:
            continue
        if in_inventory(alert["kind"], alert["cause"], entries):
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


def _owner_parents(edges: Sequence[Edge], exists: Exists) -> dict[Node, list[Edge]]:
    """A version's resolved, owner-stated registered-model edges, by parent version."""
    by_parent: dict[Node, list[Edge]] = {}
    for edge in edges:
        if edge.get("state") != "owner":
            continue  # an imported reference carries nothing (FR-010a)
        parent = parent_node(edge, exists)
        if parent is not None:
            by_parent.setdefault(parent, []).append(edge)
    return by_parent


def inherited(
    child: Node,
    edges_of: Callable[[Node], Sequence[Edge]],
    alerts_of: Callable[[str], Sequence[Mapping[str, Any]]],
    entries_of: Callable[[Node], Sequence[Mapping[str, Any]]],
    exists: Exists,
) -> list[dict[str, Any]]:
    """The inherited findings of ``child``: one per parent alert that reaches it (FR-018).

    A parent alert reaches the child when at least one path exists on which every hop passes its
    kind (owner's ruling, review R1 to R3). The walk is breadth first over states (version, kinds
    that can still travel down from it): a version is expanded again only when a path brings kinds
    no earlier path brought, so the result does not depend on the order of model ids, a cycle ends
    (the kinds on a path only shrink, and the child starts with all of them) and each version is
    expanded at most once per travelling kind. Each version's edges, alerts and entries are read
    once.

    Each finding is ``{parent, parent_alert, reach, paths, relationship_unspecified}``, taken from
    the shortest path that carries it (``reach`` is ``direct`` for one edge); ``paths`` lists that
    path once per edge of its last hop when the parent is named by several edges.
    """
    every = frozenset(kind for kind, types in TRAVELS.items() if types)
    reached: dict[Node, set[str]] = {child: set(every)}
    parents_cache: dict[Node, dict[Node, list[Edge]]] = {}
    candidates_cache: dict[Node, list[Mapping[str, Any]]] = {}
    queue: deque[tuple[Node, frozenset[str], list[list[Edge]], list[Node]]] = deque(
        [(child, every, [], [child])]
    )
    found: dict[int, dict[str, Any]] = {}
    while queue:
        node, kinds, hops, nodes = queue.popleft()
        if node not in parents_cache:
            parents_cache[node] = _owner_parents(edges_of(node), exists)
        for parent, group in sorted(parents_cache[node].items()):
            types = {edge["relationship"] for edge in group}
            passing = frozenset(kind for kind in kinds if travels(kind, types))
            new = passing - reached.setdefault(parent, set())
            if not new:
                continue  # no kind this path carries is new here: a cycle or a known route
            reached[parent] |= new
            path_hops, path_nodes = [*hops, group], [*nodes, parent]
            if parent not in candidates_cache:
                entries = entries_of(parent)
                candidates_cache[parent] = candidates(alerts_of(parent[0]), entries, parent[1])
            for alert in candidates_cache[parent]:
                if alert["kind"] in new and alert["alert_id"] not in found:
                    found[alert["alert_id"]] = _finding(parent, alert, path_hops, path_nodes)
            queue.append((parent, new, path_hops, path_nodes))
    return [found[alert_id] for alert_id in sorted(found)]


def _finding(
    parent: Node, alert: Mapping[str, Any], hops: list[list[Edge]], nodes: list[Node]
) -> dict[str, Any]:
    prefix = [
        _hop(nodes[index], nodes[index + 1], group[0]) for index, group in enumerate(hops[:-1])
    ]
    paths = [[*prefix, _hop(nodes[-2], parent, edge)] for edge in hops[-1]]
    unspecified = any(edge["relationship"] == UNSPECIFIED for group in hops for edge in group)
    return {
        "parent": parent,
        "parent_alert": {
            "alert_id": alert["alert_id"],
            "model_id": parent[0],
            "kind": alert["kind"],
            "cause_key": alert["cause_key"],
            "severity": alert["severity"],
            "state": alert["state"],
        },
        "reach": "direct" if len(hops) == 1 else "transitive",
        "paths": paths,
        "relationship_unspecified": unspecified,
    }


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

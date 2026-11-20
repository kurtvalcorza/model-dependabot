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
ruling on review R1); the walk is bounded (FR-022): each version is labelled at most once per
travelling kind. An imported (``unverified``) reference carries nothing (FR-010a).
"""

from __future__ import annotations

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


def _edge_key(edge: Edge) -> tuple[str, str, str]:
    return (str(edge["relationship"]), str(edge.get("origin")), str(edge.get("edge_id")))


# The most equally good paths one finding lists; beyond it the smallest by model versions are kept.
MAX_PATHS = 16

Label = tuple[bool, tuple[tuple[str, ...], ...]]


def inherited(
    child: Node,
    edges_of: Callable[[Node], Sequence[Edge]],
    alerts_of: Callable[[str], Sequence[Mapping[str, Any]]],
    entries_of: Callable[[Node], Sequence[Mapping[str, Any]]],
    exists: Exists,
) -> list[dict[str, Any]]:
    """The inherited findings of ``child``: one per parent alert per parent version (FR-018).

    A parent alert reaches the child when at least one path passes its kind on every hop (owner's
    ruling, review R1 to R3). For each travelling kind the walk is breadth first, layer by layer,
    over the hops that pass the kind. A parent version's best paths are its shortest qualifying
    ones, preferring among equal lengths those with no ``unspecified`` hop, then the smallest
    sequence of hop types (owner's ruling on review R2-1). Every path that ties on all three is
    listed, so the paths and the ``relationship_unspecified`` mark do not depend on how models
    are named; past ``MAX_PATHS`` the smallest by model versions are kept. The child is never a
    parent of itself, so a cycle back to it reports none of its own alerts, and the walk is
    bounded: each version is labelled at most once per travelling kind, and its edges, alerts and
    entries are read once.

    A child that reaches two versions of one parent gets a finding for each (data-model.md,
    Inherited finding; review R2-3). Each finding is ``{parent, parent_alert, reach, paths,
    relationship_unspecified}``; ``paths`` lists each best path once per edge of its last hop.
    """
    parents_cache: dict[Node, dict[Node, list[Edge]]] = {}
    candidates_cache: dict[Node, list[Mapping[str, Any]]] = {}

    def parents(node: Node) -> dict[Node, list[Edge]]:
        if node not in parents_cache:
            grouped = _owner_parents(edges_of(node), exists)
            parents_cache[node] = {p: sorted(g, key=_edge_key) for p, g in grouped.items()}
        return parents_cache[node]

    found: dict[tuple[int, Node], dict[str, Any]] = {}
    for kind in sorted(kind for kind, types in TRAVELS.items() if types):
        # Per reached version: its best label and every (previous version, edges) achieving it.
        best: dict[Node, tuple[Label, list[tuple[Node, list[Edge]]]]] = {child: ((False, ()), [])}
        frontier = [child]
        while frontier:
            layer: dict[Node, tuple[Label, list[tuple[Node, list[Edge]]]]] = {}
            for node in frontier:
                (unspecified, types), _ = best[node]
                for parent, group in parents(node).items():
                    if parent in best:
                        continue  # reached by a shorter path, or the child itself
                    relationships = {edge["relationship"] for edge in group}
                    if not travels(kind, relationships):
                        continue
                    label = (
                        unspecified or UNSPECIFIED in relationships,
                        (*types, tuple(sorted(relationships))),
                    )
                    if parent not in layer or label < layer[parent][0]:
                        layer[parent] = (label, [(node, group)])
                    elif label == layer[parent][0]:
                        layer[parent][1].append((node, group))
            best.update(layer)
            frontier = sorted(layer)
        routes: dict[Node, list[tuple[tuple[Node, ...], tuple[list[Edge], ...]]]] = {
            child: [((child,), ())]
        }

        for node in sorted(best):
            if node == child:
                continue
            if node not in candidates_cache:
                entries = entries_of(node)
                candidates_cache[node] = candidates(alerts_of(node[0]), entries, node[1])
            for alert in candidates_cache[node]:
                if alert["kind"] == kind:
                    unspecified = best[node][0][0]
                    routes_to = _paths_to(node, best, routes)
                    found[(alert["alert_id"], node)] = _finding(node, alert, routes_to, unspecified)
    return [found[key] for key in sorted(found)]


Route = tuple[tuple[Node, ...], tuple[list[Edge], ...]]


def _paths_to(
    node: Node,
    best: Mapping[Node, tuple[Label, list[tuple[Node, list[Edge]]]]],
    routes: dict[Node, list[Route]],
) -> list[Route]:
    """Every best route from the child to ``node``, smallest first, at most ``MAX_PATHS``."""
    if node not in routes:
        listed = [
            ((*nodes, node), (*groups, group))
            for previous, group in best[node][1]
            for nodes, groups in _paths_to(previous, best, routes)
        ]
        routes[node] = sorted(listed, key=lambda route: route[0])[:MAX_PATHS]
    return routes[node]


def _finding(
    parent: Node,
    alert: Mapping[str, Any],
    routes: list[tuple[tuple[Node, ...], tuple[list[Edge], ...]]],
    unspecified: bool,
) -> dict[str, Any]:
    paths = []
    for nodes, groups in routes:
        prefix = [_hop(nodes[i], nodes[i + 1], group[0]) for i, group in enumerate(groups[:-1])]
        paths += [[*prefix, _hop(nodes[-2], parent, edge)] for edge in groups[-1]]
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
        "reach": "direct" if len(routes[0][1]) == 1 else "transitive",
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

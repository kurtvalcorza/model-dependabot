"""Reference resolution and lineage problems (FR-021, FR-021a, FR-022, research L8).

Pure functions of edge rows. The graph's nodes are model versions ``(model id, version)``; its arcs
are the registered-model edges whose reference resolves in the store at the time of the call, so a
reference that starts or stops resolving changes the next result with nothing written. Hub parents
are leaves. Problems:

- ``cycle``: a path of resolved references back to the same model version; each simple cycle is
  reported once, its members rotated to start at the smallest (id, version). A reference to another
  version of the same model id is an ordinary arc (US4 AS6).
- ``duplicate_parent``: an edge declared more than once (``declared_count`` above 1).
- ``ambiguous_relationship``: one parent identity under two or more types for one child version.
- ``parent_not_registered``: a registered-model reference that does not resolve.

The note ``merge_with_one_parent`` (one ``merged-from`` edge) is listed beside them, not counted.
None of these changes an exit code or stops a registration.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from model_dependabot.lineage.edges import Edge, Exists, parent_identity, parent_label, resolved

Node = tuple[str, int]
CYCLE = "cycle"
DUPLICATE_PARENT = "duplicate_parent"
AMBIGUOUS_RELATIONSHIP = "ambiguous_relationship"
PARENT_NOT_REGISTERED = "parent_not_registered"
MERGE_WITH_ONE_PARENT = "merge_with_one_parent"
PROBLEM_KINDS = (CYCLE, DUPLICATE_PARENT, AMBIGUOUS_RELATIONSHIP, PARENT_NOT_REGISTERED)
# Bounds for the cycle search, far above any real lineage (FR-022: bounded work).
MAX_CYCLES = 1000
MAX_STEPS = 200_000


def label(node: Node) -> str:
    return f"{node[0]}@{node[1]}"


def parent_node(edge: Edge, exists: Exists) -> Node | None:
    """The parent version a registered-model edge resolves to, if it resolves."""
    if not resolved(edge, exists):
        return None
    return (str(edge["parent_model_id"]), int(edge["parent_version"]))


def arcs(
    edges_by_version: Mapping[Node, Sequence[Edge]], exists: Exists
) -> dict[Node, dict[Node, list[Edge]]]:
    """Child version to parent version to the resolved edges between them."""
    graph: dict[Node, dict[Node, list[Edge]]] = {}
    for child, edges in edges_by_version.items():
        for edge in edges:
            parent = parent_node(edge, exists)
            if parent is not None:
                graph.setdefault(child, {}).setdefault(parent, []).append(edge)
    return graph


def cycles(graph: Mapping[Node, Mapping[Node, Any]]) -> list[list[Node]]:
    """Every simple cycle once, rotated to start at its smallest node (iterative search)."""
    found: list[list[Node]] = []
    steps = 0
    for start in sorted(graph):
        path = [start]
        on_path = {start}
        stack = [iter(sorted(graph.get(start, {})))]
        while stack:
            steps += 1
            if steps > MAX_STEPS:
                return found
            successor = next(stack[-1], None)
            if successor is None:
                stack.pop()
                on_path.discard(path.pop())
                continue
            if successor == start:
                found.append(list(path))
                if len(found) >= MAX_CYCLES:
                    return found
                continue
            if successor < start or successor in on_path:
                continue
            path.append(successor)
            on_path.add(successor)
            stack.append(iter(sorted(graph.get(successor, {}))))
    return found


def _edge_ids(edges: Iterable[Edge]) -> list[Any]:
    return [edge.get("edge_id", edge.get("position")) for edge in edges]


def version_problems(child: Node, edges: Sequence[Edge], exists: Exists) -> list[dict[str, Any]]:
    """The problems one version's own edges show: duplicates, ambiguity, unregistered parents."""
    problems: list[dict[str, Any]] = []
    for edge in edges:
        if int(edge.get("declared_count") or 1) > 1:
            problems.append(
                {
                    "kind": DUPLICATE_PARENT,
                    "models": [label(child)],
                    "edges": _edge_ids([edge]),
                    "detail": {
                        "parent": parent_label(edge),
                        "relationship": edge["relationship"],
                        "count": int(edge["declared_count"]),
                        "source_key": edge.get("source_key"),
                    },
                }
            )
    groups: dict[tuple[Any, ...], list[Edge]] = {}
    for edge in edges:
        parent = parent_identity(edge)
        if parent is not None:
            groups.setdefault(parent, []).append(edge)
    for group in groups.values():
        types = sorted({edge["relationship"] for edge in group})
        if len(types) > 1:
            problems.append(
                {
                    "kind": AMBIGUOUS_RELATIONSHIP,
                    "models": [label(child)],
                    "edges": _edge_ids(group),
                    "detail": {"parent": parent_label(group[0]), "relationships": types},
                }
            )
    for edge in edges:
        named = edge.get("parent_kind") == "model" and edge.get("parent_version") is not None
        if named and not resolved(edge, exists):
            problems.append(
                {
                    "kind": PARENT_NOT_REGISTERED,
                    "models": [label(child)],
                    "edges": _edge_ids([edge]),
                    "detail": {
                        "parent": parent_label(edge),
                        "source_key": edge.get("source_key"),
                    },
                }
            )
    return problems


def problems(
    edges_by_version: Mapping[Node, Sequence[Edge]],
    exists: Exists,
    versions: Iterable[Node] | None = None,
) -> list[dict[str, Any]]:
    """The lineage problems of ``versions`` (every version when ``None``), cycles first.

    A cycle is listed for a version when the version is on it.
    """
    wanted = set(edges_by_version) if versions is None else set(versions)
    graph = arcs(edges_by_version, exists)
    found: list[dict[str, Any]] = []
    for cycle in cycles(graph):
        if not wanted & set(cycle):
            continue
        hops = list(zip(cycle, [*cycle[1:], cycle[0]], strict=True))
        ids = [_edge_ids(graph[child][parent])[0] for child, parent in hops]
        found.append(
            {
                "kind": CYCLE,
                "models": [label(node) for node in cycle],
                "edges": ids,
                "detail": {"length": len(cycle)},
            }
        )
    for child in sorted(wanted):
        found += version_problems(child, edges_by_version.get(child, ()), exists)
    return found


def notes(edges_by_version: Mapping[Node, Sequence[Edge]], versions: Iterable[Node]) -> list[dict]:
    """Remarks that are not problems: a ``merged-from`` model with one parent (spec edge case)."""
    found = []
    for child in sorted(set(versions)):
        merged = [e for e in edges_by_version.get(child, ()) if e["relationship"] == "merged-from"]
        if len(merged) == 1:
            note = {"kind": MERGE_WITH_ONE_PARENT, "models": [label(child)]}
            found.append(note | {"edges": _edge_ids(merged)})
    return found


def _version_text(text: str) -> str:
    model_id, _, version = text.rpartition("@")
    return f"{model_id} v{version}"


def problem_text(problem: Mapping[str, Any]) -> str:
    """One problem for text output."""
    kind = problem["kind"]
    detail = problem.get("detail") or {}
    if kind == CYCLE:
        members = [_version_text(model) for model in problem["models"]]
        return f"cycle: {' -> '.join([*members, members[0]])}"
    if kind == DUPLICATE_PARENT:
        return (
            f"duplicate_parent: {detail['parent']} as {detail['relationship']}, declared"
            f" {detail['count']} times"
        )
    if kind == AMBIGUOUS_RELATIONSHIP:
        return f"ambiguous_relationship: {detail['parent']} as {', '.join(detail['relationships'])}"
    return f"{kind}: {detail.get('parent')} ({detail.get('source_key')})"


def note_text(note: Mapping[str, Any]) -> str:
    if note["kind"] == MERGE_WITH_ONE_PARENT:
        return "merge with one parent"
    return str(note["kind"])

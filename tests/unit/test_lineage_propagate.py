"""The bounded walk and the referenced version's own findings (T037, FR-018, FR-022, ruling C5)."""

from __future__ import annotations

from typing import Any

from model_dependabot.lineage import propagate
from model_dependabot.lineage.edges import new_edge

FILE = "sha256:" + "a" * 64
LATER = "sha256:" + "b" * 64


def ref(parent: str, relationship: str, version: int = 1, state: str = "owner") -> dict[str, Any]:
    edge = new_edge(
        parent_kind="model",
        parent_model_id=parent,
        parent_version=version,
        relationship=relationship,
        origin="manifest" if state == "owner" else "import",
        state=state,
        source_key="parents[0]",
    )
    edge["edge_id"] = f"{parent}/{relationship}"
    return edge


def alert(alert_id: int, kind: str, identifier: str, state: str = "open", **fields: Any) -> dict:
    return {
        "alert_id": alert_id,
        "kind": kind,
        "cause_key": f"{kind}:{identifier}",
        "cause": {"identifier": identifier},
        "severity": "HIGH",
        "state": state,
        "closed_by_version": None,
    } | fields


class World:
    def __init__(self) -> None:
        self.edges: dict[tuple[str, int], list[dict[str, Any]]] = {}
        self.alerts: dict[str, list[dict[str, Any]]] = {}
        self.entries: dict[tuple[str, int], list[dict[str, Any]]] = {}
        self.visits: list[tuple[str, int]] = []

    def version(self, model_id: str, version: int, edges=(), identifiers=()) -> None:
        self.edges[(model_id, version)] = list(edges)
        self.entries[(model_id, version)] = [
            {"kind": "weight_file", "identifier": identifier} for identifier in identifiers
        ]

    def edges_of(self, node: tuple[str, int]) -> list[dict[str, Any]]:
        self.visits.append(node)
        return self.edges.get(node, [])

    def run(self, child: tuple[str, int]) -> list[dict[str, Any]]:
        return propagate.inherited(
            child,
            self.edges_of,
            lambda model_id: self.alerts.get(model_id, []),
            lambda node: self.entries.get(node, []),
            lambda model_id, version: (model_id, version) in self.edges,
        )


def _ids(found: list[dict[str, Any]]) -> list[int]:
    return [finding["parent_alert"]["alert_id"] for finding in found]


def test_direct_and_transitive_reach_with_the_full_path() -> None:
    world = World()
    world.version("grand", 1, identifiers=[FILE])
    world.version("mid", 1, [ref("grand", "adapter-for")])
    world.version("child", 1, [ref("mid", "adapter-for")])
    world.alerts["grand"] = [alert(7, "weight_file_scan", FILE)]
    [mid] = world.run(("mid", 1))
    assert (mid["reach"], mid["paths"][0][0]["relationship"]) == ("direct", "adapter-for")
    [child] = world.run(("child", 1))
    assert child["reach"] == "transitive"
    assert [(hop["child"], hop["parent"]) for hop in child["paths"][0]] == [
        ("child@1", "mid@1"),
        ("mid@1", "grand@1"),
    ]
    assert propagate.entry_identifier(child) == f"model:grand@1/weight_file_scan:{FILE}"


def test_a_weight_finding_reaches_an_adapter_and_not_a_quantised_child() -> None:
    world = World()
    world.version("base", 1, identifiers=[FILE])
    world.version("adapter", 1, [ref("base", "adapter-for")])
    world.version("quantised", 1, [ref("base", "quantized-from")])
    world.alerts["base"] = [alert(1, "weight_file_scan", FILE)]
    assert _ids(world.run(("adapter", 1))) == [1]
    assert world.run(("quantised", 1)) == []


def test_two_edges_to_one_parent_are_one_direct_finding_by_the_intersection() -> None:
    world = World()
    world.version("base", 1, identifiers=[FILE])
    world.version("child", 1, [ref("base", "adapter-for"), ref("base", "fine-tuned-from")])
    world.alerts["base"] = [
        alert(1, "weight_file_scan", FILE),
        alert(2, "dataset_retracted", FILE),
    ]
    [finding] = world.run(("child", 1))
    assert (finding["parent_alert"]["alert_id"], finding["reach"]) == (2, "direct")
    assert len(finding["paths"]) == 2


def test_each_version_is_visited_once_on_a_diamond_and_on_a_cycle() -> None:
    world = World()
    world.version("top", 1, identifiers=[FILE])
    world.version("left", 1, [ref("top", "fine-tuned-from")])
    world.version("right", 1, [ref("top", "fine-tuned-from")])
    world.version("child", 1, [ref("left", "fine-tuned-from"), ref("right", "merged-from")])
    world.alerts["top"] = [alert(3, "licence_changed", FILE)]
    assert _ids(world.run(("child", 1))) == [3]
    assert sorted(world.visits) == sorted(set(world.visits))
    loop = World()
    loop.version("a", 1, [ref("b", "fine-tuned-from")], [FILE])
    loop.version("b", 1, [ref("a", "fine-tuned-from")], [FILE])
    loop.alerts["a"] = [alert(4, "licence_changed", FILE)]
    assert _ids(loop.run(("b", 1))) == [4]
    assert sorted(loop.visits) == [("a", 1), ("b", 1)]


def test_an_unverified_edge_carries_nothing() -> None:
    world = World()
    world.version("base", 1, identifiers=[FILE])
    world.version("child", 1, [ref("base", "fine-tuned-from", state="unverified")])
    world.alerts["base"] = [alert(1, "licence_changed", FILE)]
    assert world.run(("child", 1)) == []


def test_an_unspecified_edge_passes_only_all_four_kinds_and_is_marked() -> None:
    world = World()
    world.version("base", 1, identifiers=[FILE])
    world.version("child", 1, [ref("base", "unspecified")])
    world.alerts["base"] = [alert(1, "weight_file_scan", FILE), alert(2, "licence_changed", FILE)]
    [finding] = world.run(("child", 1))
    assert finding["parent_alert"]["alert_id"] == 2
    assert finding["relationship_unspecified"] is True


def test_relevance_is_decided_by_the_referenced_versions_own_inventory() -> None:
    world = World()
    world.version("base", 1, identifiers=[FILE])
    world.version("base", 2, identifiers=[LATER])
    world.version("base", 3, identifiers=[FILE, LATER])
    world.version("child", 1, [ref("base", "adapter-for", version=1)])
    world.alerts["base"] = [
        alert(1, "weight_file_scan", FILE, state="fixed", closed_by_version=2),
        alert(2, "weight_file_scan", LATER),
        alert(3, "dataset_retracted", FILE, opened_in_version=3),
        alert(4, "licence_changed", FILE, state="dismissed"),
        alert(5, "dataset_removed", FILE, state="cleared"),
        alert(6, "dataset_not_findable", FILE, state="withdrawn"),
        alert(8, "paper_retracted", FILE, state="fixed", closed_by_version=1),
    ]
    assert _ids(world.run(("child", 1))) == [1, 3]

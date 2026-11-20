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


# --- review round 1: per-path travel (owner's ruling on R1 to R3) -------------------------------


def _diamond(first: str, second: str) -> World:
    """child -adapter-> first -fine-tuned-> grand, and child -adapter-> second -adapter-> grand."""
    world = World()
    world.version("grand", 1, identifiers=[FILE])
    world.version(first, 1, [ref("grand", "fine-tuned-from")])
    world.version(second, 1, [ref("grand", "adapter-for")])
    world.version("child", 1, [ref(first, "adapter-for"), ref(second, "adapter-for")])
    world.alerts["grand"] = [alert(7, "weight_file_scan", FILE)]
    return world


def test_a_diamond_gives_the_same_result_whichever_branch_sorts_first() -> None:
    """R1: the all-adapter branch carries the weight finding, in both namings."""
    assert _ids(_diamond("a", "b").run(("child", 1))) == [7]
    assert _ids(_diamond("z", "b").run(("child", 1))) == [7]
    [finding] = _diamond("a", "b").run(("child", 1))
    assert [hop["relationship"] for hop in finding["paths"][0]] == ["adapter-for", "adapter-for"]
    assert finding["reach"] == "transitive"


def test_a_chain_with_one_non_travelling_hop_carries_nothing_in_either_order() -> None:
    """R2: a weight finding needs adapter-for on every hop."""
    for lower, upper in (("fine-tuned-from", "adapter-for"), ("adapter-for", "fine-tuned-from")):
        world = World()
        world.version("grand", 1, identifiers=[FILE])
        world.version("mid", 1, [ref("grand", upper)])
        world.version("child", 1, [ref("mid", lower)])
        world.alerts["grand"] = [
            alert(1, "weight_file_scan", FILE),
            alert(2, "dataset_retracted", FILE),
        ]
        assert _ids(world.run(("child", 1))) == [2], (lower, upper)


def test_two_registered_parents_both_pass_their_findings_down() -> None:
    """R3: every parent is walked, not only the first."""
    world = World()
    world.version("left", 1, identifiers=[FILE])
    world.version("right", 1, identifiers=[LATER])
    world.version("child", 1, [ref("left", "merged-from"), ref("right", "merged-from")])
    world.alerts["left"] = [alert(11, "licence_changed", FILE)]
    world.alerts["right"] = [alert(12, "dataset_removed", LATER)]
    found = world.run(("child", 1))
    assert _ids(found) == [11, 12]
    assert {f["parent"] for f in found} == {("left", 1), ("right", 1)}
    assert {f["reach"] for f in found} == {"direct"}


# --- review round 2 (owner's rulings on R2-1, R2-3 and R2-4) ------------------------------------


def test_two_versions_of_one_parent_each_get_their_own_finding() -> None:
    """R2-3: one inherited finding per parent version (data-model.md, Inherited finding)."""
    world = World()
    world.version("p", 1, identifiers=[FILE])
    world.version("p", 2, identifiers=[FILE])
    world.version("q", 1, [ref("p", "fine-tuned-from", version=1)])
    world.version("child", 1, [ref("p", "fine-tuned-from", version=2), ref("q", "fine-tuned-from")])
    world.alerts["p"] = [alert(5, "dataset_retracted", FILE)]
    found = world.run(("child", 1))
    assert [(f["parent"], f["reach"]) for f in found] == [
        (("p", 1), "transitive"),
        (("p", 2), "direct"),
    ]
    assert len({propagate.entry_identifier(f) for f in found}) == 2


def _typed_or_not(typed: str, untyped: str) -> World:
    """Two equal-length paths to grand: one fully typed, one with an unspecified hop."""
    world = World()
    world.version("grand", 1, identifiers=[FILE])
    world.version(typed, 1, [ref("grand", "fine-tuned-from")])
    world.version(untyped, 1, [ref("grand", "unspecified")])
    world.version("child", 1, [ref(typed, "merged-from"), ref(untyped, "merged-from")])
    world.alerts["grand"] = [alert(9, "licence_changed", FILE)]
    return world


def test_a_fully_typed_path_is_preferred_whichever_name_sorts_first() -> None:
    """R2-1: the reported path and its unspecified mark do not depend on id order."""
    for typed, untyped in (("a", "b"), ("b", "a")):
        [finding] = _typed_or_not(typed, untyped).run(("child", 1))
        assert finding["relationship_unspecified"] is False, (typed, untyped)
        assert [hop["parent"] for hop in finding["paths"][0]] == [f"{typed}@1", "grand@1"]
        assert [hop["relationship"] for hop in finding["paths"][0]] == [
            "merged-from",
            "fine-tuned-from",
        ]


def test_the_shortest_qualifying_path_is_reported() -> None:
    """R2-4 (N5): a direct edge wins over a longer route to the same parent."""
    world = World()
    world.version("grand", 1, identifiers=[FILE])
    world.version("mid", 1, [ref("grand", "fine-tuned-from")])
    world.version("child", 1, [ref("mid", "fine-tuned-from"), ref("grand", "merged-from")])
    world.alerts["grand"] = [alert(3, "dataset_retracted", FILE)]
    [finding] = [f for f in world.run(("child", 1)) if f["parent"] == ("grand", 1)]
    assert finding["reach"] == "direct"
    assert [hop["relationship"] for hop in finding["paths"][0]] == ["merged-from"]


def test_a_cycle_back_to_the_child_never_reports_its_own_alert() -> None:
    """R2-4 (N8): the child is not its own parent."""
    world = World()
    world.version("child", 1, [ref("p", "fine-tuned-from")], [FILE])
    world.version("p", 1, [ref("child", "fine-tuned-from")], [LATER])
    world.alerts["child"] = [alert(1, "dataset_retracted", FILE)]
    world.alerts["p"] = [alert(2, "dataset_retracted", LATER)]
    assert [(f["parent"], f["parent_alert"]["alert_id"]) for f in world.run(("child", 1))] == [
        (("p", 1), 2)
    ]


def test_an_unspecified_lower_hop_marks_a_transitive_finding() -> None:
    """R2-4 (N9): the mark covers every hop of the path, not only the last."""
    world = World()
    world.version("grand", 1, identifiers=[FILE])
    world.version("mid", 1, [ref("grand", "fine-tuned-from")])
    world.version("child", 1, [ref("mid", "unspecified")])
    world.alerts["grand"] = [alert(4, "dataset_retracted", FILE)]
    [finding] = world.run(("child", 1))
    assert (finding["reach"], finding["relationship_unspecified"]) == ("transitive", True)


def test_equally_good_paths_are_all_listed_whatever_the_names() -> None:
    """R2-1: a tie on length, mark and types lists every tied path, so naming cannot pick one."""
    for left, right in (("a", "b"), ("z", "b")):
        world = World()
        world.version("grand", 1, identifiers=[FILE])
        world.version(left, 1, [ref("grand", "fine-tuned-from")])
        world.version(right, 1, [ref("grand", "fine-tuned-from")])
        world.version("child", 1, [ref(left, "merged-from"), ref(right, "merged-from")])
        world.alerts["grand"] = [alert(6, "licence_changed", FILE)]
        [finding] = world.run(("child", 1))
        middles = sorted(path[0]["parent"] for path in finding["paths"])
        assert middles == sorted([f"{left}@1", f"{right}@1"])

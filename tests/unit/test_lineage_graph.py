"""Lineage problems (T032, SC-005, FR-021, FR-021a, FR-022, research L8)."""

from __future__ import annotations

from typing import Any

from model_dependabot.lineage import graph
from model_dependabot.lineage.edges import new_edge

A = "0123456789abcdef0123456789abcdef01234567"


def ref(child: str, parent: str, version: int = 1, relationship: str = "fine-tuned-from", **f: Any):
    edge = new_edge(
        parent_kind="model",
        parent_model_id=parent,
        parent_version=version,
        relationship=relationship,
        origin="manifest",
        state="owner",
        source_key="parents[0]",
        **f,
    )
    edge["edge_id"] = f"{child}->{parent}@{version}/{relationship}"
    return edge


def hub(relationship: str, **fields: Any) -> dict[str, Any]:
    edge = new_edge(
        parent_kind="hub",
        parent_repo="example-org/base-a",
        parent_revision=A,
        relationship=relationship,
        origin="manifest",
        state="owner",
        source_key="parents[0]",
        **fields,
    )
    edge["edge_id"] = relationship
    return edge


def exists_in(store: dict[tuple[str, int], Any]):
    return lambda model_id, version: (model_id, version) in store


def kinds(found: list[dict[str, Any]]) -> list[str]:
    return [problem["kind"] for problem in found]


def test_cycles_of_length_one_two_and_three_are_each_reported_once_in_path_order() -> None:
    edges = {
        ("self", 1): [ref("self", "self")],
        ("a", 1): [ref("a", "b")],
        ("b", 1): [ref("b", "a"), ref("b", "c", relationship="merged-from")],
        ("c", 1): [ref("c", "a")],
    }
    found = graph.problems(edges, exists_in(edges))
    cycles = [p["models"] for p in found if p["kind"] == "cycle"]
    assert sorted(cycles) == [["a@1", "b@1"], ["a@1", "b@1", "c@1"], ["self@1"]]
    assert kinds(found) == ["cycle"] * 3
    [two] = [p for p in found if p["models"] == ["a@1", "b@1"]]
    assert two["edges"] == ["a->b@1/fine-tuned-from", "b->a@1/fine-tuned-from"]
    assert graph.problem_text(two) == "cycle: a v1 -> b v1 -> a v1"


def test_a_cycle_is_listed_only_for_versions_on_it() -> None:
    edges = {("a", 1): [ref("a", "b")], ("b", 1): [ref("b", "a")], ("d", 1): [ref("d", "a")]}
    assert graph.problems(edges, exists_in(edges), [("d", 1)]) == []
    assert kinds(graph.problems(edges, exists_in(edges), [("b", 1)])) == ["cycle"]


def test_duplicate_ambiguous_and_unregistered_are_each_reported_once() -> None:
    edges = {
        ("dup", 1): [hub("fine-tuned-from", declared_count=2)],
        ("amb", 1): [hub("fine-tuned-from"), hub("quantized-from")],
        ("orphan", 1): [ref("orphan", "missing", 2)],
    }
    found = graph.problems(edges, exists_in(edges))
    assert sorted(kinds(found)) == [
        "ambiguous_relationship",
        "duplicate_parent",
        "parent_not_registered",
    ]
    [ambiguous] = [p for p in found if p["kind"] == "ambiguous_relationship"]
    assert ambiguous["detail"]["relationships"] == ["fine-tuned-from", "quantized-from"]
    [duplicate] = [p for p in found if p["kind"] == "duplicate_parent"]
    assert duplicate["detail"]["count"] == 2


def test_version_2_referencing_version_1_of_the_same_model_is_not_a_cycle() -> None:
    edges = {("cont", 1): [], ("cont", 2): [ref("cont", "cont", 1)]}
    assert graph.problems(edges, exists_in(edges)) == []


def test_a_reference_resolves_once_its_parent_registers_and_stops_when_it_does_not() -> None:
    edges: dict[tuple[str, int], Any] = {("child", 1): [ref("child", "parent")]}
    assert kinds(graph.problems(edges, exists_in(edges))) == ["parent_not_registered"]
    later = edges | {("parent", 1): []}
    assert graph.problems(later, exists_in(later)) == []
    assert kinds(graph.problems(later, exists_in(edges))) == ["parent_not_registered"]


def test_unidentified_edges_are_never_duplicates_or_ambiguous() -> None:
    gaps = [
        new_edge(
            parent_kind="hub",
            relationship="unspecified",
            origin="import",
            state="unverified",
            source_key=f"ancestors[{i}]",
            gap_reason="no Hugging Face purl",
        )
        for i in range(2)
    ]
    assert graph.problems({("imp", 1): gaps}, lambda *_: True) == []


def test_a_merge_with_one_parent_is_a_note_not_a_problem() -> None:
    edges = {("m", 1): [hub("merged-from")]}
    assert graph.problems(edges, exists_in(edges)) == []
    [note] = graph.notes(edges, [("m", 1)])
    assert graph.note_text(note) == "merge with one parent"

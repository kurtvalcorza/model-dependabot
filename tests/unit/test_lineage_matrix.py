"""The closed relevance matrix, cell by cell (T036, SC-004, FR-017, FR-019)."""

from __future__ import annotations

import pytest

from model_dependabot.lineage import RELATIONSHIPS
from model_dependabot.lineage.propagate import TRAVELS, travels
from model_dependabot.store import ALERT_KINDS, WATCH_KINDS

ALL = set(RELATIONSHIPS)
WEIGHTS = {"adapter-for"}
EXPECTED = {
    "package_advisory": set(),
    "weight_file_scan": WEIGHTS,
    "hub_scan": WEIGHTS,
    "format_policy": WEIGHTS,
    "globals_policy": WEIGHTS,
    "dataset_retracted": ALL,
    "paper_retracted": ALL,
    "dataset_removed": ALL,
    "dataset_not_findable": ALL,
    "licence_changed": ALL,
    "base_model_disabled": ALL,
    "base_model_unavailable": ALL,
}


def test_the_matrix_is_exactly_the_specification_and_names_only_alert_kinds() -> None:
    assert {kind: set(types) for kind, types in TRAVELS.items()} == EXPECTED
    assert set(TRAVELS) <= set(ALERT_KINDS)


@pytest.mark.parametrize("kind", sorted(EXPECTED))
@pytest.mark.parametrize("relationship", RELATIONSHIPS)
def test_each_cell_travels_as_the_matrix_says(kind: str, relationship: str) -> None:
    assert travels(kind, {relationship}) is (relationship in EXPECTED[kind])


@pytest.mark.parametrize("kind", sorted(EXPECTED))
def test_unspecified_passes_only_the_kinds_that_travel_on_all_four(kind: str) -> None:
    assert travels(kind, {"unspecified"}) is (EXPECTED[kind] == ALL)


@pytest.mark.parametrize("kind", sorted(EXPECTED))
def test_an_ambiguous_pair_passes_the_intersection(kind: str) -> None:
    pair = {"adapter-for", "quantized-from"}
    assert travels(kind, pair) is (pair <= EXPECTED[kind])


def test_a_kind_absent_from_the_matrix_and_every_watch_kind_travel_on_none() -> None:
    for kind in ("future_kind", *WATCH_KINDS):
        assert not any(travels(kind, {relationship}) for relationship in RELATIONSHIPS)
        assert not travels(kind, {"unspecified"})

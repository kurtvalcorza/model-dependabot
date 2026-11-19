"""Which parent alerts belong to the version a child names, across revisions (review R4, ruling C5).

``candidates`` decides it with the public helpers of ``upstream.scope``: by entry identifier, or for
a repository-scoped cause by an entry of the referenced version in that repository, at any revision.
"""

from __future__ import annotations

from typing import Any

import pytest

from model_dependabot.lineage.propagate import TRAVELS, candidates
from model_dependabot.upstream import scope

A = "a" * 40
B = "b" * 40
BASE_A = f"pkg:huggingface/example-org/base@{A}"
BASE_B = f"pkg:huggingface/example-org/base@{B}"
DATA_A = f"hf-dataset:example-org/data@{A}"
DATA_B = f"hf-dataset:example-org/data@{B}"
FILE = "sha256:" + "c" * 64
DOI = "10.5555/example"


def alert(kind: str, cause: dict[str, Any], alert_id: int = 1) -> dict[str, Any]:
    return {"alert_id": alert_id, "kind": kind, "cause": cause, "state": "open"}


# The parent version the child names (v1) pins revision A of the base model and hub dataset.
V1 = [
    {"kind": "base_model", "identifier": BASE_A, "name": "example-org/base", "pinned": True},
    {"kind": "dataset", "identifier": DATA_A, "hub_repo": "example-org/data", "pinned": True},
    {"kind": "dataset", "identifier": DOI, "pinned": True},
    {"kind": "weight_file", "identifier": FILE, "pinned": True},
]


@pytest.mark.parametrize(
    ("kind", "cause"),
    [
        (
            "base_model_disabled",
            {"identifier": BASE_B, "base_model": BASE_B, "repo": "example-org/base"},
        ),
        (
            "base_model_unavailable",
            {"identifier": BASE_B, "base_model": BASE_B, "repo": "example-org/base"},
        ),
        ("dataset_removed", {"identifier": DATA_B, "dataset": DATA_B, "host": "huggingface"}),
        ("licence_changed", {"identifier": BASE_B, "item": BASE_B}),
        ("licence_changed", {"identifier": DATA_B, "item": DATA_B}),
    ],
)
def test_a_repository_alert_raised_on_revision_b_belongs_to_a_version_pinning_a(
    kind: str, cause: dict[str, Any]
) -> None:
    assert candidates([alert(kind, cause)], V1, 1) != []
    assert candidates([alert(kind, cause)], V1[2:], 1) == []  # not in that repository


@pytest.mark.parametrize(
    ("kind", "cause"),
    [
        ("dataset_retracted", {"identifier": "10.5555/other", "dataset": "10.5555/other"}),
        ("dataset_removed", {"identifier": DATA_B, "dataset": DATA_B, "host": "zenodo"}),
        ("weight_file_scan", {"identifier": "sha256:" + "d" * 64, "location": "w.pt"}),
    ],
)
def test_an_item_scoped_alert_on_another_item_does_not_belong(
    kind: str, cause: dict[str, Any]
) -> None:
    assert candidates([alert(kind, cause)], V1, 1) == []


# One cause as the check writes it for every kind the matrix lets travel.
SHAPES = {
    "weight_file_scan": {"identifier": FILE, "location": "w.pt"},
    "hub_scan": {"identifier": FILE, "location": "w.pt"},
    "format_policy": {"identifier": FILE, "location": "w.pt"},
    "globals_policy": {"identifier": FILE, "location": "w.pt"},
    "dataset_retracted": {"identifier": DOI, "dataset": DOI},
    "paper_retracted": {"identifier": DOI, "dataset": DOI, "paper_doi": "10.5555/paper"},
    "dataset_removed": {"identifier": DATA_A, "dataset": DATA_A, "host": "huggingface"},
    "dataset_not_findable": {"identifier": DOI, "dataset": DOI},
    "licence_changed": {"identifier": BASE_A, "item": BASE_A},
    "base_model_disabled": {"identifier": BASE_A, "base_model": BASE_A, "repo": "example-org/base"},
    "base_model_unavailable": {
        "identifier": BASE_A,
        "base_model": BASE_A,
        "repo": "example-org/base",
    },
}


def test_every_travelling_kind_has_a_cause_shape_candidates_recognises() -> None:
    travelling = {kind for kind, types in TRAVELS.items() if types}
    assert set(SHAPES) == travelling
    for kind, cause in SHAPES.items():
        assert candidates([alert(kind, cause)], V1, 1) != [], kind
        assert scope.in_inventory(kind, cause, V1), kind

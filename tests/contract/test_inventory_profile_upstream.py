"""Inventory profile additions: licences, paper ties and hub datasets (tasks T013)."""

from __future__ import annotations

import copy
from typing import Any

import pytest

from model_dependabot.inventory.build import new_entry
from model_dependabot.inventory.cyclonedx import export_bom, import_bom, validate

COMMIT = "0123abcd" * 5
BASE = "df939e66" * 5


def _entries() -> list[dict[str, Any]]:
    return [
        new_entry(
            "base_model",
            identifier=f"pkg:huggingface/owner/base@{BASE}",
            pinned=True,
            name="owner/base",
            version=BASE,
            recorded_licence="Apache-2.0",
            licence_form="spdx",
        ),
        new_entry(
            "dataset",
            identifier="10.5281/zenodo.3242074",
            pinned=True,
            paper_dois=["10.1177/1758835919874651"],
            recorded_licence="MIT OR Apache-2.0",
            licence_form="expression",
        ),
        new_entry(
            "dataset",
            identifier=f"hf-dataset:owner/name@{COMMIT}",
            pinned=True,
            hub_repo="owner/name",
            hub_revision=COMMIT,
            recorded_licence="llama3.1",
            licence_form="unrecognised",
        ),
        new_entry("dataset", pinned=False, gap_reason="no revision", hub_repo="owner/other"),
    ]


@pytest.fixture
def bom() -> dict[str, Any]:
    return export_bom("m", 1, _entries())


def _component(bom: dict[str, Any], ref: str) -> dict[str, Any]:
    return next(item for item in bom["components"] if item["bom-ref"] == ref)


def test_licences_use_the_standard_forms(bom: dict[str, Any]) -> None:
    ancestor = bom["metadata"]["component"]["pedigree"]["ancestors"][0]
    assert ancestor["licenses"] == [{"license": {"id": "Apache-2.0"}}]
    doi = _component(bom, "doi:10.5281/zenodo.3242074")
    assert doi["licenses"] == [{"expression": "MIT OR Apache-2.0"}]
    hub = _component(bom, f"hf-dataset:owner/name@{COMMIT}")
    assert hub["licenses"] == [{"license": {"name": "llama3.1"}}]


def test_a_paper_tie_is_a_citation_reference(bom: dict[str, Any]) -> None:
    doi = _component(bom, "doi:10.5281/zenodo.3242074")
    citation = {"type": "citation", "url": "https://doi.org/10.1177/1758835919874651"}
    assert citation in doi["externalReferences"]


def test_a_hub_dataset_is_a_data_component_with_a_distribution(bom: dict[str, Any]) -> None:
    ref = f"hf-dataset:owner/name@{COMMIT}"
    hub = _component(bom, ref)
    assert hub["type"] == "data"
    assert hub["data"][0]["type"] == "dataset"
    assert hub["externalReferences"] == [
        {"type": "distribution", "url": "https://huggingface.co/datasets/owner/name"}
    ]
    datasets = bom["metadata"]["component"]["modelCard"]["modelParameters"]["datasets"]
    assert {"ref": ref} in datasets


def test_the_export_validates(bom: dict[str, Any]) -> None:
    validate(bom)


def test_export_then_import_keeps_licences_paper_ties_and_hub_datasets() -> None:
    entries = _entries()
    imported = import_bom(export_bom("m", 1, entries))
    by_id = {entry["identifier"]: entry for entry in imported}
    for original in entries[:3]:
        back = by_id[original["identifier"]]
        for key in ("recorded_licence", "licence_form", "paper_dois", "hub_repo", "hub_revision"):
            assert back[key] == original[key], key
    gap = next(entry for entry in imported if entry["identifier"] is None)
    assert (gap["gap_reason"], gap["hub_repo"]) == ("no revision", "owner/other")


def test_an_inventory_without_licences_is_valid(bom: dict[str, Any]) -> None:
    document = copy.deepcopy(bom)
    for component in document["components"]:
        component.pop("licenses", None)
    for ancestor in document["metadata"]["component"]["pedigree"]["ancestors"]:
        ancestor.pop("licenses", None)
    validate(document)
    for entry in import_bom(document):
        assert entry["recorded_licence"] is None
        assert entry["licence_form"] is None

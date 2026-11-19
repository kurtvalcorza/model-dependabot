"""Resolving the affected entry and its relationship (T013, FR-005, FR-006, research R2)."""

from __future__ import annotations

from typing import Any

import pytest

from model_dependabot.assurance.affected import (
    NO_HOLDER,
    NO_IDENTIFIER,
    NO_VERSION,
    relationship,
    resolve_entry,
)

PICKLE = "sha256:" + "a1" * 32
PILLOW = "pkg:pypi/pillow@12.3.0"
GPT2 = "openai-community/gpt2"
GPT2_PURL = f"pkg:huggingface/{GPT2}@{'1' * 40}"
DOI = "10.5281/zenodo.3242074"
PAPER = "10.1177/1758835919874651"
HUB = "hf-dataset:yavon/muxue@" + "0" * 40

LOCAL = {"kind": "weight_file", "identifier": PICKLE, "location": "weights/model.pkl"}
HUB_FILE = {
    "kind": "weight_file",
    "identifier": "sha256:" + "f9" * 32,
    "location": None,
    "hub_repo": "owner/repo",
    "hub_file": "pytorch_model.bin",
    "hub_revision": "c" * 40,
}
PACKAGE = {"kind": "package", "identifier": PILLOW, "name": "Pillow", "version": "12.3.0"}
OTHER_PILLOW = PACKAGE | {"identifier": "pkg:pypi/pillow@12.2.0", "version": "12.2.0"}
BASE = {"kind": "base_model", "identifier": GPT2_PURL, "name": GPT2, "version": "1" * 40}
DATASET = {"kind": "dataset", "identifier": DOI, "paper_dois": [PAPER]}
HUB_DATASET = {
    "kind": "dataset",
    "identifier": HUB,
    "hub_repo": "yavon/muxue",
    "hub_revision": "0" * 40,
    "paper_dois": [PAPER],
}


def alert(kind: str, cause: dict[str, Any], **fields: Any) -> dict[str, Any]:
    return {
        "alert_id": 1,
        "model_id": "m",
        "kind": kind,
        "cause": cause,
        "state": "open",
        "opened_in_version": 1,
        "closed_by_version": None,
        **fields,
    }


def versions(*entries_by_version: list[dict[str, Any]], origin: str = "manifest") -> dict:
    return {
        number: {"origin": origin, "entries": entries}
        for number, entries in enumerate(entries_by_version, start=1)
    }


@pytest.mark.parametrize(
    ("kind", "cause", "entry"),
    [
        ("weight_file_scan", {"identifier": PICKLE}, LOCAL),
        ("hub_scan", {"identifier": HUB_FILE["identifier"]}, HUB_FILE),
        ("format_policy", {"identifier": PICKLE}, LOCAL),
        ("globals_policy", {"identifier": PICKLE}, LOCAL),
        (
            "package_advisory",
            {"identifier": PILLOW, "package": "pillow", "version": "12.3.0"},
            PACKAGE,
        ),
        ("dataset_retracted", {"identifier": DOI, "dataset": DOI}, DATASET),
        ("dataset_not_findable", {"identifier": DOI, "dataset": DOI}, DATASET),
        ("paper_retracted", {"identifier": DOI, "dataset": DOI, "paper_doi": PAPER}, DATASET),
        ("licence_changed", {"identifier": DOI, "item": DOI}, DATASET),
    ],
)
def test_each_match_rule_finds_its_entry(kind: str, cause: dict, entry: dict) -> None:
    found = resolve_entry(alert(kind, cause), versions([OTHER_PILLOW, entry]))
    assert found["status"] == "resolved"
    assert (found["kind"], found["matched_by"]) == (entry["kind"], "identifier")
    assert found["in_current_version"] is True
    assert len(found["places"]) == 1


def test_a_package_alert_never_matches_another_pinned_version() -> None:
    cause = {"identifier": PILLOW, "package": "pillow", "version": "12.3.0"}
    found = resolve_entry(alert("package_advisory", cause), versions([OTHER_PILLOW]))
    assert (found["status"], found["reason"]) == ("unresolved", NO_HOLDER)


@pytest.mark.parametrize(
    ("kind", "cause", "entry"),
    [
        ("base_model_disabled", {"identifier": "pkg:huggingface/x@0", "repo": GPT2}, BASE),
        ("base_model_unavailable", {"identifier": "pkg:huggingface/x@0", "repo": GPT2}, BASE),
        ("licence_changed", {"identifier": f"pkg:huggingface/{GPT2}@{'9' * 40}"}, BASE),
        (
            "dataset_removed",
            {
                "identifier": "hf-dataset:yavon/muxue@" + "9" * 40,
                "repo": "yavon/muxue",
                "host": "huggingface",
            },
            HUB_DATASET,
        ),
        (
            "paper_retracted",
            {"identifier": "hf-dataset:yavon/muxue@" + "9" * 40, "paper_doi": PAPER},
            HUB_DATASET,
        ),
    ],
)
def test_a_repository_keyed_alert_resolves_whatever_revision_is_pinned(
    kind: str, cause: dict, entry: dict
) -> None:
    found = resolve_entry(alert(kind, cause), versions([entry]))
    assert (found["status"], found["matched_by"]) == ("resolved", "repository")


def test_a_paper_match_always_requires_the_paper() -> None:
    cause = {"identifier": DOI, "dataset": DOI, "paper_doi": "10.1/other"}
    found = resolve_entry(alert("paper_retracted", cause), versions([DATASET]))
    assert found["status"] == "unresolved"
    hub = {"identifier": "hf-dataset:yavon/muxue@" + "9" * 40, "paper_doi": "10.1/other"}
    assert resolve_entry(alert("paper_retracted", hub), versions([HUB_DATASET]))["status"] == (
        "unresolved"
    )


def test_unresolved_reasons_and_no_match_by_name_or_prefix() -> None:
    near = {"identifier": PICKLE[:-2] + "ff"}
    assert resolve_entry(alert("weight_file_scan", near), versions([LOCAL]))["reason"] == NO_HOLDER
    named = {"identifier": "pkg:pypi/pillo@12.3.0", "package": "pillo", "version": "12.3.0"}
    assert resolve_entry(alert("package_advisory", named), versions([PACKAGE]))["reason"] == (
        NO_HOLDER
    )
    assert resolve_entry(alert("weight_file_scan", {}), versions([LOCAL]))["reason"] == (
        NO_IDENTIFIER
    )
    assert resolve_entry(alert("weight_file_scan", {"identifier": PICKLE}), {})["reason"] == (
        NO_VERSION
    )
    found = resolve_entry(alert("weight_file_scan", near), versions([LOCAL]))
    assert (
        found["places"] == []
        and found["kind"] is None
        and found["identifier"] == near["identifier"]
    )


def test_places_are_version_descending_then_entry_order() -> None:
    again = LOCAL | {"location": "weights/copy.pkl"}
    found = resolve_entry(
        alert("weight_file_scan", {"identifier": PICKLE}), versions([LOCAL], [LOCAL, again])
    )
    assert [(p["version"], p["location"]) for p in found["places"]] == [
        (2, "weights/model.pkl"),
        (2, "weights/copy.pkl"),
        (1, "weights/model.pkl"),
    ]
    assert all("entry_id" not in place for place in found["places"])


def test_a_fixed_alert_names_the_last_holder_and_the_fixing_version() -> None:
    fixed = alert("weight_file_scan", {"identifier": PICKLE}, state="fixed", closed_by_version=3)
    found = resolve_entry(fixed, versions([LOCAL], [LOCAL], []))
    assert found["in_current_version"] is False
    assert (found["last_held_in_version"], found["closed_by_version"]) == (2, 3)


def test_an_imported_version_has_no_section_and_is_declared_imported() -> None:
    held = versions([PACKAGE], origin="import")
    the_alert = alert(
        "package_advisory", {"identifier": PILLOW, "package": "pillow", "version": "12.3.0"}
    )
    found = resolve_entry(the_alert, held)
    assert found["places"][0]["section"] is None
    assert relationship(found, the_alert, found["places"])["basis"]["declared_by"] == "imported"


def test_a_hub_weight_file_location_and_sections() -> None:
    found = resolve_entry(
        alert("hub_scan", {"identifier": HUB_FILE["identifier"]}), versions([HUB_FILE])
    )
    place = found["places"][0]
    assert place["location"] == "hf:owner/repo/pytorch_model.bin"
    assert (place["section"], place["revision"]) == ("[[weights]]", "c" * 40)


def test_a_paper_alert_is_two_steps_from_the_model() -> None:
    the_alert = alert("paper_retracted", {"identifier": DOI, "dataset": DOI, "paper_doi": PAPER})
    found = resolve_entry(the_alert, versions([DATASET]))
    related = relationship(found, the_alert, found["places"])
    assert related["value"] == "paper cited by a declared dataset"
    assert related["steps_from_model"] == 2
    assert related["basis"] == {
        "declared_by": "owner",
        "origin": "manifest",
        "section": "[[datasets]]",
        "version": 1,
    }


def test_an_unresolved_entry_has_no_relationship() -> None:
    the_alert = alert("weight_file_scan", {"identifier": PICKLE})
    found = resolve_entry(the_alert, versions([]))
    assert relationship(found, the_alert, found["places"]) is None


def test_a_legacy_version_is_declared_legacy() -> None:
    the_alert = alert("weight_file_scan", {"identifier": PICKLE})
    found = resolve_entry(the_alert, {1: {"origin": None, "entries": [LOCAL]}})
    assert relationship(found, the_alert, found["places"])["basis"]["declared_by"] == "legacy"

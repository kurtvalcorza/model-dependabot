"""The CycloneDX 1.7 inventory profile (T016, contracts/inventory-profile.md, SC-005)."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import pytest
from jsonschema.exceptions import ValidationError
from referencing.exceptions import Unresolvable

from model_dependabot.inventory.build import build_entries
from model_dependabot.inventory.cyclonedx import (
    PROPERTIES,
    InventoryError,
    export_bom,
    import_bom,
    validate,
)
from model_dependabot.manifest import load_manifest
from model_dependabot.sources.fetcher import RecordedFetcher

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
EXAMPLE = FIXTURES / "manifests" / "example.toml"
COMMIT = "607a30d783dfa663caf39e06633721c8d4cfcd7e"
PREFIX = "model-dependabot:"


@pytest.fixture(scope="module")
def entries() -> list[dict[str, Any]]:
    return build_entries(load_manifest(EXAMPLE), fetcher=RecordedFetcher(FIXTURES / "hf"))


@pytest.fixture(scope="module")
def bom(entries: list[dict[str, Any]]) -> dict[str, Any]:
    return export_bom("example-detector", 3, entries)


def _props(item: dict[str, Any]) -> dict[str, str]:
    return {p["name"]: p["value"] for p in item.get("properties", [])}


def _all_properties(node: Any) -> list[str]:
    found: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "properties" and isinstance(value, list):
                found += [p["name"] for p in value if isinstance(p, dict) and "name" in p]
            else:
                found += _all_properties(value)
    elif isinstance(node, list):
        for value in node:
            found += _all_properties(value)
    return found


def test_the_property_set_is_exactly_the_documented_one() -> None:
    assert (
        frozenset(
            {
                PREFIX + name
                for name in (
                    "format",
                    "can-run-code",
                    "size",
                    "hub-repo",
                    "hub-revision",
                    "hub-file",
                    "gap",
                )
            }
        )
        == PROPERTIES
    )


def test_the_export_validates_against_the_vendored_schema(bom: dict[str, Any]) -> None:
    assert (bom["bomFormat"], bom["specVersion"]) == ("CycloneDX", "1.7")
    validate(bom)


def test_the_model_version_is_the_metadata_component(bom: dict[str, Any]) -> None:
    model = bom["metadata"]["component"]
    assert model["type"] == "machine-learning-model"
    assert model["version"] == "3"
    assert model["bom-ref"] == "model:example-detector@3"


def test_weight_files_are_file_components_with_sha256(
    bom: dict[str, Any], entries: list[dict[str, Any]]
) -> None:
    files = [c for c in bom["components"] if c["type"] == "file"]
    assert len(files) == len([e for e in entries if e["kind"] == "weight_file"])
    tiny = next(c for c in files if c["name"] == "weights/tiny.pt")
    (digest,) = tiny["hashes"]
    assert digest["alg"] == "SHA-256"
    expected = next(e for e in entries if e["location"] == "weights/tiny.pt")
    assert "sha256:" + digest["content"] == expected["identifier"]
    assert _props(tiny) == {
        PREFIX + "format": "pytorch-zip",
        PREFIX + "can-run-code": "true",
        PREFIX + "size": str(expected["size"]),
    }


def test_a_hub_weight_file_has_a_distribution_reference_and_hub_properties(
    bom: dict[str, Any],
) -> None:
    hub = next(c for c in bom["components"] if c["name"] == "model.safetensors")
    url = f"https://huggingface.co/openai-community/gpt2/resolve/{COMMIT}/model.safetensors"
    assert hub["externalReferences"] == [{"type": "distribution", "url": url}]
    props = _props(hub)
    assert props[PREFIX + "hub-repo"] == "openai-community/gpt2"
    assert props[PREFIX + "hub-revision"] == COMMIT
    assert props[PREFIX + "hub-file"] == "model.safetensors"
    assert props[PREFIX + "can-run-code"] == "false"


def test_packages_are_library_components_with_purl_and_lock_hashes(bom: dict[str, Any]) -> None:
    attrs = next(c for c in bom["components"] if c.get("purl") == "pkg:pypi/attrs@26.1.0")
    assert attrs["type"] == "library"
    assert (attrs["name"], attrs["version"]) == ("attrs", "26.1.0")
    assert [h["alg"] for h in attrs["hashes"]] == ["SHA-256", "SHA-256"]


def test_the_base_model_is_a_pedigree_ancestor_with_a_huggingface_purl(
    bom: dict[str, Any],
) -> None:
    (ancestor,) = bom["metadata"]["component"]["pedigree"]["ancestors"]
    assert ancestor["type"] == "machine-learning-model"
    assert ancestor["purl"] == f"pkg:huggingface/openai-community/gpt2@{COMMIT}"


def test_a_dataset_is_referenced_from_the_model_card_by_its_doi(bom: dict[str, Any]) -> None:
    doi = "10.5555/example-dataset-0001"
    datasets = bom["metadata"]["component"]["modelCard"]["modelParameters"]["datasets"]
    assert datasets == [{"ref": f"doi:{doi}"}]
    (data,) = [c for c in bom["components"] if c.get("bom-ref") == f"doi:{doi}"]
    assert data["type"] == "data"
    assert data["data"] == [{"type": "dataset", "name": doi}]
    assert data["externalReferences"] == [{"type": "distribution", "url": f"https://doi.org/{doi}"}]
    assert data["hashes"][0]["alg"] == "SHA-256"


def test_gaps_are_written_with_a_gap_property(bom: dict[str, Any]) -> None:
    gaps = [p for p in bom["components"] if PREFIX + "gap" in _props(p)]
    assert {_props(g)[PREFIX + "gap"] for g in gaps} == {"no revision", "no exact version"}


def test_only_documented_custom_properties_are_written(bom: dict[str, Any]) -> None:
    names = _all_properties(bom)
    assert names, "the export writes properties"
    assert set(names) <= PROPERTIES


def test_export_then_import_yields_the_same_entries(
    bom: dict[str, Any], entries: list[dict[str, Any]]
) -> None:
    assert import_bom(bom) == entries


def test_export_import_export_is_stable(bom: dict[str, Any]) -> None:
    again = export_bom("example-detector", 3, import_bom(bom))
    assert again == bom


@pytest.mark.parametrize("spec_version", ["1.5", "1.6"])
def test_older_cyclonedx_versions_import(
    bom: dict[str, Any], entries: list[dict[str, Any]], spec_version: str
) -> None:
    older = copy.deepcopy(bom)
    older["specVersion"] = spec_version
    older["$schema"] = f"http://cyclonedx.org/schema/bom-{spec_version}.schema.json"
    assert import_bom(older) == entries


def test_unreadable_entries_become_gaps() -> None:
    foreign = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {
            "component": {
                "type": "machine-learning-model",
                "name": "someone-elses-model",
                "pedigree": {"ancestors": [{"type": "machine-learning-model", "name": "x"}]},
                "modelCard": {
                    "modelParameters": {"datasets": [{"type": "dataset", "name": "inline"}]}
                },
            }
        },
        "components": [
            {"type": "library", "name": "requests"},
            {"type": "library", "name": "left-pad", "purl": "pkg:npm/left-pad@1.3.0"},
            {"type": "file", "name": "model.pt"},
            {"type": "application", "name": "some-app"},
        ],
    }
    imported = import_bom(foreign)
    assert all(entry["pinned"] is False and entry["gap_reason"] for entry in imported)
    kinds = sorted(entry["kind"] for entry in imported)
    assert kinds == ["base_model", "dataset", "package", "package", "package", "weight_file"]
    weight = next(e for e in imported if e["kind"] == "weight_file")
    assert (weight["location"], weight["format"], weight["can_run_code"]) == (
        "model.pt",
        "pickle",
        True,
    )


def test_an_inline_dataset_with_a_doi_url_is_read(bom: dict[str, Any]) -> None:
    doc = copy.deepcopy(bom)
    doc["metadata"]["component"]["modelCard"]["modelParameters"]["datasets"] = [
        {"type": "dataset", "name": "d", "contents": {"url": "https://doi.org/10.5555/Inline"}}
    ]
    doc["components"] = []
    (dataset,) = [e for e in import_bom(doc) if e["kind"] == "dataset"]
    assert (dataset["identifier"], dataset["pinned"]) == ("10.5555/inline", True)


@pytest.mark.parametrize(
    "doc",
    [
        {"bomFormat": "SPDX", "specVersion": "1.7"},
        {"bomFormat": "CycloneDX", "specVersion": "1.4"},
        {"bomFormat": "CycloneDX"},
        [],
    ],
)
def test_documents_that_are_not_cyclonedx_1_5_to_1_7_are_refused(doc: Any) -> None:
    with pytest.raises(InventoryError):
        import_bom(doc)


def test_an_invalid_export_fails_validation(bom: dict[str, Any]) -> None:
    broken = copy.deepcopy(bom)
    broken["components"][0]["hashes"] = [{"alg": "SHA-256", "content": "not-hex"}]
    with pytest.raises(ValidationError):
        validate(broken)


def test_validation_never_needs_the_unvendored_cryptography_schema(bom: dict[str, Any]) -> None:
    # A document that does reach cryptoProperties must fail loudly, which proves the registry has
    # only the vendored schemas; exports never use cryptoProperties, so they validate offline.
    crypto = copy.deepcopy(bom)
    crypto["components"].append(
        {
            "type": "cryptographic-asset",
            "name": "aes",
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": {"algorithmFamily": "AES"},
            },
        }
    )
    with pytest.raises(Unresolvable):
        validate(crypto)
    validate(bom)

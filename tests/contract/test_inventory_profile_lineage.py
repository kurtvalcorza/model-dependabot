"""Exported ancestors carry every edge (T025, contracts/cyclonedx-lineage.md, FR-010, FR-010a)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from lineage_support import manifest
from model_dependabot.inventory import cyclonedx
from model_dependabot.inventory.build import build_entries
from model_dependabot.inventory.cyclonedx import PROPERTIES, export_bom, validate
from model_dependabot.lineage.edges import edges_from_manifest
from model_dependabot.manifest import load_manifest
from model_dependabot.sources.fetcher import RecordedFetcher

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _export(path: Path | str, fetcher: Any = None) -> tuple[dict[str, Any], dict[str, Any]]:
    loaded = load_manifest(path)
    entries = build_entries(loaded, fetcher)
    edges = edges_from_manifest(
        loaded, origin="manifest", source_file="model.toml", source_sha256=loaded.sha256
    )
    for position, edge in enumerate(edges):
        edge["edge_id"] = position + 1
    legacy = export_bom(loaded.model_id, 1, entries)
    return legacy, export_bom(loaded.model_id, 1, entries, edges)


def _ancestors(document: dict[str, Any]) -> list[dict[str, Any]]:
    return document["metadata"]["component"].get("pedigree", {}).get("ancestors", [])


def _props(item: dict[str, Any]) -> dict[str, str]:
    return {prop["name"]: prop["value"] for prop in item.get("properties", [])}


def test_one_ancestor_per_edge_with_its_type_and_origin() -> None:
    _, document = _export(manifest("four-types"))
    validate(document)
    ancestors = _ancestors(document)
    assert [a["bom-ref"] for a in ancestors] == [f"base-model:{k}" for k in range(4)]
    assert [_props(a)["model-dependabot:relationship"] for a in ancestors] == [
        "fine-tuned-from",
        "merged-from",
        "quantized-from",
        "adapter-for",
    ]
    assert {_props(a)["model-dependabot:edge-origin"] for a in ancestors} == {"manifest"}
    registered = ancestors[3]
    assert "purl" not in registered
    assert (registered["type"], registered["name"]) == (
        "machine-learning-model",
        "example-adapter-base",
    )
    assert _props(registered)["model-dependabot:parent-model"] == "example-adapter-base"
    assert _props(registered)["model-dependabot:parent-version"] == "1"


def test_a_legacy_base_model_keeps_its_bom_ref_after_files_and_packages() -> None:
    fetcher = RecordedFetcher(FIXTURES / "hf")
    legacy, document = _export(FIXTURES / "manifests" / "example.toml", fetcher)
    validate(document)
    [before] = _ancestors(legacy)
    [after] = _ancestors(document)
    assert after["bom-ref"] == before["bom-ref"] != "base-model:0"
    assert {k: v for k, v in after.items() if k != "properties"} == {
        k: v for k, v in before.items() if k != "properties"
    }
    assert _props(after)["model-dependabot:relationship"] == "unspecified"


def test_refs_stay_unique_for_one_parent_under_two_types_and_a_self_reference() -> None:
    for name in ("ambiguous", "self", "duplicate", "adapter-no-revision"):
        _, document = _export(manifest(name))
        validate(document)
        refs = [a["bom-ref"] for a in _ancestors(document)]
        root = document["metadata"]["component"]["bom-ref"]
        assert len(set(refs)) == len(refs) and root not in refs, name


def test_a_gap_edge_is_written_as_a_gap_ancestor() -> None:
    _, document = _export(manifest("adapter-no-revision"))
    [ancestor] = _ancestors(document)
    assert "purl" not in ancestor
    assert _props(ancestor)["model-dependabot:gap"] == "no revision"
    assert _props(ancestor)["model-dependabot:hub-repo"] == "example-org/base-a"


def test_the_profile_lists_every_new_property() -> None:
    names = {
        "relationship",
        "relationship-recorded",
        "edge-origin",
        "claimed-origin",
        "parent-model",
        "parent-version",
    }
    assert {"model-dependabot:" + name for name in names} <= PROPERTIES
    assert cyclonedx.MAX_ANCESTORS == 256

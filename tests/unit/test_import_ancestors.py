"""The six import rules for ancestors (T026, contracts/cyclonedx-lineage.md, Import rules)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from lineage_support import A, bom
from model_dependabot.inventory.cyclonedx import import_ancestors, import_bom

PURL_A = f"pkg:huggingface/example-org/base-a@{A}"


def _document(name: str) -> dict[str, Any]:
    return json.loads(Path(bom(name)).read_text("utf-8"))


def _many(count: int) -> dict[str, Any]:
    document = _document("third-party-two-untyped")
    ancestors = [
        {
            "type": "machine-learning-model",
            "bom-ref": f"base-model:{index}",
            "name": f"example-org/base-{index}",
            "purl": f"pkg:huggingface/example-org/base-{index}@{index:040x}",
        }
        for index in range(count)
    ]
    document["metadata"]["component"]["pedigree"]["ancestors"] = ancestors
    return document


def test_at_most_256_ancestors_are_read_and_the_rest_is_one_gap() -> None:
    document = _many(300)
    edges = import_ancestors(document)
    assert len(edges) == 257
    gap = edges[-1]
    assert gap["gap_reason"] == "more than 256 ancestors; 44 not read"
    assert (gap["parent_repo"], gap["parent_model_id"]) == (None, None)
    entries = [e for e in import_bom(document) if e["kind"] == "base_model"]
    assert len(entries) == 257
    assert entries[-1]["gap_reason"] == "more than 256 ancestors; 44 not read"


def test_every_imported_edge_is_import_and_unverified_keeping_the_claim() -> None:
    [edge] = import_ancestors(_document("claims-manifest"), source_file="b.json", source_sha256="s")
    assert (edge["origin"], edge["state"], edge["claimed_origin"]) == (
        "import",
        "unverified",
        "manifest",
    )
    assert (edge["relationship"], edge["source_key"]) == ("merged-from", "ancestors[0]")
    assert (edge["source_file"], edge["source_sha256"]) == ("b.json", "s")
    assert edge["entry_identifier"] == PURL_A


def test_no_relationship_property_is_unspecified() -> None:
    edges = import_ancestors(_document("third-party-two-untyped"))
    assert [(e["relationship"], e["relationship_recorded"]) for e in edges] == [
        ("unspecified", None),
        ("unspecified", None),
    ]


def test_an_unrecognised_type_is_unspecified_with_the_value_kept() -> None:
    [edge] = import_ancestors(_document("unrecognised-type"))
    assert (edge["relationship"], edge["relationship_recorded"]) == (
        "unspecified",
        "distilled-from",
    )


def test_a_registered_model_reference_gives_an_edge_and_no_entry() -> None:
    [edge] = import_ancestors(_document("self-reference"))
    assert (edge["parent_kind"], edge["parent_model_id"], edge["parent_version"]) == (
        "model",
        "example-self-bom",
        1,
    )
    assert edge["gap_reason"] is None
    assert import_bom(_document("self-reference")) == []
    [unversioned] = import_ancestors(_document("registered-no-version"))
    assert (unversioned["parent_version"], unversioned["gap_reason"]) == (None, "no version")
    assert import_bom(_document("registered-no-version")) == []


def test_one_purl_twice_gives_two_entries_and_one_edge_declared_twice() -> None:
    [edge] = import_ancestors(_document("same-purl-twice"))
    assert edge["declared_count"] == 2
    assert len(import_bom(_document("same-purl-twice"))) == 2


def test_two_purl_less_ancestors_give_two_gap_entries_and_two_edges() -> None:
    edges = import_ancestors(_document("two-no-purl"))
    assert [(e["source_key"], e["gap_reason"], e["declared_count"]) for e in edges] == [
        ("ancestors[0]", "no Hugging Face purl", 1),
        ("ancestors[1]", "no Hugging Face purl", 1),
    ]
    assert [e["gap_reason"] for e in import_bom(_document("two-no-purl"))] == [
        "no Hugging Face purl",
        "no Hugging Face purl",
    ]


def test_one_purl_under_two_types_gives_two_edges() -> None:
    edges = import_ancestors(_document("one-parent-two-types"))
    assert [e["relationship"] for e in edges] == ["fine-tuned-from", "quantized-from"]

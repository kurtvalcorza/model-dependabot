"""CycloneDX round trips keep every edge (T027, SC-002, FR-011, review R3)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from lineage_support import Cli, bom, manifest
from model_dependabot.inventory.cyclonedx import validate


@pytest.fixture
def cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> Cli:
    return Cli(tmp_path, capsys)


def _export(cli: Cli, model_id: str, out: Path) -> dict[str, Any]:
    cli.ok("inventory", "export", model_id, "-o", str(out))
    document = json.loads(out.read_text("utf-8"))
    validate(document)
    return document


def _ancestors(document: dict[str, Any]) -> list[tuple[Any, ...]]:
    """Each ancestor's parent reference, revision, type and gap."""
    found = []
    for item in document["metadata"]["component"].get("pedigree", {}).get("ancestors", []):
        props = {
            p["name"].removeprefix("model-dependabot:"): p["value"]
            for p in item.get("properties", [])
        }
        found.append(
            (
                item.get("purl") or props.get("parent-model") or props.get("hub-repo"),
                item.get("version") or props.get("parent-version") or props.get("hub-revision"),
                props.get("relationship"),
                props.get("relationship-recorded"),
                props.get("gap"),
            )
        )
    return found


def _origins(document: dict[str, Any]) -> list[tuple[str | None, str | None]]:
    return [
        (props.get("model-dependabot:edge-origin"), props.get("model-dependabot:claimed-origin"))
        for props in (
            {p["name"]: p["value"] for p in item.get("properties", [])}
            for item in document["metadata"]["component"].get("pedigree", {}).get("ancestors", [])
        )
    ]


def _zero_parents(tmp_path: Path) -> str:
    path = tmp_path / "zero.toml"
    path.write_text('[model]\nid = "example-zero"\n', encoding="utf-8")
    return str(path)


@pytest.mark.parametrize("name", ["zero", "adapter-no-revision", "merge-two", "four-types"])
def test_export_import_export_keeps_references_revisions_types_and_gaps(
    cli: Cli, tmp_path: Path, name: str
) -> None:
    path = _zero_parents(tmp_path) if name == "zero" else manifest(name)
    if name == "four-types":
        base = tmp_path / "base.toml"
        base.write_text('[model]\nid = "example-adapter-base"\n', encoding="utf-8")
        cli.ok("register", str(base))
    registered = cli.ok("register", path)
    first = _export(cli, registered["model_id"], tmp_path / "first.json")
    imported = cli.ok("import", str(tmp_path / "first.json"), "--model-id", "example-again")
    second = _export(cli, "example-again", tmp_path / "second.json")
    assert _ancestors(second) == _ancestors(first)
    edges = imported["lineage"]["edges"]
    assert len(edges) == len(_ancestors(first))
    assert {(e["origin"], e["state"], e["claimed_origin"]) for e in edges} <= {
        ("import", "unverified", "manifest")
    }
    assert {origin for origin, _ in _origins(second)} <= {"import"}
    assert {claimed for _, claimed in _origins(second)} <= {"manifest"}
    if name == "four-types":
        model_edge = edges[3]
        assert (model_edge["resolved"], model_edge["state"]) == (True, "unverified")
        assert model_edge["note"] == "resolved by id and version only"


@pytest.mark.parametrize(
    "name",
    [
        "third-party-two-untyped",
        "unrecognised-type",
        "one-parent-two-types",
        "self-reference",
        "two-no-purl",
        "claims-manifest",
    ],
)
def test_import_then_export_of_a_third_party_document(cli: Cli, tmp_path: Path, name: str) -> None:
    original = json.loads(Path(bom(name)).read_text("utf-8"))
    model_id = "example-self-bom" if name == "self-reference" else "example-imported"
    cli.ok("import", bom(name), "--model-id", model_id)
    exported = _export(cli, model_id, tmp_path / "out.json")
    before, after = _ancestors(original), _ancestors(exported)
    assert len(after) == len(before)
    for (ref, revision, kind, _, gap), (ref2, revision2, kind2, recorded2, gap2) in zip(
        before, after, strict=True
    ):
        assert (ref, revision) == (ref2, revision2)
        if kind in ("fine-tuned-from", "adapter-for", "merged-from", "quantized-from"):
            assert kind2 == kind
        elif kind is None:
            assert kind2 == "unspecified"
        else:
            assert (kind2, recorded2) == ("unspecified", kind)
        assert gap2 == (gap or (None if ref else "no Hugging Face purl"))
    refs = [a["bom-ref"] for a in exported["metadata"]["component"]["pedigree"]["ancestors"]]
    assert len(set(refs)) == len(refs)
    assert exported["metadata"]["component"]["bom-ref"] not in refs
    assert {origin for origin, _ in _origins(exported)} == {"import"}


def test_the_limit_gap_survives_import_export_import(cli: Cli, tmp_path: Path) -> None:
    document = json.loads(Path(bom("third-party-two-untyped")).read_text("utf-8"))
    document["metadata"]["component"]["pedigree"]["ancestors"] = [
        {
            "type": "machine-learning-model",
            "bom-ref": f"base-model:{index}",
            "name": f"example-org/base-{index}",
            "purl": f"pkg:huggingface/example-org/base-{index}@{index:040x}",
        }
        for index in range(300)
    ]
    source = tmp_path / "many.json"
    source.write_text(json.dumps(document), encoding="utf-8")
    first = cli.ok("import", str(source), "--model-id", "example-many")
    gap = "more than 256 ancestors; 44 not read"
    assert first["lineage"]["edges"][-1]["gap"] == gap
    exported = _export(cli, "example-many", tmp_path / "out.json")
    assert _ancestors(exported)[-1][-1] == gap
    again = cli.ok("import", str(tmp_path / "out.json"), "--model-id", "example-many-again")
    assert len(again["lineage"]["edges"]) == 257
    assert again["lineage"]["edges"][-1]["gap"] == gap

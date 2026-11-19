"""Importing several CycloneDX ancestors (T011; the multi-ancestor test the spec found missing).

(a) characterises today's ``import_bom``: one ``base_model`` entry per ancestor, with no
de-duplication, and the gap "no Hugging Face purl" for an ancestor without one. (b) checks what
feature 011 adds through ``model-dependabot import``: one edge per ancestor identity, origin
``import``, state ``unverified``, and no entry for an ancestor naming a registered model.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lineage_support import A, B, Cli, bom
from model_dependabot.inventory.cyclonedx import import_bom
from model_dependabot.store import Store


def _entries(name: str) -> list[dict]:
    return [e for e in import_bom(json.loads(Path(bom(name)).read_text("utf-8"))) if e]


def test_two_hub_ancestors_give_two_pinned_base_model_entries() -> None:
    entries = _entries("third-party-two-untyped")
    assert [(e["kind"], e["identifier"], e["version"]) for e in entries] == [
        ("base_model", f"pkg:huggingface/example-org/base-a@{A}", A),
        ("base_model", f"pkg:huggingface/example-org/base-b@{B}", B),
    ]


def test_two_ancestors_with_one_purl_stay_two_entries() -> None:
    entries = _entries("same-purl-twice")
    assert [e["identifier"] for e in entries] == [f"pkg:huggingface/example-org/base-a@{A}"] * 2


def test_an_ancestor_without_a_purl_is_the_gap_no_hugging_face_purl() -> None:
    entries = _entries("two-no-purl")
    assert [(e["pinned"], e["gap_reason"]) for e in entries] == [
        (False, "no Hugging Face purl"),
        (False, "no Hugging Face purl"),
    ]


@pytest.fixture
def cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> Cli:
    return Cli(tmp_path, capsys)


def test_importing_two_untyped_ancestors_records_two_unverified_edges(cli: Cli) -> None:
    cli.ok("import", bom("third-party-two-untyped"), "--model-id", "example-imported")
    with Store(cli.db) as store:
        edges = store.edges("example-imported", 1)
    assert [(e["parent_repo"], e["parent_revision"]) for e in edges] == [
        ("example-org/base-a", A),
        ("example-org/base-b", B),
    ]
    assert {(e["relationship"], e["origin"], e["state"]) for e in edges} == {
        ("unspecified", "import", "unverified")
    }
    assert [e["source_key"] for e in edges] == ["ancestors[0]", "ancestors[1]"]


def test_an_ancestor_naming_a_registered_model_gives_an_edge_and_no_entry(cli: Cli) -> None:
    payload = cli.ok("import", bom("self-reference"), "--model-id", "example-self-bom")
    assert payload["entries"] == [] and payload["gaps"] == []
    with Store(cli.db) as store:
        [edge] = store.edges("example-self-bom", 1)
    assert (edge["parent_kind"], edge["parent_model_id"], edge["parent_version"]) == (
        "model",
        "example-self-bom",
        1,
    )

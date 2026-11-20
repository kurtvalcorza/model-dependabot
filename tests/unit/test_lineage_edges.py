"""Edges from a manifest: identity, folding, gaps and source (T017, data-model.md, research L3)."""

from __future__ import annotations

from pathlib import Path

from lineage_support import A2, A, manifest
from model_dependabot.lineage.edges import edges_from_manifest
from model_dependabot.manifest import load_manifest

PURL_A = f"pkg:huggingface/example-org/base-a@{A}"


def _edges(name: str, origin: str = "manifest") -> list[dict]:
    loaded = load_manifest(manifest(name))
    return edges_from_manifest(
        loaded, origin=origin, source_file=f"{name}.toml", source_sha256=loaded.sha256
    )


def test_one_edge_per_parent_in_declaration_order_with_its_source() -> None:
    edges = _edges("four-types")
    assert [e["relationship"] for e in edges] == [
        "fine-tuned-from",
        "merged-from",
        "quantized-from",
        "adapter-for",
    ]
    assert [e["position"] for e in edges] == [0, 1, 2, 3]
    assert [e["source_key"] for e in edges] == [f"parents[{i}]" for i in range(4)]
    loaded = load_manifest(manifest("four-types"))
    assert {(e["source_file"], e["source_sha256"]) for e in edges} == {
        ("four-types.toml", loaded.sha256)
    }
    assert {(e["origin"], e["state"]) for e in edges} == {("manifest", "owner")}
    assert edges[0]["entry_identifier"] == PURL_A
    assert (edges[3]["parent_kind"], edges[3]["parent_model_id"], edges[3]["parent_version"]) == (
        "model",
        "example-adapter-base",
        1,
    )
    assert edges[3]["entry_identifier"] is None


def test_a_repeat_with_the_same_type_folds_into_one_edge_declared_twice() -> None:
    [edge] = _edges("duplicate")
    assert (edge["declared_count"], edge["source_key"]) == (2, "parents[0]")


def test_the_same_parent_with_two_types_gives_two_edges() -> None:
    edges = _edges("ambiguous")
    assert [(e["relationship"], e["declared_count"]) for e in edges] == [
        ("fine-tuned-from", 1),
        ("quantized-from", 1),
    ]
    assert {e["entry_identifier"] for e in edges} == {PURL_A}


def test_two_revisions_of_one_repository_are_two_edges() -> None:
    edges = _edges("same-repo-two-revisions")
    assert [e["parent_revision"] for e in edges] == [A, A2]


def test_gaps_no_revision_not_a_commit_and_no_version(tmp_path: Path) -> None:
    [edge] = _edges("adapter-no-revision")
    assert (edge["gap_reason"], edge["entry_identifier"]) == ("no revision", None)
    path = tmp_path / "model.toml"
    path.write_text(
        '[model]\nid = "m"\n[[parents]]\nhub = "hf:example-org/base-a"\nrevision = "main"\n'
        'relationship = "fine-tuned-from"\n'
        '[[parents]]\nmodel = "x"\nrelationship = "adapter-for"\n',
        encoding="utf-8",
    )
    loaded = load_manifest(path)
    commit, version = edges_from_manifest(
        loaded, origin="manifest", source_file="model.toml", source_sha256=loaded.sha256
    )
    assert commit["gap_reason"] == "revision is not a commit"
    assert version["gap_reason"] == "no version"


def test_a_record_registration_gives_origin_record_and_state_owner() -> None:
    edges = _edges("merge-two", origin="record")
    assert {(e["origin"], e["state"]) for e in edges} == {("record", "owner")}


def test_a_legacy_base_model_is_one_unspecified_edge_keyed_base_model(tmp_path: Path) -> None:
    path = tmp_path / "model.toml"
    path.write_text(
        f'[model]\nid = "m"\n[base_model]\nhub = "hf:example-org/base-a"\nrevision = "{A}"\n',
        encoding="utf-8",
    )
    loaded = load_manifest(path)
    [edge] = edges_from_manifest(
        loaded, origin="manifest", source_file="model.toml", source_sha256=loaded.sha256
    )
    assert (edge["relationship"], edge["source_key"], edge["entry_identifier"]) == (
        "unspecified",
        "base_model",
        PURL_A,
    )


# --- review R10: the repository filter of cause_edges and the case of parent identity -----------


def test_cause_edges_names_only_the_hub_edges_of_that_repository() -> None:
    from model_dependabot.lineage.edges import cause_edges

    edges = _edges("four-types")  # base-a, base-b, base-c and a registered model
    [only] = cause_edges(edges, "Example-Org/Base-B")
    assert (only["relationship"], only["source_key"]) == ("merged-from", "parents[1]")
    assert cause_edges(edges, "example-org/other") == []
    assert len(cause_edges(_edges("same-repo-two-revisions"), "example-org/base-a")) == 2


def test_parent_identity_ignores_the_case_of_a_repository() -> None:
    from model_dependabot.lineage.edges import fold, parent_identity

    upper = dict(_edges("merge-two")[0], parent_repo="Example-Org/Base-A")
    lower = _edges("merge-two")[0]
    assert parent_identity(upper) == parent_identity(lower)
    [folded] = fold([lower, upper])
    assert folded["declared_count"] == 2

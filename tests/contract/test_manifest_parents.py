"""The manifest's parent list (T016, contracts/manifest-parents.md, FR-001 to FR-004)."""

from __future__ import annotations

from pathlib import Path

import pytest

from lineage_support import A, B, C, manifest
from model_dependabot.manifest import ManifestError, ParentSpec, load_manifest, parents_of

TYPES = "fine-tuned-from, adapter-for, merged-from, quantized-from"


def test_two_merged_from_parents_are_parsed_in_order() -> None:
    loaded = load_manifest(manifest("merge-two"))
    assert loaded.base_model is None
    assert loaded.parents == (
        ParentSpec(0, "parents", "example-org/base-a", A, None, None, "merged-from"),
        ParentSpec(1, "parents", "example-org/base-b", B, None, None, "merged-from"),
    )


def test_four_types_include_a_registered_model_parent() -> None:
    parents = load_manifest(manifest("four-types")).parents
    assert [(p.repo, p.revision, p.relationship) for p in parents[:3]] == [
        ("example-org/base-a", A, "fine-tuned-from"),
        ("example-org/base-b", B, "merged-from"),
        ("example-org/base-c", C, "quantized-from"),
    ]
    assert (parents[3].model_id, parents[3].model_version, parents[3].relationship) == (
        "example-adapter-base",
        1,
        "adapter-for",
    )


def test_a_legacy_base_model_is_one_unspecified_parent() -> None:
    loaded = load_manifest(
        Path(__file__).resolve().parent.parent / "fixtures/manifests/example.toml"
    )
    assert loaded.base_model is not None
    [parent] = loaded.parents
    assert (parent.form, parent.index, parent.relationship) == ("base_model", 0, "unspecified")
    assert (parent.repo, parent.revision) == (loaded.base_model.repo, loaded.base_model.revision)
    assert parents_of(loaded) == loaded.parents


def _write(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "model.toml"
    path.write_text('[model]\nid = "m"\n' + body, encoding="utf-8")
    return path


@pytest.mark.parametrize(
    ("body", "message"),
    [
        (
            Path(manifest("both-forms")).read_text("utf-8").split("\n", 4)[4],
            "use either [base_model] or [[parents]], not both",
        ),
        (
            '[[parents]]\nhub = "hf:a/b"\nrelationship = "distilled-from"\n',
            f"parents[0].relationship must be one of {TYPES}",
        ),
        (
            '[[parents]]\nhub = "hf:a/b"\nrelationship = "unspecified"\n',
            f"parents[0].relationship must be one of {TYPES}",
        ),
        ('[[parents]]\nhub = "hf:a/b"\n', f"parents[0].relationship must be one of {TYPES}"),
        (
            '[[parents]]\nhub = "hf:a/b"\nmodel = "x"\nrelationship = "adapter-for"\n',
            "parents[0] needs exactly one of hub and model",
        ),
        (
            '[[parents]]\nrelationship = "adapter-for"\n',
            "parents[0] needs exactly one of hub and model",
        ),
        (
            '[[parents]]\nmodel = "x"\nrevision = "y"\nrelationship = "adapter-for"\n',
            "parents[0].revision needs hub",
        ),
        (
            '[[parents]]\nhub = "hf:a/b"\nversion = 1\nrelationship = "adapter-for"\n',
            "parents[0].version needs model",
        ),
        (
            '[[parents]]\nmodel = "x"\nversion = 0\nrelationship = "adapter-for"\n',
            "parents[0].version must be a positive integer",
        ),
        (
            '[[parents]]\nmodel = "x"\nversion = "2"\nrelationship = "adapter-for"\n',
            "parents[0].version must be a positive integer",
        ),
        (
            '[[parents]]\nhub = "hf:a/b"\nrelationship = "adapter-for"\ntype = "x"\n',
            "unknown key in parents[0]: type",
        ),
        (
            '[base_model]\nhub = "hf:a/b"\nrelationship = "adapter-for"\n',
            "unknown key in base_model",
        ),
    ],
)
def test_every_invalid_parent_is_a_manifest_error(tmp_path: Path, body: str, message: str) -> None:
    with pytest.raises(ManifestError) as raised:
        load_manifest(_write(tmp_path, body))
    assert message in str(raised.value)


def test_the_second_parent_is_named_by_its_index(tmp_path: Path) -> None:
    body = '[[parents]]\nhub = "hf:a/b"\nrelationship = "adapter-for"\n'
    body += '[[parents]]\nhub = "hf:a/c"\nrelationship = "derived"\n'
    with pytest.raises(ManifestError, match=r"parents\[1\]\.relationship"):
        load_manifest(_write(tmp_path, body))

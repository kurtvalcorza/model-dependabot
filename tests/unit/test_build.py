"""Manifest to inventory entries: hashing, format classes and gaps (T014, FR-001 to FR-003)."""

from __future__ import annotations

import hashlib
import io
import zipfile
from pathlib import Path

import pytest

from model_dependabot.inventory.build import (
    ENTRY_KIND_ORDER,
    build_entries,
    check_entry,
    classify,
    new_entry,
)
from model_dependabot.manifest import load_manifest
from model_dependabot.sources.fetcher import RecordedFetcher
from model_dependabot.store import ENTRY_FIELDS, ENTRY_KINDS

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
EXAMPLE = FIXTURES / "manifests" / "example.toml"
WEIGHTS = FIXTURES / "manifests" / "weights"
COMMIT = "607a30d783dfa663caf39e06633721c8d4cfcd7e"
GPT2_SAFETENSORS_SHA256 = "248dfc3911869ec493c76e65bf2fcf7f615828b0254c12b473182f0f81d3a707"


@pytest.fixture
def entries() -> list[dict]:
    return build_entries(load_manifest(EXAMPLE), fetcher=RecordedFetcher(FIXTURES / "hf"))


def _zip(names: list[str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name in names:
            archive.writestr(name, b"\x80\x02}q\x00.")
    return buffer.getvalue()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_local_weight_files_are_hashed_with_sha256_and_sized(entries: list[dict]) -> None:
    local = {e["location"]: e for e in entries if e["kind"] == "weight_file" and not e["hub_repo"]}
    assert set(local) == {"weights/tiny.pt", "weights/tiny.safetensors", "weights/tiny.onnx"}
    for location, entry in local.items():
        path = WEIGHTS.parent / location
        assert entry["identifier"] == "sha256:" + _sha256(path)
        assert entry["size"] == path.stat().st_size
        assert entry["pinned"] is True
        assert entry["gap_reason"] is None


def test_local_weight_formats_and_can_run_code(entries: list[dict]) -> None:
    formats = {
        e["location"]: (e["format"], e["can_run_code"])
        for e in entries
        if e["kind"] == "weight_file" and not e["hub_repo"]
    }
    assert formats == {
        "weights/tiny.pt": ("pytorch-zip", True),
        "weights/tiny.safetensors": ("safetensors", False),
        "weights/tiny.onnx": ("onnx", False),
    }


@pytest.mark.parametrize(
    ("name", "head", "expected"),
    [
        ("model.pt", b"\x80\x02}q\x00.", ("pickle", True)),
        ("model.pth", b"\x80\x04", ("pickle", True)),
        ("model.bin", b"\x80\x02", ("pickle", True)),
        ("model.ckpt", b"\x80\x02", ("pickle", True)),
        ("model.pkl", b"\x80\x04", ("pickle", True)),
        ("model.joblib", b"\x80\x04", ("joblib", True)),
        ("model.pt", _zip(["archive/data.pkl", "archive/version"]), ("pytorch-zip", True)),
        ("model.bin", _zip(["archive/data.pkl"]), ("pytorch-zip", True)),
        ("model.safetensors", b"\x10\x00", ("safetensors", False)),
        ("model.onnx", b"\x08\x07", ("onnx", False)),
        ("model.gguf", b"GGUF", ("gguf", False)),
        ("MODEL.SafeTensors", b"", ("safetensors", False)),
        ("model.h5", b"\x89HDF", ("unknown", None)),
        ("model.bin", None, ("pickle", True)),
    ],
)
def test_formats_are_classified_as_pickle_based_or_code_free(
    name: str, head: bytes | None, expected: tuple[str, bool | None]
) -> None:
    assert classify(name, head) == expected


def test_every_entry_has_a_known_kind_and_every_field(entries: list[dict]) -> None:
    assert {entry["kind"] for entry in entries} == set(ENTRY_KINDS)
    for entry in entries:
        assert set(entry) == set(ENTRY_FIELDS)
        check_entry(entry)


def test_entries_come_in_kind_order(entries: list[dict]) -> None:
    ranks = [ENTRY_KIND_ORDER.index(entry["kind"]) for entry in entries]
    assert ranks == sorted(ranks)


def test_an_unpinned_entry_needs_a_gap_reason() -> None:
    with pytest.raises(ValueError, match="gap_reason"):
        check_entry(new_entry("package", name="numpy", pinned=False))
    with pytest.raises(ValueError, match="kind"):
        check_entry(new_entry("model", identifier="x", pinned=True))
    with pytest.raises(ValueError, match="identifier"):
        check_entry(new_entry("dataset", pinned=True))
    check_entry(new_entry("package", name="numpy", pinned=False, gap_reason="no exact version"))


def test_packages_come_from_the_lock(entries: list[dict]) -> None:
    packages = {e["name"]: e for e in entries if e["kind"] == "package"}
    assert packages["attrs"]["identifier"] == "pkg:pypi/attrs@26.1.0"
    assert packages["attrs"]["version"] == "26.1.0"
    assert packages["attrs"]["pinned"] is True
    assert len(packages["attrs"]["hashes"]) == 2
    gaps = [e for e in entries if e["kind"] == "package" and not e["pinned"]]
    assert [(gap["name"], gap["gap_reason"]) for gap in gaps] == [(".", "no exact version")]


def test_the_base_model_is_pinned_to_its_commit(entries: list[dict]) -> None:
    (base,) = [e for e in entries if e["kind"] == "base_model"]
    assert base["identifier"] == f"pkg:huggingface/openai-community/gpt2@{COMMIT}"
    assert (base["name"], base["version"], base["pinned"]) == (
        "openai-community/gpt2",
        COMMIT,
        True,
    )


def test_a_dataset_is_identified_by_its_doi_with_its_sha256(entries: list[dict]) -> None:
    (dataset,) = [e for e in entries if e["kind"] == "dataset"]
    assert dataset["identifier"] == "10.5555/example-dataset-0001"
    assert dataset["pinned"] is True
    assert dataset["hashes"] == [
        "sha256:0f343b0931126a20f133d67c2b018a3b1d06bf1a3c4d3d1f7b2b2f1b1a4e5c6d"
    ]


def test_a_hub_weight_file_is_pinned_from_the_hub(entries: list[dict]) -> None:
    (hub,) = [e for e in entries if e["hub_file"] == "model.safetensors"]
    assert hub["identifier"] == "sha256:" + GPT2_SAFETENSORS_SHA256
    assert hub["size"] == 548105171
    assert (hub["format"], hub["can_run_code"]) == ("safetensors", False)
    assert (hub["hub_repo"], hub["hub_revision"]) == ("openai-community/gpt2", COMMIT)
    assert hub["location"] == (
        f"https://huggingface.co/openai-community/gpt2/resolve/{COMMIT}/model.safetensors"
    )


def test_a_hub_weight_file_without_revision_is_classified_but_a_gap(entries: list[dict]) -> None:
    (hub,) = [e for e in entries if e["hub_file"] == "pytorch_model.bin"]
    assert (hub["pinned"], hub["gap_reason"], hub["identifier"]) == (False, "no revision", None)
    assert (hub["format"], hub["can_run_code"]) == ("pickle", True)


def _manifest(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "m.toml"
    path.write_text('[model]\nid = "m"\n' + body, encoding="utf-8")
    return path


@pytest.mark.parametrize(
    ("revision_line", "reason"),
    [("", "no revision"), ('revision = "main"\n', "revision is not a commit")],
)
def test_a_base_model_without_an_exact_commit_is_a_gap(
    tmp_path: Path, revision_line: str, reason: str
) -> None:
    path = _manifest(tmp_path, '[base_model]\nhub = "hf:openai-community/gpt2"\n' + revision_line)
    (base,) = build_entries(load_manifest(path), fetcher=None)
    assert (base["pinned"], base["gap_reason"], base["identifier"]) == (False, reason, None)
    assert base["name"] == "openai-community/gpt2"


def test_doi_forms_are_normalised_and_a_missing_doi_is_a_gap(tmp_path: Path) -> None:
    path = _manifest(
        tmp_path,
        '[[datasets]]\ndoi = "https://doi.org/10.5555/ABC"\n'
        '[[datasets]]\ndoi = "doi:10.5555/xyz"\n'
        '[[datasets]]\ndoi = "not-a-doi"\n'
        '[[datasets]]\nsha256 = "' + "a" * 64 + '"\n',
    )
    first, second, bad, missing = build_entries(load_manifest(path), fetcher=None)
    assert (first["identifier"], first["pinned"]) == ("10.5555/abc", True)
    assert (second["identifier"], second["pinned"]) == ("10.5555/xyz", True)
    assert (bad["pinned"], bad["gap_reason"]) == (False, "not a DOI")
    assert (missing["pinned"], missing["gap_reason"]) == (False, "no DOI")
    assert missing["hashes"] == ["sha256:" + "a" * 64]


def test_a_hub_weight_file_on_a_repository_the_hub_refuses_is_a_gap(tmp_path: Path) -> None:
    path = _manifest(
        tmp_path,
        '[[weights]]\nhub = "hf:model-dependabot-fixture/does-not-exist"\n'
        f'revision = "{COMMIT}"\nfile = "model.safetensors"\n',
    )
    (entry,) = build_entries(load_manifest(path), fetcher=RecordedFetcher(FIXTURES / "hf"))
    assert entry["pinned"] is False
    assert "401" in entry["gap_reason"]
    assert entry["hub_revision"] is None

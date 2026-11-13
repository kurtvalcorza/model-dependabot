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
    merge_datasets,
    new_entry,
    shows_onnx,
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


def _safetensors(length: int, header: bytes = b'{"__metadata__":{}}') -> bytes:
    """A safetensors file with no tensor data and its header padded to ``length`` bytes."""
    return length.to_bytes(8, "little") + header.ljust(length, b" ")


def _gguf(version: int, *, tensors: int = 0, pairs: int = 0, size: int = 24) -> bytes:
    """A GGUF header (magic, version, tensor and metadata counts) zero-padded to ``size`` bytes."""
    header = b"GGUF" + version.to_bytes(4, "little")
    header += tensors.to_bytes(8, "little") + pairs.to_bytes(8, "little")
    return header.ljust(size, b"\x00")


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
        ("model.safetensors", _safetensors(64), ("safetensors", False)),
        ("model.onnx", b"\x08\x07", ("onnx", False)),
        ("model.gguf", _gguf(3), ("gguf", False)),
        ("model.gguf", _gguf(2, tensors=1, pairs=1, size=24 + 24 + 12), ("gguf", False)),
        ("MODEL.SafeTensors", _safetensors(64), ("safetensors", False)),
        # A code-free name must show its format in the bytes: placeholder bytes, an empty file or
        # a protocol 0 pickle (no header to recognise) is classified code-capable.
        ("model.safetensors", b"\x10\x00", ("pickle", True)),
        ("model.safetensors", b"", ("pickle", True)),
        ("model.safetensors", b"cos\nsystem\n.", ("pickle", True)),
        ("model.gguf", b"cos\nsystem\n.", ("pickle", True)),
        ("model.gguf", b"GGU", ("pickle", True)),
        ("model.gguf", b"GGUF", ("pickle", True)),
        ("model.gguf", _gguf(1), ("pickle", True)),
        ("model.gguf", _gguf(3, tensors=1, pairs=1, size=24 + 24 + 11), ("pickle", True)),
        # The magic alone is not a header: BINFLOAT (G) swallows it, then a GLOBAL (review of #4).
        ("model.gguf", b"GGUF\x03\x00\x00\x00\x000ccollections\nOrderedDict\n.", ("pickle", True)),
        # ONNX has no magic: only a zip or a protocol 2-5 pickle is recognised (known limit).
        ("model.onnx", b"cos\nsystem\n.", ("onnx", False)),
        ("model.h5", b"\x89HDF", ("unknown", None)),
        ("model.bin", None, ("pickle", True)),
        # A code-free name over pickle-based bytes is classified by the bytes (review F-02).
        ("model.safetensors", b"\x80\x04\x95\x00", ("pickle", True)),
        ("model.onnx", b"\x80\x02}q\x00.", ("pickle", True)),
        ("model.gguf", _zip(["archive/data.pkl"]), ("pytorch-zip", True)),
        ("model.safetensors", _zip(["notes.txt"]), ("unknown", None)),
        # A safetensors header length can start with the PROTO bytes: a well-formed header shows it.
        ("model.safetensors", _safetensors(640), ("safetensors", False)),
        # A brace at byte 8 alone is not a header: here it ends a pickle string (review F-02).
        ("model.safetensors", b"\x80\x04\x8c\x05aaaa{0cos\nsystem\n.", ("pickle", True)),
        ("model.safetensors", (640).to_bytes(8, "little") + b"{}", ("pickle", True)),
        ("model.safetensors", _safetensors(640, b'{"w":{"data_offsets":[0,9]}}'), ("pickle", True)),
        ("model.safetensors", None, ("safetensors", False)),
    ],
)
def test_formats_are_classified_as_pickle_based_or_code_free(
    name: str, head: bytes | None, expected: tuple[str, bool | None]
) -> None:
    assert classify(name, head) == expected


def test_a_deeply_nested_safetensors_header_is_code_capable_not_a_crash() -> None:
    """json.loads raises RecursionError on deep nesting (review of #4); the file is then not a
    safetensors file, so it is scanned like any other code-capable file."""
    nested = _safetensors(40000, b"[" * 20000 + b"]" * 20000)
    assert classify("model.safetensors", nested) == ("pickle", True)


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


def test_a_dataset_listed_again_keeps_a_licence_only_the_later_listing_records() -> None:
    doi = "10.5281/zenodo.1"
    bare = new_entry("dataset", identifier=doi, pinned=True)
    mit = new_entry(
        "dataset", identifier=doi, pinned=True, recorded_licence="MIT", licence_form="spdx"
    )
    [merged] = merge_datasets([bare, mit])
    assert (merged["recorded_licence"], merged["licence_form"]) == ("MIT", "spdx")
    cc0 = new_entry(
        "dataset", identifier=doi, pinned=True, recorded_licence="CC0-1.0", licence_form="spdx"
    )
    [kept] = merge_datasets([mit, cc0])
    assert kept["recorded_licence"] == "MIT"  # the first recorded licence stays the baseline


# --- classify_lead: the same rules on the first bytes and the true size (T006, research A4) -------

LEAD = 1 << 20


def _lead_cases() -> list[tuple[str, bytes]]:
    return [
        ("model.safetensors", _safetensors(64)),
        ("model.safetensors", _safetensors(640, b'{"w":{"data_offsets":[0,9]}}') + b"\x00" * 9),
        ("model.safetensors", _safetensors(640, b'{"w":{"data_offsets":[0,9]}}')),
        ("model.safetensors", b"\x80\x04\x95\x00" + b"\x00" * 64),
        ("model.safetensors", b""),
        ("model.gguf", _gguf(3)),
        ("model.gguf", _gguf(3, tensors=1, pairs=1, size=24 + 24 + 11)),
        ("model.gguf", b"cos\nsystem\n."),
        ("model.onnx", b"\x08\x07" + b"\x00" * 32),
        ("model.onnx", b"\x80\x02}q\x00."),
        *[
            (f"model.{ext}", b"\x80" + bytes([protocol]) + b"}q\x00.")
            for ext in ("pt", "bin")
            for protocol in (2, 3, 4, 5)
        ],
        ("model.safetensors", b"\x80\x05\x95\x00" + b"\x00" * 64),
        ("model.pt", _zip(["archive/data.pkl", "archive/version"])),
        ("model.safetensors", _zip(["notes.txt"])),
        ("model.gguf", _zip(["archive/data.pkl"])),
        ("model.h5", b"\x89HDF"),
    ]


@pytest.mark.parametrize(("name", "content"), _lead_cases())
def test_classify_lead_agrees_with_classify_on_the_whole_file(name: str, content: bytes) -> None:
    from model_dependabot.inventory.build import classify_lead

    assert classify_lead(name, content[:LEAD], len(content)) == classify(name, content)


def test_classify_lead_uses_the_true_size_not_the_lead_length() -> None:
    """Offsets and counts must fit the whole file, which is larger than the lead."""
    from model_dependabot.inventory.build import classify_lead

    big = _safetensors(64, b'{"w":{"data_offsets":[0,2000000]}}') + b"\x00" * 2_000_000
    assert classify_lead("model.safetensors", big[:LEAD], len(big)) == classify(
        "model.safetensors", big
    )
    assert classify_lead("model.safetensors", big[:LEAD], len(big)) == ("safetensors", False)
    # The same header claimed for a file too small to hold its data is not safetensors.
    assert classify_lead("model.safetensors", big[:LEAD], 100) == ("pickle", True)
    gguf = _gguf(3, tensors=50_000, size=LEAD)
    assert classify_lead("model.gguf", gguf, 24 + 24 * 50_000) == ("gguf", False)
    assert classify_lead("model.gguf", gguf, LEAD) == ("pickle", True)


def test_a_lead_that_starts_like_a_zip_is_never_code_free() -> None:
    """The central directory is at the end of a zip, out of the lead's reach."""
    from model_dependabot.inventory.build import classify_lead

    archive = _zip(["archive/data.pkl"]) + b"\x00" * (2 * LEAD)
    for name in ("model.safetensors", "model.gguf", "model.onnx"):
        file_format, can_run_code = classify_lead(name, archive[:LEAD], len(archive))
        assert can_run_code is not False
        assert file_format != "safetensors"


def test_a_safetensors_header_longer_than_the_lead_asks_for_more_bytes() -> None:
    from model_dependabot.inventory.build import NeedMoreBytes, classify_lead

    header = b'{"w":{"data_offsets":[0,4]}}'
    content = _safetensors(3 * LEAD, header) + b"\x00" * 4
    answer = classify_lead("model.safetensors", content[:LEAD], len(content))
    assert answer == NeedMoreBytes(8 + 3 * LEAD)
    assert classify_lead("model.safetensors", content[: 8 + 3 * LEAD], len(content)) == (
        "safetensors",
        False,
    )


# --- review F2 (PR #15 R5): positive ONNX structure ---------------------------------------------


@pytest.mark.parametrize(
    ("lead", "total", "shown"),
    [
        (FIXTURES / "manifests" / "weights" / "tiny.onnx", None, True),
        (
            b"\x08\x08\x12\x04test\x3a\xff\xff\x03" + b"\x0a" * 100,
            70_000,
            True,
        ),  # graph read in part
        (b"cos\nsystem\n(S'echo hi'\ntR.", None, False),  # a protocol 0 pickle
        (b"(dp0\nS'a'\np1\nI1\ns.", None, False),  # protocol 0 again
        (b"\x80\x02}q\x00.", None, False),  # protocol 2
        (b"PK\x03\x04" + bytes(30), None, False),
        (b"just some text", None, False),
        (b"", None, False),
        (b"\x08\x00", None, False),  # ir_version 0
        (b"\x08\x07\x48\x01", None, False),  # field 9 is not a ModelProto field
        (b"\x08\x07\x12\x05ab", None, False),  # a string longer than the file
        (b"\x08\x07\x3a\xff\xff\x03", 100, False),  # a graph longer than the file
    ],
)
def test_shows_onnx_needs_a_model_proto(lead: bytes | Path, total: int | None, shown: bool) -> None:
    data = lead.read_bytes() if isinstance(lead, Path) else lead
    assert shows_onnx(data, len(data) if total is None else total) is shown


def _pickle_zip() -> bytes:
    import io
    import zipfile

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("archive/data.pkl", b"\x80\x04N.")
    return buffer.getvalue()


@pytest.mark.parametrize(
    ("lead", "total", "tail"),
    [
        (b"\x08\x07\x10\x01", None, b""),  # field 2 (producer_name) given as a varint
        (b"\x08\x07\x0a\x00", None, b""),  # field 1 (ir_version) given as a length
        (b"\x08\x07", 0, b""),  # a lead longer than the file it is said to begin
        (b"\x08\x07", 1, b""),
        # a zip inside a field, then a zip at the end of the file, past the lead
        (b"\x08\x08\x3a" + bytes([len(_pickle_zip())]) + _pickle_zip(), None, b""),
        (b"\x08\x08\x3a\xff\xff\x7f", 3_000_000, _pickle_zip()),
    ],
)
def test_shows_onnx_refuses_wrong_wire_types_sizes_and_zips(
    lead: bytes, total: int | None, tail: bytes
) -> None:
    """PR #15 round 2, G2 and G3."""
    assert shows_onnx(lead, len(lead) if total is None else total, tail) is False

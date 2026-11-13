"""The ``format-check`` source: confirming imported claims (T014; FR-002 to FR-003, research A3-A5).

Local cases read files under the version's ``base_dir`` built in ``tmp_path``; hub cases replay the
recordings in ``tests/fixtures/format_check``. Reading and recording are separate steps, so a
source that fails part-way records nothing.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from conftest import (
    FORGED_COMMIT,
    FORGED_REPO,
    FORMAT_CHECK_FIXTURES,
    GPT2_COMMIT,
    GPT2_PICKLE,
    GPT2_REPO,
    GPT2_SAFETENSORS,
    resolve,
    tree_item,
    tree_url,
)
from model_dependabot.assurance.format_check import (
    SOURCE,
    VersionTarget,
    apply_claims,
    measure_imported,
    read_claims,
)
from model_dependabot.inventory.build import NO_ONNX_STRUCTURE
from model_dependabot.sources.fetcher import RecordedFetcher, SourceFailedError
from model_dependabot.store import Store

NOW = datetime(2026, 11, 13, 9, 0, tzinfo=UTC)


def _safetensors() -> bytes:
    header = b'{"w":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}'
    return len(header).to_bytes(8, "little") + header + b"\x00" * 4


PICKLE = b"\x80\x04\x95\x10\x00\x00\x00\x00\x00\x00\x00}\x94\x8c\x01a\x94K\x01s."


def _sha(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


def _local(location: str, content: bytes, **fields: Any) -> dict[str, Any]:
    entry = {
        "kind": "weight_file",
        "identifier": _sha(content),
        "pinned": True,
        "location": location,
        "format": "safetensors",
        "can_run_code": False,
        "format_origin": "import",
    }
    return entry | fields


def _hub(
    file: str,
    sha256: str,
    *,
    repo: str = GPT2_REPO,
    commit: str | None = GPT2_COMMIT,
    **fields: Any,
) -> dict[str, Any]:
    entry = {
        "kind": "weight_file",
        "identifier": f"sha256:{sha256}",
        "pinned": True,
        "location": None if commit is None else resolve(repo, commit, file),
        "format": "safetensors" if file.endswith(".safetensors") else "pickle",
        "can_run_code": not file.endswith(".safetensors"),
        "hub_repo": repo,
        "hub_revision": commit,
        "hub_file": file,
        "format_origin": "import",
    }
    return entry | fields


@pytest.fixture
def store(tmp_path: Path) -> Store:
    opened = Store(tmp_path / "db" / "md.db", now=lambda: NOW)
    yield opened
    opened.close()


def _target(
    store: Store,
    entries: list[dict[str, Any]],
    *,
    origin: str | None = "import",
    base_dir: Path | None = None,
) -> VersionTarget:
    model_id = f"m{len(store.model_ids())}"
    store.add_model(model_id)
    version = store.add_version(model_id, {}, "f" * 64, entries, base_dir=base_dir, origin=origin)
    record = store.get_version(model_id, version)
    return VersionTarget(
        model_id, version, record["origin"], record["base_dir"], store.entries(model_id, version)
    )


def _outcomes(store: Store, target: VersionTarget) -> list[tuple[str, str, str | None]]:
    return [
        (check["claim"], check["outcome"], check["measured_format"])
        for check in store.claim_checks(target.model_id, target.version)
    ]


def _run(store: Store, fetcher: Any, targets: list[VersionTarget], run_id: int | None = None):
    reads = read_claims(store, fetcher, targets)
    return apply_claims(store, run_id, reads)


class NoNetwork:
    """A fetcher that fails the test if asked anything."""

    def get(self, url: str, **kwargs: Any) -> Any:
        raise AssertionError(f"unexpected request: {url}")

    get_range = post = get


# --- local files ----------------------------------------------------------------------------------


def test_an_honest_local_file_is_confirmed(store: Store, tmp_path: Path) -> None:
    (tmp_path / "bom").mkdir()
    (tmp_path / "bom" / "model.safetensors").write_bytes(_safetensors())
    target = _target(
        store, [_local("model.safetensors", _safetensors())], base_dir=tmp_path / "bom"
    )
    _run(store, NoNetwork(), [target])
    assert _outcomes(store, target) == [
        ("identity", "confirmed", None),
        ("code_free", "confirmed", "safetensors"),
    ]


def test_a_local_pickle_named_safetensors_is_contradicted(store: Store, tmp_path: Path) -> None:
    (tmp_path / "bom").mkdir()
    (tmp_path / "bom" / "model.safetensors").write_bytes(PICKLE)
    target = _target(store, [_local("model.safetensors", PICKLE)], base_dir=tmp_path / "bom")
    applied = _run(store, NoNetwork(), [target])
    assert _outcomes(store, target) == [
        ("identity", "confirmed", None),
        ("code_free", "contradicted", "pickle"),
    ]
    contradicted = [item for item in applied if item.read.outcome == "contradicted"]
    assert contradicted[0].read.measured_can_run_code is True


def test_a_missing_local_file_is_unreadable(store: Store, tmp_path: Path) -> None:
    target = _target(store, [_local("model.safetensors", PICKLE)], base_dir=tmp_path)
    _run(store, NoNetwork(), [target])
    checks = store.claim_checks(target.model_id, target.version)
    assert {check["outcome"] for check in checks} == {"unreadable"}
    assert {check["reason"] for check in checks} == {"file absent"}


def test_a_local_hash_mismatch_contradicts_the_identity(store: Store, tmp_path: Path) -> None:
    (tmp_path / "model.safetensors").write_bytes(_safetensors())
    entry = _local("model.safetensors", PICKLE)  # pins another file's hash
    target = _target(store, [entry], base_dir=tmp_path)
    _run(store, NoNetwork(), [target])
    assert _outcomes(store, target) == [("identity", "contradicted", None)]


@pytest.mark.parametrize("location", ["../outside.safetensors", "sub/../../outside.safetensors"])
def test_a_path_out_of_the_base_dir_is_not_opened(
    store: Store, tmp_path: Path, location: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    base = tmp_path / "bom"
    (base / "sub").mkdir(parents=True)
    (tmp_path / "outside.safetensors").write_bytes(_safetensors())
    target = _target(store, [_local(location, _safetensors())], base_dir=base)
    opened: list[Path] = []
    real_open = Path.open
    monkeypatch.setattr(
        Path, "open", lambda self, *a, **k: opened.append(self) or real_open(self, *a, **k)
    )
    _run(store, NoNetwork(), [target])
    assert [path for path in opened if path.name == "outside.safetensors"] == []
    checks = store.claim_checks(target.model_id, target.version)
    assert {check["outcome"] for check in checks} == {"unreadable"}
    assert all("outside" in check["reason"] for check in checks)


def test_an_absolute_path_is_not_opened(store: Store, tmp_path: Path) -> None:
    (tmp_path / "abs.safetensors").write_bytes(_safetensors())
    location = str(tmp_path / "abs.safetensors")
    target = _target(store, [_local(location, _safetensors())], base_dir=tmp_path / "bom")
    _run(store, NoNetwork(), [target])
    assert {c["outcome"] for c in store.claim_checks(target.model_id, target.version)} == {
        "unreadable"
    }


def test_a_symbolic_link_out_of_the_base_dir_is_not_followed(store: Store, tmp_path: Path) -> None:
    base = tmp_path / "bom"
    base.mkdir()
    (tmp_path / "outside.safetensors").write_bytes(_safetensors())
    try:
        os.symlink(tmp_path / "outside.safetensors", base / "model.safetensors")
    except OSError as error:  # Windows without the symbolic-link privilege (plan, Target Platform)
        pytest.skip(f"symbolic links are not available to this user: {error}")
    target = _target(store, [_local("model.safetensors", _safetensors())], base_dir=base)
    _run(store, NoNetwork(), [target])
    checks = store.claim_checks(target.model_id, target.version)
    assert {check["outcome"] for check in checks} == {"unreadable"}
    assert all("outside" in check["reason"] for check in checks)


# --- hub files ------------------------------------------------------------------------------------


def test_a_hub_weight_without_a_pinned_revision_is_never_read(store: Store) -> None:
    target = _target(store, [_hub("model.safetensors", GPT2_SAFETENSORS, commit=None)])
    assert read_claims(store, NoNetwork(), [target]) == []


def test_a_forged_hub_file_is_contradicted(store: Store, derive_format_check: Callable) -> None:
    fetcher = RecordedFetcher(derive_format_check())
    entry = _hub("model.safetensors", GPT2_PICKLE, repo=FORGED_REPO, commit=FORGED_COMMIT)
    target = _target(store, [entry])
    _run(store, fetcher, [target])
    assert _outcomes(store, target) == [
        ("identity", "confirmed", None),
        ("code_free", "contradicted", "pickle"),
    ]


def test_an_honest_hub_file_is_confirmed(store: Store) -> None:
    target = _target(store, [_hub("model.safetensors", GPT2_SAFETENSORS)])
    _run(store, RecordedFetcher(FORMAT_CHECK_FIXTURES), [target])
    assert _outcomes(store, target) == [
        ("identity", "confirmed", None),
        ("code_free", "confirmed", "safetensors"),
    ]


def test_identity_is_checked_for_every_imported_weight_and_the_header_only_if_code_free(
    store: Store,
) -> None:
    fetcher = RecordedFetcher(FORMAT_CHECK_FIXTURES)
    target = _target(store, [_hub("pytorch_model.bin", GPT2_PICKLE)])
    _run(store, fetcher, [target])
    assert _outcomes(store, target) == [("identity", "confirmed", None)]
    assert [url for _, url, _ in fetcher.requests if "/resolve/" in url] == []


def test_a_connection_reset_fails_the_source_and_records_nothing(
    store: Store, derive_format_check: Callable
) -> None:
    hop = resolve(GPT2_REPO, GPT2_COMMIT, "model.safetensors")
    root = derive_format_check({"reset": {"url": hop, "error": "ConnectionResetError after 4"}})
    target = _target(store, [_hub("model.safetensors", GPT2_SAFETENSORS)])
    with pytest.raises(SourceFailedError):
        read_claims(store, RecordedFetcher(root), [target])
    assert store.claim_checks(target.model_id, target.version) == []


def test_a_final_outcome_is_never_read_again(store: Store) -> None:
    target = _target(store, [_hub("model.safetensors", GPT2_SAFETENSORS)])
    _run(store, RecordedFetcher(FORMAT_CHECK_FIXTURES), [target])
    assert read_claims(store, NoNetwork(), [target]) == []


def test_an_unreadable_claim_is_read_again_next_run(store: Store, tmp_path: Path) -> None:
    target = _target(store, [_local("model.safetensors", _safetensors())], base_dir=tmp_path)
    _run(store, NoNetwork(), [target])  # file absent
    (tmp_path / "model.safetensors").write_bytes(_safetensors())
    _run(store, NoNetwork(), [target])
    latest = store.latest_claim_check(
        target.model_id, target.version, target.entries[0]["identifier"]
    )
    assert latest is not None and latest["outcome"] == "confirmed"


@pytest.mark.parametrize("origin", ["manifest", "record"])
def test_a_version_with_nothing_to_confirm_makes_no_request(store: Store, origin: str) -> None:
    entry = _hub("model.safetensors", GPT2_SAFETENSORS, format_origin="name")
    target = _target(store, [entry], origin=origin)
    assert read_claims(store, NoNetwork(), [target]) == []


def test_each_outcome_stores_one_evidence_summary_without_weight_bytes(store: Store) -> None:
    target = _target(store, [_hub("model.safetensors", GPT2_SAFETENSORS)])
    _run(store, RecordedFetcher(FORMAT_CHECK_FIXTURES), [target], run_id=None)
    checks = store.claim_checks(target.model_id, target.version)
    assert len({check["evidence_id"] for check in checks}) == len(checks) == 2
    for check in checks:
        evidence = store.get_evidence(check["evidence_id"])
        assert evidence["source"] == SOURCE
        assert evidence["url"] == resolve(GPT2_REPO, GPT2_COMMIT, "model.safetensors")
        assert evidence["matched_identifier"] == f"sha256:{GPT2_SAFETENSORS}"
        body = store.read_body(evidence["body_sha256"])
        assert len(body) < 4096
        summary = json.loads(body)
        assert {
            "url",
            "commit",
            "file",
            "status",
            "content_range",
            "lead_sha256",
            "lead_length",
            "measured_format",
        } <= set(summary)
        assert summary["commit"] == GPT2_COMMIT and summary["status"] == 206


# --- review F2 (PR #15 R5): an imported .onnx claim needs ONNX in the bytes -----------------------

PICKLE_0 = b"cos\nsystem\n(S'echo hi'\ntR."  # a protocol 0 pickle: it starts with no 0x80
WEIGHTS = Path(__file__).resolve().parent.parent / "fixtures" / "manifests" / "weights"
TINY_ONNX = WEIGHTS / "tiny.onnx"


def _onnx(location: str, content: bytes) -> dict[str, Any]:
    return _local(location, content, format="onnx")


def test_an_onnx_claim_on_bytes_with_no_onnx_model_stays_unverified(
    store: Store, tmp_path: Path
) -> None:
    (tmp_path / "bom").mkdir()
    (tmp_path / "bom" / "decoy.onnx").write_bytes(PICKLE_0)
    target = _target(store, [_onnx("decoy.onnx", PICKLE_0)], base_dir=tmp_path / "bom")
    _run(store, NoNetwork(), [target])
    assert _outcomes(store, target) == [
        ("identity", "confirmed", None),
        ("code_free", "unreadable", None),
    ]
    [check] = [c for c in store.claim_checks(target.model_id, target.version) if c["reason"]]
    assert check["reason"] == NO_ONNX_STRUCTURE


def test_an_onnx_claim_on_an_onnx_model_is_confirmed(store: Store, tmp_path: Path) -> None:
    content = TINY_ONNX.read_bytes()
    (tmp_path / "bom").mkdir()
    (tmp_path / "bom" / "model.onnx").write_bytes(content)
    target = _target(store, [_onnx("model.onnx", content)], base_dir=tmp_path / "bom")
    _run(store, NoNetwork(), [target])
    assert _outcomes(store, target) == [
        ("identity", "confirmed", None),
        ("code_free", "confirmed", "onnx"),
    ]


def test_a_hub_onnx_claim_on_bytes_with_no_onnx_model_stays_unverified(
    store: Store, derive_format_check: Callable
) -> None:
    sha256 = hashlib.sha256(PICKLE_0).hexdigest()
    fetcher = RecordedFetcher(
        derive_format_check(
            {
                "decoy-tree": {
                    "url": tree_url(FORGED_REPO, FORGED_COMMIT),
                    "status": 200,
                    "range": None,
                    "body": json.dumps([tree_item("decoy.onnx", sha256, len(PICKLE_0))]),
                },
                "decoy-range": {
                    "url": resolve(FORGED_REPO, FORGED_COMMIT, "decoy.onnx"),
                    "status": 206,
                    "headers": {"Content-Range": f"bytes 0-{len(PICKLE_0) - 1}/{len(PICKLE_0)}"},
                    "body": PICKLE_0,
                },
            },
            forged=False,
        )
    )
    entry = _hub("decoy.onnx", sha256, repo=FORGED_REPO, commit=FORGED_COMMIT)
    target = _target(store, [entry | {"format": "onnx", "can_run_code": False}])
    _run(store, fetcher, [target])
    assert _outcomes(store, target) == [
        ("identity", "confirmed", None),
        ("code_free", "unreadable", None),
    ]


def test_import_does_not_take_an_onnx_name_for_a_measured_class(tmp_path: Path) -> None:
    (tmp_path / "decoy.onnx").write_bytes(PICKLE_0)
    (tmp_path / "model.onnx").write_bytes(TINY_ONNX.read_bytes())
    decoy = _onnx("decoy.onnx", PICKLE_0)
    honest = _onnx("model.onnx", TINY_ONNX.read_bytes())
    measures = measure_imported([decoy, honest], tmp_path, NOW)
    assert [measure.entry["location"] for measure in measures] == ["model.onnx"]
    assert decoy["format_origin"] == "import"  # the claim is left for format-check
    assert honest["format_origin"] == "bytes"


def test_an_onnx_prefix_in_front_of_a_zip_is_not_confirmed(store: Store, tmp_path: Path) -> None:
    """PR #15 round 2, G2: a zip reader finds its directory at the end, past the 1 MiB lead."""
    import io
    import zipfile

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("archive/data.pkl", b"\x80\x04N.")
    padding = 2 * 1024 * 1024
    # ir_version 8, a graph field of 2 MiB (the varint 80 80 80 01) and a zip after it
    content = b"\x08\x08\x3a\x80\x80\x80\x01" + bytes(padding) + buffer.getvalue()
    assert b"PK" not in content[: 1024 * 1024]
    (tmp_path / "bom").mkdir()
    (tmp_path / "bom" / "model.onnx").write_bytes(content)
    target = _target(store, [_onnx("model.onnx", content)], base_dir=tmp_path / "bom")
    _run(store, NoNetwork(), [target])
    assert ("code_free", "unreadable", None) in _outcomes(store, target)

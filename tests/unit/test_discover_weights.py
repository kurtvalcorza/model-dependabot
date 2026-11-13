"""Local weight files measured by discovery (T037; FR-017)."""

from __future__ import annotations

import hashlib
import shutil
from pathlib import Path

from model_dependabot.discover.walk import Limits, walk
from model_dependabot.discover.weights import WEIGHT_LIMIT, discover_weights

NOW = "2026-11-13T00:00:00Z"
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
TINY = FIXTURES / "manifests" / "weights" / "tiny.safetensors"
PICKLE = b"\x80\x04\x95\x05\x00\x00\x00\x00\x00\x00\x00K\x01."


def test_a_well_formed_file_is_verified_from_its_bytes(tmp_path: Path) -> None:
    shutil.copyfile(TINY, tmp_path / "model.safetensors")
    [item], skipped = discover_weights(walk(tmp_path), NOW, Limits())
    assert skipped == []
    data = TINY.read_bytes()
    assert item["identity"] == {
        "path": "model.safetensors",
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "format": "safetensors",
        "can_run_code": False,
    }
    assert item["status"] == "verified"
    assert item["origin"] == {"file": "model.safetensors"}
    assert "note" not in item


def test_a_pickle_named_safetensors_is_a_pickle(tmp_path: Path) -> None:
    (tmp_path / "runs").mkdir()
    (tmp_path / "runs" / "best.safetensors").write_bytes(PICKLE)
    [item], _ = discover_weights(walk(tmp_path), NOW, Limits())
    assert item["identity"]["format"] == "pickle"
    assert item["identity"]["can_run_code"] is True
    assert item["status"] == "verified"
    assert item["note"] == "named as safetensors; the bytes show pickle"


def test_the_same_bytes_under_two_names_conflict(tmp_path: Path) -> None:
    (tmp_path / "a.pt").write_bytes(PICKLE)
    (tmp_path / "b.bin").write_bytes(PICKLE)
    (tmp_path / "other.pt").write_bytes(PICKLE + b"x")
    items, _ = discover_weights(walk(tmp_path), NOW, Limits())
    status = {item["identity"]["path"]: item["status"] for item in items}
    assert status == {"a.pt": "conflicting", "b.bin": "conflicting", "other.pt": "verified"}
    notes = {item["identity"]["path"]: item.get("note") for item in items}
    assert notes["a.pt"] == "the same bytes as b.bin"


def test_only_weight_suffixes_are_hashed(tmp_path: Path) -> None:
    (tmp_path / "notes.txt").write_bytes(PICKLE)
    (tmp_path / "model.onnx").write_bytes(b"\x08\x07")
    items, _ = discover_weights(walk(tmp_path), NOW, Limits())
    assert [item["identity"]["path"] for item in items] == ["model.onnx"]


def test_the_weight_file_limit(tmp_path: Path) -> None:
    for index in range(4):
        (tmp_path / f"w{index}.pt").write_bytes(PICKLE + bytes([index]))
    items, skipped = discover_weights(walk(tmp_path), NOW, Limits(weight_files=2))
    assert [item["identity"]["path"] for item in items] == ["w0.pt", "w1.pt"]
    assert skipped == [
        {"path": "w2.pt", "reason": WEIGHT_LIMIT},
        {"path": "w3.pt", "reason": WEIGHT_LIMIT},
    ]

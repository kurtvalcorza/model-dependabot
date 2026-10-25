"""Weight files are hashed, classified and scanned from disk, never read whole (review C1).

A weight file can be many gigabytes, so the inventory and the scan read it in chunks or through a
file handle. ``Path.read_bytes`` is made to fail for weight files here: any code that reads a
whole file into memory fails these tests. Nothing here is ever unpickled.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from model_dependabot.inventory.build import _local_weight, classify
from model_dependabot.lifecycle import run_check
from model_dependabot.manifest import WeightSpec
from model_dependabot.sources import pickle_scan
from model_dependabot.sources.fetcher import RecordedFetcher
from model_dependabot.store import Store

MOMENT = datetime(2026, 10, 24, 8, 0, tzinfo=UTC)
WEIGHT_SUFFIXES = {".pt", ".pth", ".bin", ".ckpt", ".pkl", ".joblib"}


@pytest.fixture
def no_whole_reads(monkeypatch: pytest.MonkeyPatch) -> None:
    original = Path.read_bytes

    def guarded(self: Path) -> bytes:
        if self.suffix.lower() in WEIGHT_SUFFIXES:
            raise AssertionError(f"a weight file was read whole: {self.name}")
        return original(self)

    monkeypatch.setattr(Path, "read_bytes", guarded)


def test_a_zip_checkpoint_is_classified_from_its_path(craft: ModuleType, tmp_path: Path) -> None:
    path = tmp_path / "model.bin"
    path.write_bytes(craft.pytorch_zip(craft.innocuous()))
    assert classify(path.name, path) == ("pytorch-zip", True)
    plain = tmp_path / "plain.bin"
    plain.write_bytes(craft.innocuous())
    assert classify(plain.name, plain) == ("pickle", True)


def test_a_local_zip_weight_is_not_read_whole(
    craft: ModuleType, tmp_path: Path, no_whole_reads: None
) -> None:
    data = craft.pytorch_zip(craft.innocuous())
    path = tmp_path / "model.pt"
    path.write_bytes(data)
    entry = _local_weight(WeightSpec(path=path, relative="model.pt"))
    assert entry["identifier"] == f"sha256:{hashlib.sha256(data).hexdigest()}"
    assert entry["size"] == len(data)
    assert (entry["format"], entry["can_run_code"]) == ("pytorch-zip", True)


@pytest.mark.parametrize("zipped", [False, True])
def test_scanning_a_path_matches_scanning_its_bytes(
    craft: ModuleType, tmp_path: Path, zipped: bool
) -> None:
    data = craft.pytorch_zip(craft.dangerous()) if zipped else craft.dangerous()
    path = tmp_path / ("dangerous.pt" if zipped else "dangerous.pkl")
    path.write_bytes(data)
    expected = pickle_scan.scan(data, path.name)
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(Path, "read_bytes", _forbidden)
        assert pickle_scan.scan_path(path) == expected


def test_a_stopped_scan_from_a_path_keeps_its_position(craft: ModuleType, tmp_path: Path) -> None:
    path = tmp_path / "model.joblib"
    path.write_bytes(craft.joblib_style())
    report = pickle_scan.scan_path(path)
    assert report.complete is False
    assert report.position == len(craft.JOBLIB_HEADER)


def _forbidden(self: Path) -> bytes:
    raise AssertionError(f"a weight file was read whole: {self.name}")


def test_a_check_scans_local_files_without_reading_them_whole(
    craft: ModuleType, tmp_path: Path, no_whole_reads: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    def bytes_scan(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("the check must scan from the file, not from its bytes")

    monkeypatch.setattr(pickle_scan, "scan", bytes_scan)
    data = craft.dangerous()
    (tmp_path / "dangerous.pkl").write_bytes(data)
    entry = {
        "kind": "weight_file",
        "identifier": f"sha256:{hashlib.sha256(data).hexdigest()}",
        "pinned": True,
        "location": "dangerous.pkl",
        "size": len(data),
        "format": "pickle",
        "can_run_code": True,
    }
    with Store(tmp_path / "md.db", now=lambda: MOMENT) as store:
        store.add_model("m")
        store.add_version("m", {}, "0" * 64, [entry], base_dir=tmp_path)
        run_check(store, RecordedFetcher(tmp_path / "none"), ["m"], ["picklescan"])
        [alert] = store.alerts_for("m")
    assert alert["cause"]["dangerous"] == ["os.system"]


def test_a_file_changed_while_scanned_gives_no_report_against_the_pinned_hash(
    craft: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Review D3: the file is changed in place after it is hashed and before the scanner reads
    it. The scan saw other bytes than the pinned ones, so it is discarded: no alert is raised
    against the pinned hash, and the run records a hash mismatch with the hash it read last."""
    pinned = craft.innocuous()
    changed = craft.dangerous()
    path = tmp_path / "model.pkl"
    path.write_bytes(pinned)
    original = pickle_scan.scanner.scan_bytes

    def change_then_scan(stream: Any, *args: Any, **kwargs: Any) -> Any:
        path.write_bytes(changed)  # another writer, through its own handle
        return original(stream, *args, **kwargs)

    monkeypatch.setattr(pickle_scan.scanner, "scan_bytes", change_then_scan)
    identifier = f"sha256:{hashlib.sha256(pinned).hexdigest()}"
    entry = {
        "kind": "weight_file",
        "identifier": identifier,
        "pinned": True,
        "location": "model.pkl",
        "size": len(pinned),
        "format": "pickle",
        "can_run_code": True,
    }
    with Store(tmp_path / "md.db", now=lambda: MOMENT) as store:
        store.add_model("m")
        store.add_version("m", {}, "0" * 64, [entry], base_dir=tmp_path)
        run_check(store, RecordedFetcher(tmp_path / "none"), ["m"], ["picklescan"])
        assert store.alerts_for("m") == []
        [event] = [e for e in store.watch_events("m") if e["kind"] == "hash_mismatch"]
    assert event["entry_identifier"] == identifier
    assert event["detail"]["actual_sha256"] == hashlib.sha256(changed).hexdigest()

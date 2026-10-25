"""The picklescan adapter (T036; research R4, FR-011).

The dangerous fixtures are built into ``tmp_path`` at test time and never committed (see
``tests/fixtures/pickles/NOTES.md``); nothing here is ever unpickled.
"""

from __future__ import annotations

import pickle
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from model_dependabot.sources import pickle_scan

PICKLES = Path(__file__).resolve().parent.parent / "fixtures" / "pickles"


def _no_unpickling(*args: object, **kwargs: object) -> None:
    raise AssertionError("the adapter must never unpickle a file")


@pytest.fixture(autouse=True)
def _forbid_unpickling(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("load", "loads", "Unpickler"):
        monkeypatch.setattr(pickle, name, _no_unpickling)


@pytest.fixture
def calls(monkeypatch: pytest.MonkeyPatch) -> list[tuple[Any, ...]]:
    seen: list[tuple[Any, ...]] = []
    original = pickle_scan.scanner.scan_bytes

    def recording(data: Any, file_id: Any, file_ext: Any = None, strict: bool = False) -> Any:
        seen.append((file_id, file_ext))
        return original(data, file_id, file_ext, strict=strict)

    monkeypatch.setattr(pickle_scan.scanner, "scan_bytes", recording)
    return seen


def test_dangerous_global_is_named_as_evidence(
    craft: ModuleType, tmp_path: Path, calls: list[tuple[Any, ...]]
) -> None:
    path = tmp_path / "dangerous.pkl"
    path.write_bytes(craft.dangerous())
    report = pickle_scan.scan(path.read_bytes(), path.name)
    assert calls == [("dangerous.pkl", ".pkl")]
    assert report.dangerous == ["os.system"]
    assert report.suspicious == []
    assert report.complete is True
    assert report.position == len(craft.dangerous())
    assert (report.scanner, report.scanner_version) == ("picklescan", "1.0.5")
    record = report.as_record()
    assert {"module": "os", "name": "system", "safety": "dangerous"} in record["globals"]


def test_pytorch_zip_wrapped_dangerous_pickle(
    craft: ModuleType, tmp_path: Path, calls: list[tuple[Any, ...]]
) -> None:
    path = tmp_path / "dangerous.pt"
    path.write_bytes(craft.pytorch_zip(craft.dangerous()))
    report = pickle_scan.scan(path.read_bytes(), path.name)
    assert calls == [("dangerous.pt", ".pt")]
    assert report.dangerous == ["os.system"]
    assert report.complete is True


def test_innocuous_globals_only(craft: ModuleType, calls: list[tuple[Any, ...]]) -> None:
    report = pickle_scan.scan((PICKLES / "innocuous.pkl").read_bytes(), "innocuous.pkl")
    assert report.innocuous == ["collections.OrderedDict", "torch._utils._rebuild_tensor_v2"]
    assert report.dangerous == [] and report.suspicious == []
    assert report.complete is True


def test_suspicious_global(craft: ModuleType) -> None:
    report = pickle_scan.scan((PICKLES / "suspicious.pkl").read_bytes(), "suspicious.pkl")
    assert report.suspicious == ["model_dependabot_fixture.layers.CustomLayer"]
    assert report.dangerous == []


def test_extension_decides_the_scanner_path(
    craft: ModuleType, calls: list[tuple[Any, ...]]
) -> None:
    pickle_scan.scan(craft.innocuous(), "weights/model.BIN")
    assert calls == [("weights/model.BIN", ".bin")]


@pytest.mark.parametrize("name", ["innocuous.pkl", "suspicious.pkl", "joblib-style.joblib"])
def test_committed_fixtures_match_the_builder(craft: ModuleType, name: str) -> None:
    assert (PICKLES / name).read_bytes() == craft.COMMITTED[name]()


def test_no_dangerous_fixture_is_committed() -> None:
    names = {path.name for path in PICKLES.iterdir() if path.name != "__pycache__"}
    assert names == {
        "craft.py",
        "NOTES.md",
        "innocuous.pkl",
        "suspicious.pkl",
        "joblib-style.joblib",
    }

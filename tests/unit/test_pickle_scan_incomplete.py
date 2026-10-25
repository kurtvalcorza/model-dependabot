"""A scanner that stops early is a ``scan_incomplete`` watch event, never clean (T039b; FR-022)."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType

from model_dependabot.lifecycle import run_check
from model_dependabot.sources import pickle_scan
from model_dependabot.sources.fetcher import RecordedFetcher
from model_dependabot.store import Store

PICKLES = Path(__file__).resolve().parent.parent / "fixtures" / "pickles"


def test_joblib_style_file_stops_at_the_array_bytes(craft: ModuleType) -> None:
    data = (PICKLES / "joblib-style.joblib").read_bytes()
    report = pickle_scan.scan(data, "model.joblib")
    assert report.complete is False
    assert report.position == len(craft.JOBLIB_HEADER)  # the first raw array byte
    assert report.position < len(data)
    assert report.error is not None
    assert report.scanner == "picklescan"


def test_bytes_that_are_not_a_pickle_are_never_clean() -> None:
    report = pickle_scan.scan(b"\xff\xfe not a pickle", "model.pkl")
    assert report.complete is False
    assert report.position == 0


def test_scan_incomplete_watch_event(tmp_path: Path) -> None:
    data = (PICKLES / "joblib-style.joblib").read_bytes()
    (tmp_path / "model.joblib").write_bytes(data)

    entry = {
        "kind": "weight_file",
        "identifier": f"sha256:{hashlib.sha256(data).hexdigest()}",
        "pinned": True,
        "location": "model.joblib",
        "size": len(data),
        "format": "joblib",
        "can_run_code": True,
    }
    moment = datetime(2026, 10, 24, 8, 0, tzinfo=UTC)
    with Store(tmp_path / "md.db", now=lambda: moment) as store:
        store.add_model("m")
        store.add_version("m", {}, "0" * 64, [entry], base_dir=tmp_path)
        outcome = run_check(store, RecordedFetcher(tmp_path), ["m"], ["picklescan"])
        assert outcome.sources == {"picklescan": "ok"}
        events = {event["kind"]: event for event in store.watch_events("m")}
        assert store.alerts_for("m") == []
    assert set(events) == {"pickle_format", "scan_suspicious", "scan_incomplete"}
    incomplete = events["scan_incomplete"]
    assert incomplete["detail"]["scanner"] == "picklescan"
    assert incomplete["detail"]["position"] == 43
    assert incomplete["detail"]["size"] == len(data)
    [evidence] = incomplete["evidence"]
    assert evidence["source"] == "picklescan"
    assert evidence["matched_identifier"] == entry["identifier"]


def test_an_unreadable_file_is_incomplete_not_clean(tmp_path: Path) -> None:
    entry = {
        "kind": "weight_file",
        "identifier": "sha256:" + "ab" * 32,
        "pinned": True,
        "location": "gone.pkl",
        "format": "pickle",
        "can_run_code": True,
    }
    with Store(tmp_path / "md.db") as store:
        store.add_model("m")
        store.add_version("m", {}, "0" * 64, [entry], base_dir=tmp_path)
        run_check(store, RecordedFetcher(tmp_path), ["m"], ["picklescan"])
        kinds = {event["kind"]: event for event in store.watch_events("m")}
    assert kinds["scan_incomplete"]["detail"]["position"] == 0
    assert "cannot read" in kinds["scan_incomplete"]["detail"]["reason"]

"""The hub's scan verdicts (T037; FR-012, FR-013, research R5).

``eicar-security`` and ``eicar-tree-expand`` are real anonymous recordings of a public test
repository whose files carry real ``unsafe`` verdicts; those files are outside LFS, so the hub
publishes no SHA-256 for them. The unsafe verdict for a file whose SHA-256 matches, and the
pending, missing, unrecognised and mismatched answers, are derived from the real recordings by the
``derive_hf`` fixture (see ``tests/fixtures/hf/NOTES.md``).
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from conftest import EICAR_BIN_SHA256, EICAR_COMMIT, EICAR_REPO, HF_FIXTURES
from model_dependabot.lifecycle import run_check
from model_dependabot.sources import hf
from model_dependabot.sources.fetcher import RecordedFetcher
from model_dependabot.store import Store

MOMENT = datetime(2026, 10, 24, 8, 0, tzinfo=UTC)


def hub_entry(file: str, sha256: str) -> dict[str, Any]:
    return {
        "kind": "weight_file",
        "identifier": f"sha256:{sha256}",
        "pinned": True,
        "location": hf.resolve_url(EICAR_REPO, EICAR_COMMIT, file),
        "format": "pickle",
        "can_run_code": True,
        "hub_repo": EICAR_REPO,
        "hub_revision": EICAR_COMMIT,
        "hub_file": file,
    }


BIN = hub_entry("pytorch_model.bin", EICAR_BIN_SHA256)


def flag_bin(level: str) -> Callable[[Any], Any]:
    def change(info: Any) -> Any:
        info["securityRepoStatus"]["filesWithIssues"].append(
            {"path": "pytorch_model.bin", "level": level}
        )
        return info

    return change


def bin_status(status: str) -> Callable[[Any], Any]:
    def change(items: Any) -> Any:
        for item in items:
            if item["path"] == "pytorch_model.bin":
                item["securityFileStatus"]["status"] = status
                item["securityFileStatus"]["pickleImportScan"]["status"] = status
        return items

    return change


@pytest.fixture
def store(tmp_path: Path) -> Store:
    with Store(tmp_path / "md.db", now=lambda: MOMENT) as opened:
        opened.add_model("m")
        yield opened


def check(store: Store, root: Path, entries: list[dict[str, Any]]) -> Any:
    store.add_version("m", {}, "0" * 64, entries)
    return run_check(store, RecordedFetcher(root), ["m"], ["hf-scan"])


def kinds(store: Store) -> dict[str, dict[str, Any]]:
    return {event["kind"]: event for event in store.watch_events("m")}


# --- the adapter, on the real recordings ---------------------------------------------------------


def test_real_status_lists_real_unsafe_verdicts() -> None:
    security = hf.HubSecurity(RecordedFetcher(HF_FIXTURES))
    status = security.status(EICAR_REPO)
    assert status.state == "answered"
    assert status.commit == EICAR_COMMIT
    assert status.levels["model_broken_X.pkl"] == "unsafe"
    assert status.levels["build_pickles.py"] == "caution"
    verdict = security.verdict(status, "model_broken_X.pkl")
    assert verdict.state == "unsafe"
    assert verdict.hub_sha256 is None  # outside LFS: the hub gives no SHA-256
    assert verdict.scanners["pickleImportScan"] == "unsafe"
    assert security.verdict(status, "pytorch_model.bin").state == "clean"


def test_real_clean_answer() -> None:
    security = hf.HubSecurity(RecordedFetcher(HF_FIXTURES))
    status = security.status("openai-community/gpt2")
    assert (status.state, status.levels) == ("answered", {})
    assert security.verdict(status, "pytorch_model.bin").state == "clean"


# --- check runs ----------------------------------------------------------------------------------


def test_unsafe_verdict_with_matching_hash_raises_a_hub_scan_alert(
    store: Store, derive_hf: Callable[..., Path]
) -> None:
    root = derive_hf(security=flag_bin("unsafe"), tree=bin_status("unsafe"))
    outcome = check(store, root, [BIN])
    assert outcome.sources == {"hf-scan": "ok"}
    [alert] = store.alerts_for("m")
    assert alert["kind"] == "hub_scan"
    assert (alert["severity"], alert["severity_origin"]) == ("HIGH", "policy")
    assert alert["cause_key"] == f"hub_scan:{EICAR_BIN_SHA256}"
    cause = alert["cause"]
    assert cause["verdict"] == "unsafe"
    assert cause["scanners"]["pickleImportScan"] == "unsafe"
    assert cause["location"] == BIN["location"]
    assert cause["hub_commit"] == EICAR_COMMIT
    evidence = store.alert_evidence(alert["alert_id"])
    assert [e["url"] for e in evidence] == [
        f"https://huggingface.co/api/models/{EICAR_REPO}?securityStatus=true",
        f"https://huggingface.co/api/models/{EICAR_REPO}/tree/{EICAR_COMMIT}?expand=true",
    ]
    assert [e["retrieved_at"] for e in evidence] == ["2026-10-24T04:24:59Z", "2026-10-24T04:25:00Z"]
    for record in evidence:
        assert record["source"] == "huggingface.co"
        assert record["matched_identifier"] == BIN["identifier"]
        assert record["detail"]["verdict"] == "unsafe"
    assert set(kinds(store)) == {"pickle_format"}


def test_real_recordings_raise_nothing_for_a_clean_file(
    store: Store, derive_hf: Callable[..., Path]
) -> None:
    check(store, derive_hf(), [BIN])
    assert store.alerts_for("m") == []
    assert set(kinds(store)) == {"pickle_format"}


def test_real_unsafe_verdict_without_a_hub_sha256_is_a_hash_mismatch(
    store: Store, derive_hf: Callable[..., Path]
) -> None:
    check(store, derive_hf(), [hub_entry("model_broken_X.pkl", "cd" * 32)])
    assert store.alerts_for("m") == []
    event = kinds(store)["hash_mismatch"]
    assert event["detail"]["verdict"] == "unsafe"
    assert event["detail"]["hub_sha256"] is None


def test_unsafe_verdict_for_a_different_hash_is_a_hash_mismatch(
    store: Store, derive_hf: Callable[..., Path]
) -> None:
    def changed_file(items: Any) -> Any:
        for item in items:
            if item["path"] == "pytorch_model.bin":
                item["lfs"]["oid"] = "ef" * 32
        return items

    root = derive_hf(security=flag_bin("unsafe"), tree=changed_file)
    check(store, root, [BIN])
    assert store.alerts_for("m") == []
    event = kinds(store)["hash_mismatch"]
    assert (event["detail"]["inventory_sha256"], event["detail"]["hub_sha256"]) == (
        EICAR_BIN_SHA256,
        "ef" * 32,
    )


def _pending(info: Any) -> Any:
    info["securityRepoStatus"]["scansDone"] = False
    return info


def _missing(info: Any) -> Any:
    del info["securityRepoStatus"]
    return info


@pytest.mark.parametrize(
    ("change", "state"),
    [(_pending, "pending"), (_missing, "missing"), (flag_bin("quarantined"), "unrecognised")],
)
def test_unconfirmed_verdicts_are_hub_scan_unknown(
    store: Store, derive_hf: Callable[..., Path], change: Callable[[Any], Any], state: str
) -> None:
    check(store, derive_hf(security=change), [BIN])
    assert store.alerts_for("m") == []
    event = kinds(store)["hub_scan_unknown"]
    assert event["detail"]["verdict"] == state


def test_caution_with_matching_hash_is_a_suspicious_watch_event(
    store: Store, derive_hf: Callable[..., Path]
) -> None:
    check(store, derive_hf(security=flag_bin("caution")), [BIN])
    assert store.alerts_for("m") == []
    assert kinds(store)["scan_suspicious"]["detail"]["scanner"] == "hf-scan"


def test_a_failed_hub_changes_nothing(store: Store, derive_hf: Callable[..., Path]) -> None:
    root = derive_hf(errors={"eicar-security": "timed out"})
    outcome = check(store, root, [BIN])
    assert outcome.sources["hf-scan"] == "failed: timed out"
    assert store.alerts_for("m") == []
    assert set(kinds(store)) == {"pickle_format"}  # from the inventory, not from the hub

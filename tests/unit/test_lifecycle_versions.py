"""Re-evaluation of open alerts when a newer version is registered (T043; FR-014, SC-004).

Registration compares the new inventory with the open alerts of the model and consults no source:
``reevaluate_version`` takes no fetcher at all, and the recorded fetcher used by the checks before
it sees no further request.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from model_dependabot.lifecycle import reevaluate_version, run_check
from model_dependabot.sources.fetcher import RecordedFetcher
from model_dependabot.store import Store

OSV = Path(__file__).resolve().parent.parent / "fixtures" / "osv"
MOMENT = datetime(2026, 10, 24, 8, 0, tzinfo=UTC)
CP9V = "GHSA-cp9v-662q-vvx9"
R24 = "GHSA-24rc-8hj2-v98c"


def _package(name: str, version: str) -> dict[str, Any]:
    return {
        "kind": "package",
        "identifier": f"pkg:pypi/{name}@{version}",
        "pinned": True,
        "name": name,
        "version": version,
        "hashes": ["sha256:" + "0" * 64],
    }


VULNERABLE = [_package("pillow", "12.3.0"), _package("validators", "0.12.2")]
FIXED = [_package("pillow", "13.0.0"), _package("validators", "0.12.2")]
STILL_AFFECTED = [_package("pillow", "12.3.1"), _package("validators", "0.12.2")]


def weight(directory: Path, name: str, data: bytes, file_format: str, code: bool) -> dict[str, Any]:
    (directory / name).write_bytes(data)
    return {
        "kind": "weight_file",
        "identifier": f"sha256:{hashlib.sha256(data).hexdigest()}",
        "pinned": True,
        "location": name,
        "size": len(data),
        "format": file_format,
        "can_run_code": code,
    }


@pytest.fixture
def store(tmp_path: Path) -> Store:
    with Store(tmp_path / "md.db", now=lambda: MOMENT) as opened:
        opened.add_model("m")
        yield opened


def register(store: Store, entries: list[dict[str, Any]], base: Path | None = None) -> int:
    version = store.add_version("m", {"bomFormat": "CycloneDX"}, "0" * 64, entries, base_dir=base)
    reevaluate_version(store, "m", version)
    return version


def by_advisory(store: Store) -> dict[str, dict[str, Any]]:
    return {alert["cause"]["advisory_id"]: alert for alert in store.alerts_for("m")}


def test_a_new_version_without_the_cause_closes_the_alert_as_fixed(store: Store) -> None:
    register(store, VULNERABLE)
    fetcher = RecordedFetcher(OSV)
    run_check(store, fetcher, ["m"], ["osv"])
    seen = len(fetcher.requests)
    opened = by_advisory(store)
    assert sorted(opened) == [R24, CP9V]
    first_evidence = {key: alert["evidence_ids"] for key, alert in opened.items()}

    version = store.add_version("m", {"bomFormat": "CycloneDX", "v": 2}, "1" * 64, FIXED)
    result = reevaluate_version(store, "m", version)
    assert len(fetcher.requests) == seen  # no source request at registration
    assert store.latest_check_run()["run_id"] == 1  # and no check run

    closed = by_advisory(store)
    assert sorted(result["fixed"]) == sorted(alert["alert_id"] for alert in closed.values())
    assert result["carried_forward"] == []
    for key, alert in closed.items():
        assert alert["state"] == "fixed"
        assert alert["closed_by_version"] == 2
        assert alert["closed_at"] == "2026-10-24T08:00:00Z"
        assert alert["current_version"] == 1
        assert alert["evidence_ids"][: len(first_evidence[key])] == first_evidence[key]
        inventory = store.alert_evidence(alert["alert_id"])[-1]
        assert inventory["source"] == "inventory"
        assert inventory["matched_identifier"] == "pkg:pypi/pillow@12.3.0"
        assert inventory["detail"]["version"] == 2
        assert inventory["detail"]["found"] == "pkg:pypi/pillow@13.0.0"
        assert json.loads(store.read_body(inventory["body_sha256"])) == {
            "bomFormat": "CycloneDX",
            "v": 2,
        }


def test_a_new_version_without_the_package_closes_the_alert_as_fixed(store: Store) -> None:
    register(store, VULNERABLE)
    run_check(store, RecordedFetcher(OSV), ["m"], ["osv"])
    register(store, [_package("validators", "0.12.2")])
    alerts = by_advisory(store)
    assert {alert["state"] for alert in alerts.values()} == {"fixed"}
    assert store.alert_evidence(alerts[CP9V]["alert_id"])[-1]["detail"]["found"] is None


def test_a_new_version_still_affected_carries_the_alert_forward(store: Store) -> None:
    register(store, VULNERABLE)
    fetcher = RecordedFetcher(OSV)
    run_check(store, fetcher, ["m"], ["osv"])
    seen = len(fetcher.requests)
    before = by_advisory(store)

    version = store.add_version("m", {}, "1" * 64, STILL_AFFECTED)
    result = reevaluate_version(store, "m", version)
    assert len(fetcher.requests) == seen
    after = by_advisory(store)
    assert sorted(result["carried_forward"]) == sorted(a["alert_id"] for a in before.values())
    assert result["fixed"] == []
    for key, alert in after.items():
        assert alert["alert_id"] == before[key]["alert_id"]
        assert alert["state"] == "open"
        assert (alert["opened_in_version"], alert["current_version"]) == (1, 2)
        assert alert["cause"]["version"] == "12.3.1"
        assert alert["cause"]["identifier"] == "pkg:pypi/pillow@12.3.1"
        assert alert["evidence_ids"] == before[key]["evidence_ids"]


def test_an_unpinned_package_is_not_proof_the_cause_is_gone(store: Store) -> None:
    register(store, VULNERABLE)
    run_check(store, RecordedFetcher(OSV), ["m"], ["osv"])
    gap = {"kind": "package", "pinned": False, "name": "Pillow", "gap_reason": "no exact version"}
    register(store, [gap])
    assert {alert["state"] for alert in by_advisory(store).values()} == {"open"}


def test_a_cause_found_again_opens_a_new_alert_and_keeps_the_old_one(store: Store) -> None:
    register(store, VULNERABLE)
    run_check(store, RecordedFetcher(OSV), ["m"], ["osv"])
    old = by_advisory(store)[CP9V]
    register(store, FIXED)
    register(store, VULNERABLE)
    assert store.get_alert(old["alert_id"])["state"] == "fixed"  # registration opens nothing
    run_check(store, RecordedFetcher(OSV), ["m"], ["osv"])

    cp9v = [alert for alert in store.alerts_for("m") if alert["cause"]["advisory_id"] == CP9V]
    assert [alert["state"] for alert in cp9v] == ["fixed", "open"]
    kept, new = cp9v
    assert (kept["alert_id"], kept["closed_by_version"]) == (old["alert_id"], 2)
    assert new["alert_id"] != old["alert_id"]
    assert (new["opened_in_version"], new["current_version"]) == (3, 3)


def test_a_weight_file_alert_is_fixed_by_a_version_without_the_file(
    store: Store, tmp_path: Path, craft: ModuleType
) -> None:
    dangerous = weight(tmp_path, "model.pkl", craft.dangerous(), "pickle", True)
    innocuous = weight(tmp_path, "clean.pkl", craft.innocuous(), "pickle", True)
    register(store, [dangerous], tmp_path)
    run_check(store, RecordedFetcher(tmp_path / "none"), ["m"], ["picklescan"])
    [alert] = store.alerts_for("m")
    assert alert["kind"] == "weight_file_scan"

    register(store, [dangerous, innocuous], tmp_path)
    carried = store.get_alert(alert["alert_id"])
    assert (carried["state"], carried["current_version"]) == ("open", 2)

    register(store, [innocuous], tmp_path)
    fixed = store.get_alert(alert["alert_id"])
    assert (fixed["state"], fixed["closed_by_version"]) == ("fixed", 3)
    evidence = store.alert_evidence(alert["alert_id"])[-1]
    assert evidence["source"] == "inventory"
    assert evidence["matched_identifier"] == dangerous["identifier"]


def test_a_code_free_sibling_in_a_new_version_fixes_the_format_policy_alert(
    store: Store, tmp_path: Path, craft: ModuleType
) -> None:
    store.set_format_policy("m", "strict", set_by="Model owner")
    pickled = weight(tmp_path, "model.pkl", craft.innocuous(), "pickle", True)
    sibling = weight(tmp_path, "model.safetensors", b"{}", "safetensors", False)
    register(store, [pickled], tmp_path)
    run_check(store, RecordedFetcher(tmp_path / "none"), ["m"], ["picklescan"])
    [alert] = store.alerts_for("m")
    assert alert["kind"] == "format_policy"

    register(store, [pickled, sibling], tmp_path)
    fixed = store.get_alert(alert["alert_id"])
    assert (fixed["state"], fixed["closed_by_version"]) == ("fixed", 2)
    detail = store.alert_evidence(alert["alert_id"])[-1]["detail"]
    assert detail["code_free_beside"] == [sibling["identifier"]]


def test_the_first_version_has_nothing_to_reevaluate(store: Store) -> None:
    version = store.add_version("m", {}, "0" * 64, VULNERABLE)
    assert reevaluate_version(store, "m", version) == {"fixed": [], "carried_forward": []}

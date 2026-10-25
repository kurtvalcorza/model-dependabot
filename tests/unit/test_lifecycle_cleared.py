"""Alerts the source itself clears (T043a; FR-016, FR-023, constitution III 1.0.2).

Every changed source state is derived from the real recordings by ``derive_osv`` and ``derive_hf``
and written out in the test that uses it.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from conftest import EICAR_BIN_SHA256, EICAR_COMMIT, EICAR_REPO
from model_dependabot.lifecycle import run_check
from model_dependabot.sources import hf
from model_dependabot.sources.fetcher import RecordedFetcher
from model_dependabot.store import Store

OSV = Path(__file__).resolve().parent.parent / "fixtures" / "osv"
MOMENT = datetime(2026, 10, 24, 8, 0, tzinfo=UTC)
PILLOW = "pkg:pypi/pillow@12.3.0"
CP9V = "GHSA-cp9v-662q-vvx9"
R24 = "GHSA-24rc-8hj2-v98c"
WITHDRAWN = "PYSEC-2019-64"


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


@pytest.fixture
def store(tmp_path: Path) -> Store:
    with Store(tmp_path / "md.db", now=lambda: MOMENT) as opened:
        opened.add_model("m")
        yield opened


def osv_check(store: Store, root: Path) -> Any:
    return run_check(store, RecordedFetcher(root), ["m"], ["osv"])


def by_advisory(store: Store) -> dict[str, dict[str, Any]]:
    return {alert["cause"]["advisory_id"]: alert for alert in store.alerts_for("m")}


def narrowed(advisory: dict[str, Any]) -> dict[str, Any]:
    """The record after the source narrows its range so that 12.3.0 is no longer affected."""
    affected = advisory["affected"][0]
    affected["ranges"][0]["events"] = [{"introduced": "12.0.0"}, {"fixed": "12.3.0"}]
    affected["versions"] = ["12.0.0", "12.1.0", "12.1.1", "12.2.0"]
    advisory["modified"] = "2026-10-25T00:00:00Z"
    return advisory


def unlisted(answer: dict[str, Any]) -> dict[str, Any]:
    """The batch answer once OSV no longer lists the advisory for pillow 12.3.0."""
    answer["results"][0]["vulns"] = [v for v in answer["results"][0]["vulns"] if v["id"] != CP9V]
    return answer


@pytest.fixture
def opened(store: Store) -> dict[str, dict[str, Any]]:
    store.add_version("m", {}, "0" * 64, VULNERABLE)
    osv_check(store, OSV)
    alerts = by_advisory(store)
    assert sorted(alerts) == [R24, CP9V]
    return alerts


# --- advisories ----------------------------------------------------------------------------------


def test_narrowed_ranges_with_both_agreeing_clear_the_alert(
    store: Store, opened: dict[str, dict[str, Any]], derive_osv: Callable[..., Path]
) -> None:
    root = derive_osv({"querybatch-vulnerable": unlisted, f"vuln-{CP9V}": narrowed})
    outcome = osv_check(store, root)
    assert outcome.sources == {"osv": "ok"}
    alert = store.get_alert(opened[CP9V]["alert_id"])
    assert alert["state"] == "cleared"
    assert alert["closed_at"] == "2026-10-24T08:00:00Z"
    assert alert["closed_by_version"] is None
    assert alert["alert_id"] in outcome.models[0]["closed"]
    evidence = store.alert_evidence(alert["alert_id"])
    assert len(evidence) == 2  # the earlier record is kept
    observed = evidence[-1]
    assert observed["url"] == f"https://api.osv.dev/v1/vulns/{CP9V}"
    assert observed["matched_identifier"] == PILLOW
    assert (observed["detail"]["osv_match"], observed["detail"]["local_match"]) == (False, False)
    body = json.loads(store.read_body(observed["body_sha256"]))
    assert body["affected"][0]["ranges"][0]["events"][-1] == {"fixed": "12.3.0"}
    assert store.get_alert(opened[R24]["alert_id"])["state"] == "open"
    assert store.watch_events("m") == []


def test_only_the_local_evaluation_agreeing_leaves_the_alert_open(
    store: Store, opened: dict[str, dict[str, Any]], derive_osv: Callable[..., Path]
) -> None:
    osv_check(store, derive_osv({f"vuln-{CP9V}": narrowed}))  # OSV still lists it
    assert store.get_alert(opened[CP9V]["alert_id"])["state"] == "open"
    [event] = store.watch_events("m")
    assert event["kind"] == "advisory_unmatched"
    assert event["detail"]["advisories"][CP9V] == {"osv_match": True, "local_match": False}


def test_only_osv_agreeing_leaves_the_alert_open(
    store: Store, opened: dict[str, dict[str, Any]], derive_osv: Callable[..., Path]
) -> None:
    osv_check(store, derive_osv({"querybatch-vulnerable": unlisted}))  # ranges unchanged
    assert store.get_alert(opened[CP9V]["alert_id"])["state"] == "open"
    [event] = store.watch_events("m")
    assert event["kind"] == "advisory_unmatched"
    assert event["detail"]["advisories"][CP9V] == {"osv_match": False, "local_match": True}


@pytest.mark.parametrize("failing", ["querybatch-vulnerable", f"vuln-{CP9V}", f"vuln-{R24}"])
def test_a_failed_source_clears_nothing(
    store: Store,
    opened: dict[str, dict[str, Any]],
    derive_osv: Callable[..., Path],
    failing: str,
) -> None:
    changes = {"querybatch-vulnerable": unlisted, f"vuln-{CP9V}": narrowed}
    outcome = osv_check(store, derive_osv(changes, errors={failing: "timed out"}))
    assert outcome.sources["osv"] == "failed: timed out"
    assert {alert["state"] for alert in store.alerts_for("m")} == {"open"}
    assert len(store.alert_evidence(opened[CP9V]["alert_id"])) == 1


def test_a_withdrawn_advisory_still_closes_as_withdrawn(
    store: Store, derive_osv: Callable[..., Path]
) -> None:
    def listed(answer: dict[str, Any]) -> dict[str, Any]:
        answer["results"][1]["vulns"] = [{"id": WITHDRAWN, "modified": "2019-04-01T00:00:00Z"}]
        return answer

    def before_withdrawal(advisory: dict[str, Any]) -> dict[str, Any]:
        advisory.pop("withdrawn")
        return advisory

    store.add_version("m", {}, "0" * 64, VULNERABLE)
    changes = {"querybatch-vulnerable": listed, f"vuln-{WITHDRAWN}": before_withdrawal}
    osv_check(store, derive_osv(changes))
    alert = by_advisory(store)[WITHDRAWN]
    osv_check(store, OSV)  # no longer listed, and withdrawn
    assert store.get_alert(alert["alert_id"])["state"] == "withdrawn"


# --- hub verdicts --------------------------------------------------------------------------------

BIN = {
    "kind": "weight_file",
    "identifier": f"sha256:{EICAR_BIN_SHA256}",
    "pinned": True,
    "location": hf.resolve_url(EICAR_REPO, EICAR_COMMIT, "pytorch_model.bin"),
    "format": "pickle",
    "can_run_code": True,
    "hub_repo": EICAR_REPO,
    "hub_revision": EICAR_COMMIT,
    "hub_file": "pytorch_model.bin",
}


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


def hub_check(store: Store, root: Path) -> Any:
    return run_check(store, RecordedFetcher(root), ["m"], ["hf-scan"])


@pytest.fixture
def hub_alert(store: Store, derive_hf: Callable[..., Path]) -> dict[str, Any]:
    store.add_version("m", {}, "0" * 64, [BIN])
    hub_check(store, derive_hf(security=flag_bin("unsafe"), tree=bin_status("unsafe")))
    [alert] = store.alerts_for("m")
    assert (alert["kind"], alert["state"]) == ("hub_scan", "open")
    return alert


def test_an_explicit_safe_verdict_for_the_matching_hash_clears_the_hub_alert(
    store: Store, hub_alert: dict[str, Any], derive_hf: Callable[..., Path]
) -> None:
    outcome = hub_check(store, derive_hf())  # the real recordings: the file is listed as safe
    assert outcome.sources == {"hf-scan": "ok"}
    alert = store.get_alert(hub_alert["alert_id"])
    assert alert["state"] == "cleared"
    assert alert["alert_id"] in outcome.models[0]["closed"]
    evidence = store.alert_evidence(alert["alert_id"])
    assert len(evidence) == 4  # the unsafe verdict's two records, then the safe verdict's two
    status, tree = evidence[2:]
    assert status["url"] == f"https://huggingface.co/api/models/{EICAR_REPO}?securityStatus=true"
    assert tree["url"].endswith(f"/tree/{EICAR_COMMIT}?expand=true")
    for record in (status, tree):
        assert record["detail"]["verdict"] == "clean"
        assert record["detail"]["file_status"] == "safe"
        assert record["detail"]["hub_sha256"] == EICAR_BIN_SHA256
        assert record["matched_identifier"] == BIN["identifier"]


def _pending(info: Any) -> Any:
    info["securityRepoStatus"]["scansDone"] = False
    return info


def _missing(info: Any) -> Any:
    del info["securityRepoStatus"]
    return info


def _other_hash(items: Any) -> Any:
    for item in items:
        if item["path"] == "pytorch_model.bin":
            item["lfs"]["oid"] = "ef" * 32
    return items


@pytest.mark.parametrize(
    ("security", "tree"),
    [
        (_pending, None),
        (_missing, None),
        (flag_bin("quarantined"), None),
        (flag_bin("caution"), None),
        (None, _other_hash),
        (None, bin_status("unscanned")),
    ],
    ids=["pending", "missing", "unrecognised", "caution", "other-hash", "not-explicit"],
)
def test_anything_short_of_an_explicit_safe_verdict_changes_nothing(
    store: Store,
    hub_alert: dict[str, Any],
    derive_hf: Callable[..., Path],
    security: Callable[[Any], Any] | None,
    tree: Callable[[Any], Any] | None,
) -> None:
    hub_check(store, derive_hf(security=security, tree=tree))
    assert store.get_alert(hub_alert["alert_id"])["state"] == "open"


@pytest.mark.parametrize("failing", ["eicar-security", "eicar-tree-expand"])
def test_a_failed_hub_clears_nothing(
    store: Store, hub_alert: dict[str, Any], derive_hf: Callable[..., Path], failing: str
) -> None:
    outcome = hub_check(store, derive_hf(errors={failing: "timed out"}))
    assert outcome.sources["hf-scan"] == "failed: timed out"
    assert store.get_alert(hub_alert["alert_id"])["state"] == "open"
    assert len(store.alert_evidence(hub_alert["alert_id"])) == 2


# --- the owner's format policy (orchestrator disposition under constitution III 1.0.2) ----------


def test_switching_the_policy_back_to_default_clears_the_format_policy_alert(
    store: Store, tmp_path: Path, craft: ModuleType
) -> None:
    data = craft.innocuous()
    (tmp_path / "model.pkl").write_bytes(data)
    entry = {
        "kind": "weight_file",
        "identifier": f"sha256:{hashlib.sha256(data).hexdigest()}",
        "pinned": True,
        "location": "model.pkl",
        "size": len(data),
        "format": "pickle",
        "can_run_code": True,
    }
    store.set_format_policy("m", "strict", set_by="Model owner")
    store.add_version("m", {}, "0" * 64, [entry], base_dir=tmp_path)
    fetcher = RecordedFetcher(tmp_path / "none")
    run_check(store, fetcher, ["m"], ["picklescan"])
    [alert] = store.alerts_for("m")
    assert alert["kind"] == "format_policy"

    run_check(store, fetcher, ["m"], ["picklescan"])  # still strict: still open
    assert store.get_alert(alert["alert_id"])["state"] == "open"

    store.set_format_policy("m", "default", set_by="Security lead")
    outcome = run_check(store, fetcher, ["m"], ["picklescan"])
    closed = store.get_alert(alert["alert_id"])
    assert closed["state"] == "cleared"
    assert closed["alert_id"] in outcome.models[0]["closed"]
    observed = store.alert_evidence(alert["alert_id"])[-1]
    assert observed["source"] == "format-policy"
    assert observed["matched_identifier"] == entry["identifier"]
    assert observed["detail"]["policy"] == "default"
    assert observed["detail"]["set_by"] == "Security lead"
    assert observed["detail"]["set_at"] == "2026-10-24T08:00:00Z"
    assert json.loads(store.read_body(observed["body_sha256"])) == {
        "model_id": "m",
        "format_policy": "default",
        "set_by": "Security lead",
        "set_at": "2026-10-24T08:00:00Z",
    }

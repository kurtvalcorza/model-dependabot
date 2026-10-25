"""Package alerts, watch events, evidence and check runs (T028; FR-007 to FR-010, FR-016, FR-019).

The derived fixture states (an advisory before its withdrawal, a changed record, a failed source)
are made from the recordings by the ``derive_osv`` fixture, each one written out in its test.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from model_dependabot.lifecycle import run_check
from model_dependabot.sources.fetcher import RecordedFetcher
from model_dependabot.store import Store

OSV = Path(__file__).resolve().parent.parent / "fixtures" / "osv"
PILLOW = "pkg:pypi/pillow@12.3.0"
VALIDATORS = "pkg:pypi/validators@0.12.2"
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


GAP = {"kind": "package", "pinned": False, "name": "numpy", "gap_reason": "no exact version"}
VULNERABLE = [_package("pillow", "12.3.0"), _package("validators", "0.12.2"), GAP]
FIXED = [_package("pillow", "13.0.0")]


@pytest.fixture
def store(tmp_path: Path) -> Store:
    moment = datetime(2026, 10, 24, 8, 0, tzinfo=UTC)
    with Store(tmp_path / "md.db", now=lambda: moment) as opened:
        yield opened


def _register(store: Store, model_id: str, entries: list[dict[str, Any]]) -> int:
    if store.get_model(model_id) is None:
        store.add_model(model_id)
    return store.add_version(model_id, {"bomFormat": "CycloneDX"}, "0" * 64, entries)


def _check(store: Store, root: Path, *model_ids: str):
    return run_check(store, RecordedFetcher(root), list(model_ids), ["osv"])


def _open(store: Store, model_id: str) -> dict[str, dict[str, Any]]:
    return {
        alert["cause"]["advisory_id"]: alert
        for alert in store.alerts_for(model_id)
        if alert["state"] == "open"
    }


def _with_withdrawn_listed(answer: dict[str, Any]) -> dict[str, Any]:
    answer["results"][1]["vulns"] = [{"id": WITHDRAWN, "modified": "2019-04-01T00:00:00Z"}]
    return answer


def _before_withdrawal(advisory: dict[str, Any]) -> dict[str, Any]:
    advisory.pop("withdrawn")
    return advisory


def test_an_affected_version_gets_one_alert_per_advisory(store: Store) -> None:
    _register(store, "m", VULNERABLE)
    outcome = _check(store, OSV, "m")
    assert outcome.sources == {"osv": "ok"}
    alerts = _open(store, "m")
    assert sorted(alerts) == [R24, CP9V]

    alert = alerts[CP9V]
    assert alert["kind"] == "package_advisory"
    assert alert["cause_key"] == f"package_advisory:{CP9V}:pillow"
    assert (alert["severity"], alert["severity_origin"]) == ("HIGH", "database_specific")
    assert (alert["opened_in_version"], alert["current_version"]) == (1, 1)
    assert alert["cause"] == {
        "advisory_id": CP9V,
        "aliases": ["CVE-2026-112405"],
        "source": "osv.dev",
        "package": "pillow",
        "version": "12.3.0",
        "identifier": PILLOW,
        "affected": [
            {"type": "ECOSYSTEM", "events": [{"introduced": "12.0.0"}, {"fixed": "13.0.0"}]}
        ],
        "fixed": ["13.0.0"],
    }
    [evidence] = store.alert_evidence(alert["alert_id"])
    assert evidence["source"] == "osv.dev"
    assert evidence["url"] == f"https://api.osv.dev/v1/vulns/{CP9V}"
    assert evidence["retrieved_at"].startswith("2026-10-24T")
    assert evidence["matched_identifier"] == PILLOW
    assert evidence["detail"]["osv_match"] is True
    assert evidence["detail"]["local_match"] is True
    assert store.read_body(evidence["body_sha256"]) == (OSV / f"vuln-{CP9V}.json").read_bytes()
    assert alerts[R24]["severity"] == "MODERATE"


def test_the_advisory_is_cached_with_its_severity_origin(store: Store) -> None:
    _register(store, "m", VULNERABLE)
    _check(store, OSV, "m")
    cached = store.get_advisory("osv.dev", CP9V)
    assert cached is not None
    assert (cached["severity"], cached["severity_origin"]) == ("HIGH", "database_specific")
    assert cached["aliases"] == ["CVE-2026-112405"]
    assert cached["withdrawn"] is None


def test_an_unaffected_version_gets_no_alert(store: Store) -> None:
    _register(store, "m", FIXED)
    outcome = _check(store, OSV, "m")
    assert outcome.sources == {"osv": "ok"}
    assert store.alerts_for("m") == []
    assert store.watch_events("m") == []


def test_disagreement_is_a_watch_event_not_an_alert(
    store: Store, derive_osv: Callable[..., Path]
) -> None:
    def narrowed(advisory: dict[str, Any]) -> dict[str, Any]:
        affected = advisory["affected"][0]
        affected["ranges"][0]["events"] = [{"introduced": "12.0.0"}, {"fixed": "12.3.0"}]
        affected["versions"] = ["12.0.0", "12.1.0", "12.1.1", "12.2.0"]
        return advisory

    root = derive_osv({f"vuln-{CP9V}": narrowed})
    _register(store, "m", VULNERABLE)
    _check(store, root, "m")
    assert sorted(_open(store, "m")) == [R24]
    [event] = store.watch_events("m")
    assert event["kind"] == "advisory_unmatched"
    assert event["entry_identifier"] == PILLOW
    assert event["detail"]["advisories"][CP9V] == {"osv_match": True, "local_match": False}
    [evidence] = event["evidence"]
    assert evidence["url"] == f"https://api.osv.dev/v1/vulns/{CP9V}"
    assert evidence["matched_identifier"] == PILLOW


def test_an_open_alert_is_carried_forward_not_raised_again(store: Store) -> None:
    _register(store, "m", VULNERABLE)
    _check(store, OSV, "m")
    first = {key: alert["alert_id"] for key, alert in _open(store, "m").items()}
    _check(store, OSV, "m")
    _register(store, "m", VULNERABLE)
    _check(store, OSV, "m")
    alerts = _open(store, "m")
    assert {key: alert["alert_id"] for key, alert in alerts.items()} == first
    assert len(store.alerts_for("m")) == 2
    assert (alerts[CP9V]["opened_in_version"], alerts[CP9V]["current_version"]) == (1, 2)
    assert len(store.alert_evidence(alerts[CP9V]["alert_id"])) == 1


def test_a_withdrawn_advisory_closes_its_alert(
    store: Store, derive_osv: Callable[..., Path]
) -> None:
    before = derive_osv(
        {"querybatch-vulnerable": _with_withdrawn_listed, f"vuln-{WITHDRAWN}": _before_withdrawal}
    )
    _register(store, "m", VULNERABLE)
    _check(store, before, "m")
    alert = _open(store, "m")[WITHDRAWN]
    assert (alert["severity"], alert["severity_origin"]) == ("UNKNOWN", "unknown")

    _check(store, OSV, "m")
    closed = store.get_alert(alert["alert_id"])
    assert closed["state"] == "withdrawn"
    assert closed["closed_at"] is not None
    evidence = store.alert_evidence(alert["alert_id"])
    assert len(evidence) == 2
    withdrawal = evidence[-1]
    assert withdrawal["detail"]["withdrawn"] == "2023-03-14T07:01:09.371407Z"
    assert (
        store.read_body(withdrawal["body_sha256"]) == (OSV / f"vuln-{WITHDRAWN}.json").read_bytes()
    )
    assert sorted(_open(store, "m")) == [R24, CP9V]


def test_a_withdrawn_advisory_raises_no_alert(
    store: Store, derive_osv: Callable[..., Path]
) -> None:
    root = derive_osv({"querybatch-vulnerable": _with_withdrawn_listed})
    _register(store, "m", VULNERABLE)
    _check(store, root, "m")
    assert WITHDRAWN not in {alert["cause"]["advisory_id"] for alert in store.alerts_for("m")}


@pytest.mark.parametrize("failing", ["querybatch-vulnerable", f"vuln-{CP9V}", f"vuln-{WITHDRAWN}"])
def test_a_failed_source_changes_no_alert(
    store: Store, derive_osv: Callable[..., Path], failing: str
) -> None:
    before = derive_osv(
        {"querybatch-vulnerable": _with_withdrawn_listed, f"vuln-{WITHDRAWN}": _before_withdrawal}
    )
    _register(store, "m", VULNERABLE)
    _check(store, before, "m")
    snapshot = [(a, store.alert_evidence(a["alert_id"])) for a in store.alerts_for("m")]
    assert len(snapshot) == 3

    _register(store, "m", VULNERABLE)
    outcome = _check(store, derive_osv(errors={failing: "timed out"}), "m")
    assert outcome.failed
    assert outcome.sources["osv"].startswith("failed")
    assert [(a, store.alert_evidence(a["alert_id"])) for a in store.alerts_for("m")] == snapshot
    run = store.get_check_run(outcome.run_id)
    assert run["sources"]["osv"].startswith("failed")


def test_the_same_advisory_in_two_models_gives_each_its_own_alert(store: Store) -> None:
    _register(store, "a", VULNERABLE)
    _register(store, "b", [_package("pillow", "12.3.0")])
    _check(store, OSV, "a", "b")  # one batch for both models: pillow 12.3.0, validators 0.12.2
    a, b = _open(store, "a")[CP9V], _open(store, "b")[CP9V]
    assert a["alert_id"] != b["alert_id"]
    assert a["cause_key"] == b["cause_key"]


def test_a_changed_advisory_updates_the_alert_and_keeps_both_evidence_records(
    store: Store, derive_osv: Callable[..., Path]
) -> None:
    def updated(advisory: dict[str, Any]) -> dict[str, Any]:
        advisory["database_specific"]["severity"] = "CRITICAL"
        advisory["modified"] = "2026-10-25T00:00:00Z"
        advisory["affected"][0]["ranges"][0]["events"] = [
            {"introduced": "12.0.0"},
            {"fixed": "12.4.0"},
        ]
        return advisory

    _register(store, "m", VULNERABLE)
    _check(store, OSV, "m")
    alert_id = _open(store, "m")[CP9V]["alert_id"]
    _check(store, derive_osv({f"vuln-{CP9V}": updated}), "m")
    alert = store.get_alert(alert_id)
    assert alert["state"] == "open"
    assert alert["severity"] == "CRITICAL"
    assert alert["cause"]["fixed"] == ["12.4.0"]
    bodies = [json.loads(store.read_body(e["body_sha256"])) for e in store.alert_evidence(alert_id)]
    assert [body["database_specific"]["severity"] for body in bodies] == ["HIGH", "CRITICAL"]


def test_a_check_run_records_its_sources(store: Store) -> None:
    _register(store, "m", VULNERABLE)
    outcome = _check(store, OSV, "m")
    run = store.get_check_run(outcome.run_id)
    assert run["sources"] == {"osv": "ok"}
    assert run["finished_at"] is not None
    assert store.latest_check_run()["run_id"] == outcome.run_id


# --- OSV ``limit`` and unevaluable ranges in the lifecycle (review F5, phase B1) -----------------


def test_an_explicit_infinite_limit_raises_the_alert(
    store: Store, derive_osv: Callable[..., Path]
) -> None:
    def star(advisory: dict[str, Any]) -> dict[str, Any]:
        advisory["affected"][0]["ranges"][0]["events"] = [{"introduced": "12.0.0"}, {"limit": "*"}]
        advisory["affected"][0].pop("versions", None)
        return advisory

    root = derive_osv({f"vuln-{CP9V}": star})
    _register(store, "m", VULNERABLE)
    _check(store, root, "m")
    assert sorted(_open(store, "m")) == [R24, CP9V]
    assert store.watch_events("m") == []


def test_an_unevaluable_range_is_a_watch_event_that_says_why(
    store: Store, derive_osv: Callable[..., Path]
) -> None:
    def bogus(advisory: dict[str, Any]) -> dict[str, Any]:
        advisory["affected"][0]["ranges"][0]["events"] = [{"introduced": "twelve!"}]
        advisory["affected"][0].pop("versions", None)
        return advisory

    root = derive_osv({f"vuln-{CP9V}": bogus})
    _register(store, "m", VULNERABLE)
    _check(store, root, "m")
    assert sorted(_open(store, "m")) == [R24]
    [event] = store.watch_events("m")
    assert event["kind"] == "advisory_unmatched"
    recorded = event["detail"]["advisories"][CP9V]
    assert recorded["osv_match"] is True
    assert recorded["local_match"] is False
    assert recorded["local_unevaluated"] == ["introduced value 'twelve!' is not a PEP 440 version"]


def test_an_open_alert_is_not_cleared_when_the_local_check_cannot_evaluate(
    store: Store, derive_osv: Callable[..., Path]
) -> None:
    _register(store, "m", VULNERABLE)
    _check(store, OSV, "m")
    assert CP9V in _open(store, "m")

    def unlisted(answer: dict[str, Any]) -> dict[str, Any]:
        answer["results"][0]["vulns"] = [
            vuln for vuln in answer["results"][0].get("vulns") or [] if vuln["id"] != CP9V
        ]
        return answer

    def bogus(advisory: dict[str, Any]) -> dict[str, Any]:
        advisory["affected"][0]["ranges"][0]["events"] = [{"introduced": "twelve!"}]
        advisory["affected"][0].pop("versions", None)
        return advisory

    root = derive_osv({"querybatch-vulnerable": unlisted, f"vuln-{CP9V}": bogus})
    _check(store, root, "m")
    assert CP9V in _open(store, "m")
    [event] = store.watch_events("m")
    assert event["detail"]["advisories"][CP9V]["local_unevaluated"]

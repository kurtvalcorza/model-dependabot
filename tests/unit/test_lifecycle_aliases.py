"""One alert per vulnerability: OSV records that alias each other (feature 006, E2).

OSV can return the same vulnerability for one package version under several ids (a ``PYSEC`` and a
``GHSA`` record that list each other in ``aliases``). They raise one ``package_advisory`` alert
whose cause lists every id, with evidence from every record. The primary id is the GHSA id if there
is one (the lexicographically first if several), else the lexicographically first id. The derived
records here are written out in each test from the recorded GHSA record.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from model_dependabot.lifecycle import package_cause_key, run_check
from model_dependabot.sources.fetcher import RecordedFetcher
from model_dependabot.store import Store

OSV = Path(__file__).resolve().parent.parent / "fixtures" / "osv"
CP9V = "GHSA-cp9v-662q-vvx9"
R24 = "GHSA-24rc-8hj2-v98c"
PYSEC = "PYSEC-2026-1001"
BIT = "BIT-pillow-2026-1"
PILLOW = {
    "kind": "package",
    "identifier": "pkg:pypi/pillow@12.3.0",
    "pinned": True,
    "name": "pillow",
    "version": "12.3.0",
    "hashes": ["sha256:" + "0" * 64],
}
# The recorded batch answer is for pillow 12.3.0 and validators 0.12.2 together.
VALIDATORS = {
    **PILLOW,
    "identifier": "pkg:pypi/validators@0.12.2",
    "name": "validators",
    "version": "0.12.2",
}


@pytest.fixture
def store(tmp_path: Path) -> Store:
    moment = datetime(2026, 10, 24, 8, 0, tzinfo=UTC)
    with Store(tmp_path / "md.db", now=lambda: moment) as opened:
        yield opened


def _record(advisory_id: str, aliases: list[str], **changes: Any) -> dict[str, Any]:
    """A record for the same pillow vulnerability as GHSA-cp9v, under another id."""
    record = json.loads((OSV / f"vuln-{CP9V}.json").read_text("utf-8"))
    record.pop("database_specific", None)
    record.pop("severity", None)
    record.update(id=advisory_id, aliases=aliases, **changes)
    return record


def _root(
    derive_osv: Callable[..., Path],
    records: list[dict[str, Any]],
    *,
    listed: list[str] | None = None,
    ghsa_aliases: list[str] | None = None,
    withdrawn: dict[str, str] | None = None,
) -> Path:
    """OSV recordings with ``records`` added and the batch answer for pillow listing ``listed``."""
    names = [r["id"] for r in records] if listed is None else listed

    def batch(answer: dict[str, Any]) -> dict[str, Any]:
        vulns = answer["results"][0]["vulns"]
        vulns.extend({"id": name, "modified": "2026-10-23T00:00:00Z"} for name in names)
        answer["results"][0]["vulns"] = [v for v in vulns if v["id"] not in (withdrawn or {})]
        return answer

    changes: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
        "querybatch-vulnerable": batch
    }
    if ghsa_aliases is not None or CP9V in (withdrawn or {}):

        def ghsa(advisory: dict[str, Any]) -> dict[str, Any]:
            if ghsa_aliases is not None:
                advisory["aliases"] = ghsa_aliases
            if CP9V in (withdrawn or {}):
                advisory["withdrawn"] = withdrawn[CP9V]
            return advisory

        changes[f"vuln-{CP9V}"] = ghsa
    root = derive_osv(changes)
    for record in records:
        if record["id"] in (withdrawn or {}):
            record = {**record, "withdrawn": withdrawn[record["id"]]}
        url = f"https://api.osv.dev/v1/vulns/{record['id']}"
        (root / f"vuln-{record['id']}.json").write_text(json.dumps(record), "utf-8")
        meta = {
            "method": "GET",
            "url": url,
            "status": 200,
            "headers": {"content-type": "application/json"},
            "retrieved_at": "2026-10-24T03:54:34Z",
            "body_file": f"vuln-{record['id']}.json",
        }
        (root / f"vuln-{record['id']}.meta.json").write_text(json.dumps(meta), "utf-8")
    return root


def _register(store: Store) -> None:
    if store.get_model("m") is None:
        store.add_model("m")
    store.add_version("m", {"bomFormat": "CycloneDX"}, "0" * 64, [PILLOW, VALIDATORS])


def _check(store: Store, root: Path):
    return run_check(store, RecordedFetcher(root), ["m"], ["osv"])


def _open(store: Store) -> list[dict[str, Any]]:
    return store.alerts_for("m", ["open"])


def _for(store: Store, advisory_id: str) -> dict[str, Any]:
    [alert] = [a for a in _open(store) if advisory_id in a["cause"]["advisory_ids"]]
    return alert


def test_two_aliasing_records_raise_one_alert(
    store: Store, derive_osv: Callable[..., Path]
) -> None:
    root = _root(derive_osv, [_record(PYSEC, [CP9V, "CVE-2026-112405"])])
    _register(store)
    _check(store, root)
    alerts = _open(store)
    assert sorted(a["cause"]["advisory_id"] for a in alerts) == [R24, CP9V]
    alert = _for(store, PYSEC)
    assert alert["cause"]["advisory_id"] == CP9V  # the GHSA id is primary
    assert alert["cause"]["advisory_ids"] == [CP9V, PYSEC]
    assert alert["cause_key"] == package_cause_key(CP9V, "pillow")
    assert PYSEC in alert["cause"]["aliases"]
    urls = sorted(e["url"] for e in store.alert_evidence(alert["alert_id"]))
    assert urls == [f"https://api.osv.dev/v1/vulns/{x}" for x in sorted([CP9V, PYSEC])]
    # GHSA-cp9v carries HIGH; the PYSEC record has no severity, so the highest is the GHSA's.
    assert (alert["severity"], alert["severity_origin"]) == ("HIGH", "database_specific")
    assert alert["cause"]["severity_from"] == CP9V


def test_the_highest_severity_across_the_records_is_used(
    store: Store, derive_osv: Callable[..., Path]
) -> None:
    critical = _record(PYSEC, [CP9V], database_specific={"severity": "CRITICAL"})
    _register(store)
    _check(store, _root(derive_osv, [critical]))
    alert = _for(store, PYSEC)
    assert alert["cause"]["advisory_id"] == CP9V
    assert (alert["severity"], alert["severity_origin"]) == ("CRITICAL", "database_specific")
    assert alert["cause"]["severity_from"] == PYSEC


def test_three_way_transitive_aliases_raise_one_alert(
    store: Store, derive_osv: Callable[..., Path]
) -> None:
    # PYSEC names the GHSA record; BIT names only PYSEC; the GHSA record names neither.
    records = [_record(PYSEC, [CP9V]), _record(BIT, [PYSEC])]
    _register(store)
    _check(store, _root(derive_osv, records))
    assert len(_open(store)) == 2  # the merged one and GHSA-24rc
    alert = _for(store, BIT)
    assert alert["cause"]["advisory_ids"] == [CP9V, BIT, PYSEC]
    assert len(store.alert_evidence(alert["alert_id"])) == 3


def test_without_a_ghsa_id_the_first_id_is_primary(
    store: Store, derive_osv: Callable[..., Path]
) -> None:
    records = [_record(PYSEC, [BIT]), _record(BIT, [])]
    _register(store)
    _check(store, _root(derive_osv, records))
    alert = _for(store, PYSEC)
    assert alert["cause"]["advisory_id"] == BIT
    assert alert["cause"]["advisory_ids"] == [BIT, PYSEC]


def test_a_rerun_carries_the_merged_alert_forward(
    store: Store, derive_osv: Callable[..., Path]
) -> None:
    root = _root(derive_osv, [_record(PYSEC, [CP9V])])
    _register(store)
    _check(store, root)
    first = _for(store, PYSEC)
    evidence = [e["evidence_id"] for e in store.alert_evidence(first["alert_id"])]
    outcome = _check(store, root)
    assert _for(store, PYSEC)["alert_id"] == first["alert_id"]
    assert first["alert_id"] in outcome.models[0]["carried_forward"]
    assert [e["evidence_id"] for e in store.alert_evidence(first["alert_id"])] == evidence
    assert len(_open(store)) == 2


def _old_alert(store: Store, advisory_id: str) -> int:
    """An open alert as stored before 006: one per OSV record, keyed by its own id."""
    record = (_record(PYSEC, [CP9V]) if advisory_id == PYSEC else {"aliases": []})["aliases"]
    evidence_id = store.add_evidence(
        source="osv.dev",
        url=f"https://api.osv.dev/v1/vulns/{advisory_id}",
        retrieved_at=datetime(2026, 10, 23, tzinfo=UTC),
        matched_identifier=PILLOW["identifier"],
        body=json.dumps({"id": advisory_id}).encode(),
    )
    return store.insert_alert(
        model_id="m",
        kind="package_advisory",
        cause_key=package_cause_key(advisory_id, "pillow"),
        cause={
            "advisory_id": advisory_id,
            "aliases": record,
            "source": "osv.dev",
            "package": "pillow",
            "version": "12.3.0",
            "identifier": PILLOW["identifier"],
            "affected": [],
            "fixed": ["13.0.0"],
        },
        severity="HIGH",
        severity_origin="database_specific",
        opened_in_version=1,
        evidence_ids=[evidence_id],
    )


def test_existing_duplicate_alerts_are_merged_into_the_primary(
    store: Store, derive_osv: Callable[..., Path]
) -> None:
    _register(store)
    ghsa_id, pysec_id = _old_alert(store, CP9V), _old_alert(store, PYSEC)
    outcome = _check(store, _root(derive_osv, [_record(PYSEC, [CP9V])]))

    kept = store.get_alert(ghsa_id)
    assert kept["state"] == "open"
    assert kept["cause"]["advisory_ids"] == [CP9V, PYSEC]
    merged = store.get_alert(pysec_id)
    assert merged["state"] == "cleared"
    assert f"alert {ghsa_id}" in merged["note"] and CP9V in merged["note"]
    assert pysec_id in outcome.models[0]["closed"]
    # The clearance is recorded with the source's records as evidence (constitution III).
    urls = {e["url"] for e in store.alert_evidence(pysec_id)}
    assert f"https://api.osv.dev/v1/vulns/{PYSEC}" in urls
    assert f"https://api.osv.dev/v1/vulns/{CP9V}" in urls
    assert len(_open(store)) == 2


def test_an_existing_alert_under_a_secondary_id_is_rekeyed(
    store: Store, derive_osv: Callable[..., Path]
) -> None:
    _register(store)
    pysec_id = _old_alert(store, PYSEC)
    _check(store, _root(derive_osv, [_record(PYSEC, [CP9V])]))
    alert = store.get_alert(pysec_id)
    assert alert["state"] == "open"
    assert alert["cause_key"] == package_cause_key(CP9V, "pillow")
    assert alert["cause"]["advisory_ids"] == [CP9V, PYSEC]
    assert len(_open(store)) == 2


@pytest.mark.parametrize("gone", [PYSEC, CP9V])
def test_withdrawing_one_alias_keeps_the_merged_alert_open(
    store: Store, derive_osv: Callable[..., Path], gone: str
) -> None:
    records = [_record(PYSEC, [CP9V])]
    _register(store)
    _check(store, _root(derive_osv, records))
    alert_id = _for(store, PYSEC)["alert_id"]

    # OSV leaves a withdrawn record out of query answers; the other record still matches.
    _check(store, _root(derive_osv, records, withdrawn={gone: "2026-10-25T00:00:00Z"}))
    alert = store.get_alert(alert_id)
    assert alert["state"] == "open"
    [remaining] = [x for x in (CP9V, PYSEC) if x != gone]
    assert alert["cause"]["advisory_id"] == remaining
    assert alert["cause"]["advisory_ids"] == [remaining]
    assert len(_open(store)) == 2
    withdrawal = [e for e in store.alert_evidence(alert_id) if e["url"].endswith(gone)][-1]
    assert json.loads(store.read_body(withdrawal["body_sha256"]))["withdrawn"]


def test_withdrawing_every_alias_closes_the_merged_alert(
    store: Store, derive_osv: Callable[..., Path]
) -> None:
    records = [_record(PYSEC, [CP9V])]
    _register(store)
    _check(store, _root(derive_osv, records))
    alert_id = _for(store, PYSEC)["alert_id"]
    stamp = "2026-10-25T00:00:00Z"
    _check(store, _root(derive_osv, records, withdrawn={CP9V: stamp, PYSEC: stamp}))
    assert store.get_alert(alert_id)["state"] == "withdrawn"

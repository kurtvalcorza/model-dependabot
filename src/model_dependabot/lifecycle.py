"""Check runs, package alerts, watch events and evidence (data-model.md; FR-006 to FR-010, FR-016).

A check run reads each requested source in full before it changes anything. If a source fails
anywhere in the run, nothing it would have changed is changed: it is recorded as ``failed`` in the
run and every alert is left as it was (FR-016, SC-007).

For OSV, a package alert opens only when OSV lists the advisory for the exact pinned version and the
local PEP 440 evaluation of the record's ranges agrees (research R2); when the two disagree, a watch
event of kind ``advisory_unmatched`` is recorded instead (FR-007). An open alert is carried forward
rather than raised again (FR-010): its current version, severity and fixed versions follow the
source, and a changed record is added as new evidence beside the earlier one. A withdrawn advisory
closes its alerts as ``withdrawn`` with the withdrawn record as evidence (FR-009). OSV leaves
withdrawn records out of query answers, so the advisory of every open alert is fetched by id on each
run.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from packaging.utils import canonicalize_name

from model_dependabot.matching.severity import severity_of
from model_dependabot.matching.versions import advisory_affects, affected_ranges, fixed_versions
from model_dependabot.sources.fetcher import Fetcher, SourceFailedError
from model_dependabot.sources.osv import (
    SOURCE,
    BatchAnswer,
    OsvClient,
    VulnRecord,
    aliases,
    pinned_packages,
    withdrawn,
)
from model_dependabot.store import Store

PACKAGE_ALERT = "package_advisory"
UNMATCHED = "advisory_unmatched"


@dataclass
class CheckOutcome:
    """What a check run did: per source ``ok``, ``failed: reason`` or ``skipped``; per model the
    alerts opened, carried forward and closed."""

    run_id: int
    sources: dict[str, str]
    models: list[dict[str, Any]] = field(default_factory=list)

    @property
    def failed(self) -> bool:
        return any(status.startswith("failed") for status in self.sources.values())


def package_cause_key(advisory_id: str, package: str) -> str:
    """``kind`` plus advisory id plus normalised package name (data-model.md, Alert)."""
    return f"{PACKAGE_ALERT}:{advisory_id}:{canonicalize_name(package)}"


@dataclass
class _Target:
    model_id: str
    version: int
    entries: list[dict[str, Any]]
    summary: dict[str, Any]


@dataclass
class _OsvRead:
    batch: BatchAnswer
    records: dict[str, VulnRecord]


def run_check(
    store: Store,
    fetcher: Fetcher,
    model_ids: Sequence[str],
    sources: Sequence[str] = ("osv",),
    *,
    scope: str | None = None,
) -> CheckOutcome:
    """Check the current version of each model against the requested sources."""
    run_id = store.start_check_run(scope=scope or ",".join(model_ids))
    targets = []
    for model_id in model_ids:
        version = store.latest_version(model_id)
        if version is None:
            continue
        summary: dict[str, Any] = {
            "model_id": model_id,
            "version": version,
            "opened": [],
            "carried_forward": [],
            "closed": [],
            "watch_events": [],
        }
        targets.append(_Target(model_id, version, store.entries(model_id, version), summary))

    statuses: dict[str, str] = {}
    for source in sources:
        if source != "osv":
            statuses[source] = "skipped"
            continue
        try:
            read = _read_osv(store, OsvClient(fetcher), targets)
        except SourceFailedError as error:
            statuses[source] = f"failed: {error.reason}"
            continue
        for target in targets:
            _apply_osv(store, run_id, read, target)
        statuses[source] = "ok"
    store.finish_check_run(run_id, statuses)
    return CheckOutcome(run_id, statuses, [target.summary for target in targets])


def _read_osv(store: Store, client: OsvClient, targets: list[_Target]) -> _OsvRead:
    """Everything the run needs from OSV, read before anything changes (FR-016)."""
    batch = client.query(entry for target in targets for entry in target.entries)
    wanted = {advisory_id for ids in batch.matches.values() for advisory_id in ids}
    for target in targets:
        for alert in store.alerts_for(target.model_id, ["open"]):
            if alert["kind"] == PACKAGE_ALERT:
                wanted.add(alert["cause"]["advisory_id"])
    records = {advisory_id: client.vuln(advisory_id) for advisory_id in sorted(wanted)}
    return _OsvRead(batch, records)


def _sha256(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def _evidence(
    store: Store,
    run_id: int,
    record: VulnRecord,
    identifier: str,
    detail: Mapping[str, Any],
    existing: Sequence[Mapping[str, Any]] = (),
) -> tuple[int, bool]:
    """The evidence id for this record, reusing an identical record already linked."""
    digest = _sha256(record.response.body)
    for evidence in existing:
        if evidence["url"] == record.response.url and evidence["body_sha256"] == digest:
            return int(evidence["evidence_id"]), False
    evidence_id = store.add_evidence(
        source=SOURCE,
        url=record.response.url,
        retrieved_at=record.response.retrieved_at,
        matched_identifier=identifier,
        body=record.response.body,
        detail=detail,
        run_id=run_id,
    )
    return evidence_id, True


def _cache(store: Store, record: VulnRecord, evidence_id: int) -> None:
    advisory = record.advisory
    severity, origin = severity_of(advisory)
    store.upsert_advisory(
        source=SOURCE,
        advisory_id=advisory["id"],
        aliases=aliases(advisory),
        modified=advisory.get("modified"),
        withdrawn=withdrawn(advisory),
        severity=severity,
        severity_origin=origin,
        affected=advisory.get("affected") or [],
        evidence_id=evidence_id,
    )


def _apply_osv(store: Store, run_id: int, read: _OsvRead, target: _Target) -> None:
    batch_detail: dict[str, Any] = {}
    if read.batch.response is not None:
        batch_detail = {
            "query_url": read.batch.response.url,
            "query_sha256": store.put_body(read.batch.response.body),
        }
    packages = {entry["identifier"]: entry for entry in pinned_packages(target.entries)}
    handled: set[str] = set()

    for identifier, entry in packages.items():
        for advisory_id in read.batch.matches.get(identifier, []):
            record = read.records[advisory_id]
            if withdrawn(record.advisory):
                continue  # closed below if an alert is open; never raised
            local = advisory_affects(record.advisory, entry["name"], entry["version"])
            match = {"osv_match": True, "local_match": local, **batch_detail}
            if local:
                handled.add(package_cause_key(advisory_id, entry["name"]))
                _raise_or_carry(store, run_id, target, entry, record, match)
            else:
                _unmatched(store, run_id, target, identifier, record, match)

    for alert in store.alerts_for(target.model_id, ["open"]):
        if alert["kind"] != PACKAGE_ALERT or alert["cause_key"] in handled:
            continue
        advisory_id = alert["cause"]["advisory_id"]
        record = read.records[advisory_id]
        identifier = alert["cause"]["identifier"]
        if withdrawn(record.advisory):
            detail = {"withdrawn": withdrawn(record.advisory), **batch_detail}
            evidence_id, _ = _evidence(store, run_id, record, identifier, detail)
            store.link_alert_evidence(alert["alert_id"], evidence_id)
            store.close_alert(alert["alert_id"], state="withdrawn")
            _cache(store, record, evidence_id)
            target.summary["closed"].append(alert["alert_id"])
            continue
        entry = packages.get(identifier)
        if entry is None:
            continue  # the package changed in this version: settled at registration
        if advisory_affects(record.advisory, entry["name"], entry["version"]):
            match = {"osv_match": False, "local_match": True, **batch_detail}
            _unmatched(store, run_id, target, identifier, record, match)
        # Both agree the version is no longer affected: closing as ``cleared`` is FR-023 (US4).


def _raise_or_carry(
    store: Store,
    run_id: int,
    target: _Target,
    entry: Mapping[str, Any],
    record: VulnRecord,
    detail: Mapping[str, Any],
) -> None:
    advisory = record.advisory
    name, version = entry["name"], entry["version"]
    severity, origin = severity_of(advisory)
    cause = {
        "advisory_id": advisory["id"],
        "aliases": aliases(advisory),
        "source": SOURCE,
        "package": name,
        "version": version,
        "identifier": entry["identifier"],
        "affected": affected_ranges(advisory, name),
        "fixed": fixed_versions(advisory, name),
    }
    cause_key = package_cause_key(advisory["id"], name)
    existing = store.find_open_alert(target.model_id, cause_key)
    if existing is None:
        evidence_id, _ = _evidence(store, run_id, record, entry["identifier"], detail)
        alert_id = store.insert_alert(
            model_id=target.model_id,
            kind=PACKAGE_ALERT,
            cause_key=cause_key,
            cause=cause,
            severity=severity,
            severity_origin=origin,
            opened_in_version=target.version,
            evidence_ids=[evidence_id],
        )
        target.summary["opened"].append(alert_id)
    else:
        alert_id = existing["alert_id"]
        linked = store.alert_evidence(alert_id)
        evidence_id, _ = _evidence(store, run_id, record, entry["identifier"], detail, linked)
        store.link_alert_evidence(alert_id, evidence_id)
        store.update_open_alert(
            alert_id,
            current_version=max(existing["current_version"], target.version),
            severity=severity,
            severity_origin=origin,
            cause=cause,
        )
        target.summary["carried_forward"].append(alert_id)
    _cache(store, record, evidence_id)


def _unmatched(
    store: Store,
    run_id: int,
    target: _Target,
    identifier: str,
    record: VulnRecord,
    match: Mapping[str, Any],
) -> None:
    """OSV and the local evaluation disagree: a watch event, never an alert (FR-007)."""
    existing = store.get_watch_event(target.model_id, target.version, identifier, UNMATCHED)
    detail: dict[str, Any] = dict(existing["detail"]) if existing else {}
    advisories = dict(detail.get("advisories") or {})
    advisories[record.advisory["id"]] = {
        "osv_match": match["osv_match"],
        "local_match": match["local_match"],
    }
    detail["advisories"] = advisories
    linked = existing["evidence"] if existing else []
    evidence_id, _ = _evidence(store, run_id, record, identifier, match, linked)
    watch_event_id = store.record_watch_event(
        model_id=target.model_id,
        version=target.version,
        entry_identifier=identifier,
        kind=UNMATCHED,
        detail=detail,
        evidence_ids=[evidence_id],
    )
    _cache(store, record, evidence_id)
    if watch_event_id not in target.summary["watch_events"]:
        target.summary["watch_events"].append(watch_event_id)

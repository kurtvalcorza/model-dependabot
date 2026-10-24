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

Weight files (research R4, R5; FR-011 to FR-013, FR-021, FR-022): every pinned code-capable file
gets a ``pickle_format`` watch event, and under the owner's ``strict`` format policy a
``format_policy`` alert when no code-free file is beside it in the version. These two rules read
only the inventory and the owner's recorded policy, and run whenever ``picklescan`` or ``hf-scan``
is requested. ``picklescan`` scans the local files (never loading them): a ``dangerous`` global
raises a ``weight_file_scan`` alert, a ``suspicious`` one a ``scan_suspicious`` watch event, and a
scan that stopped early a ``scan_incomplete`` watch event. ``hf-scan`` reads the hub's verdict: only
an explicit ``unsafe`` verdict for a file whose hub SHA-256 matches the inventory raises a
``hub_scan`` alert; anything else it cannot confirm is a watch event.

Closing (US4; FR-014, FR-015, FR-023, constitution III): registering a newer version closes an
alert as ``fixed`` when the new inventory no longer has its cause and carries it forward when it
does, consulting no source. A check closes an alert as ``cleared`` when the source that answered in
that run no longer shows the cause: OSV and the local evaluation both agree the pinned version is
unaffected, the hub gives an explicit ``safe`` verdict for the matching hash, or the owner's
recorded format policy is no longer ``strict``. A person dismisses an alert with a listed reason.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from packaging.utils import canonicalize_name

from model_dependabot.matching.severity import severity_of
from model_dependabot.matching.versions import advisory_affects, affected_ranges, fixed_versions
from model_dependabot.sources import (
    crossref,
    datacite,
    figshare,
    hf_takedowns,
    pickle_scan,
    zenodo,
)
from model_dependabot.sources import hf as hub
from model_dependabot.sources.doi_ra import ensure_agency
from model_dependabot.sources.fetcher import Fetcher, SourceFailedError, source_of
from model_dependabot.sources.osv import (
    SOURCE,
    BatchAnswer,
    OsvClient,
    VulnRecord,
    aliases,
    pinned_packages,
    withdrawn,
)
from model_dependabot.store import DISMISSAL_REASONS, Store
from model_dependabot.upstream.observe import observe

PACKAGE_ALERT = "package_advisory"
UNMATCHED = "advisory_unmatched"

WEIGHT_SCAN_ALERT = "weight_file_scan"
HUB_SCAN_ALERT = "hub_scan"
FORMAT_POLICY_ALERT = "format_policy"
PICKLE_FORMAT = "pickle_format"
SCAN_SUSPICIOUS = "scan_suspicious"
SCAN_INCOMPLETE = "scan_incomplete"
HUB_SCAN_UNKNOWN = "hub_scan_unknown"
HASH_MISMATCH = "hash_mismatch"

PICKLESCAN = "picklescan"
HF_SCAN = "hf-scan"
WEIGHT_SOURCES = (PICKLESCAN, HF_SCAN)
FORMAT_RULE_SOURCE = "format-rule"
FORMAT_POLICY_SOURCE = "format-policy"

# data-model.md, Alert: fixed rules of this service, not values from a source.
WEIGHT_SEVERITY = {
    WEIGHT_SCAN_ALERT: "HIGH",
    HUB_SCAN_ALERT: "HIGH",
    FORMAT_POLICY_ALERT: "MODERATE",
}
POLICY_ORIGIN = "policy"
PICKLE_REASON = "the format can run code when loaded"
SUGGESTION = "use a format that cannot run code when loaded: safetensors, ONNX or GGUF"


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
    base_dir: str | None = None


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
    trigger: str = "on_demand",
) -> CheckOutcome:
    """Check the current version of each model against the requested sources.

    ``trigger`` is ``scheduled`` for ``check --all --scheduled`` and ``on_demand`` otherwise. The
    upstream sources of feature 002 (``hf-hub``, ``hf-takedowns``, ``crossref``, ``datacite``,
    ``zenodo``, ``figshare``) are all read before any of them changes anything, and a source
    that failed opens, changes or closes nothing (FR-018).
    """
    run_id = store.start_check_run(scope=scope or ",".join(model_ids), trigger=trigger)
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
        record = store.get_version(model_id, version) or {}
        entries = store.entries(model_id, version)
        targets.append(_Target(model_id, version, entries, summary, record.get("base_dir")))

    statuses: dict[str, str] = {}
    wanted = [source for source in sources if source in UPSTREAM_SOURCES]
    upstream = _read_upstream(store, fetcher, targets, wanted) if wanted else None
    for source in sources:
        if upstream is not None and source in UPSTREAM_SOURCES:
            statuses[source] = upstream.statuses[source]
            continue
        if source == PICKLESCAN:
            scans = _read_local_scans(store, targets)
            for target in targets:
                _apply_local_scans(store, run_id, target, scans)
            statuses[source] = "ok"
            continue
        if source == HF_SCAN:
            try:
                verdicts = _read_hub(store, hub.HubSecurity(fetcher), targets)
            except SourceFailedError as error:
                statuses[source] = f"failed: {error.reason}"
                continue
            for target in targets:
                _apply_hub(store, run_id, target, verdicts)
            statuses[source] = "ok"
            continue
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
    if any(source in WEIGHT_SOURCES for source in sources):
        for target in targets:
            _apply_format_rules(store, run_id, target)
    if upstream is not None:
        observed = _Observed(store, run_id)
        for target in targets:
            _apply_upstream(store, target, observed, upstream)
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
        listed = advisory_id in read.batch.matches.get(identifier, [])
        if listed:
            continue  # OSV lists it, the local evaluation does not: recorded above as unmatched
        if advisory_affects(record.advisory, entry["name"], entry["version"]):
            match = {"osv_match": False, "local_match": True, **batch_detail}
            _unmatched(store, run_id, target, identifier, record, match)
            continue
        # Both agree the pinned version is no longer affected: the source cleared it (FR-023).
        detail = {"osv_match": False, "local_match": False, **batch_detail}
        linked = store.alert_evidence(alert["alert_id"])
        evidence_id, _ = _evidence(store, run_id, record, identifier, detail, linked)
        _cache(store, record, evidence_id)
        _close(store, target, alert, "cleared", [evidence_id])


def _close(
    store: Store,
    target: _Target,
    alert: Mapping[str, Any],
    state: str,
    evidence_ids: Sequence[int],
) -> None:
    """Close an alert on the source's own observation, kept as evidence (constitution III)."""
    for evidence_id in evidence_ids:
        store.link_alert_evidence(alert["alert_id"], evidence_id)
    store.close_alert(alert["alert_id"], state=state)
    target.summary["closed"].append(alert["alert_id"])


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


# --- weight files (US3) --------------------------------------------------------------------------


def weight_cause_key(kind: str, identifier: str) -> str:
    """``kind`` plus the file's SHA-256 (data-model.md, Alert)."""
    return f"{kind}:{identifier.removeprefix('sha256:')}"


def _code_capable(entries: Sequence[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    """Pinned weight files whose format can run code; gaps are never scanned."""
    return [
        entry
        for entry in entries
        if entry["kind"] == "weight_file" and entry["pinned"] and entry["can_run_code"]
    ]


def _json_body(record: Mapping[str, Any]) -> bytes:
    return json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass
class _Observation:
    """One piece of evidence about a weight file, before it is stored."""

    source: str
    url: str
    retrieved_at: Any
    body: bytes
    detail: dict[str, Any]


def _store_observations(
    store: Store,
    run_id: int,
    identifier: str,
    observations: Sequence[_Observation],
    existing: Sequence[Mapping[str, Any]] = (),
) -> list[int]:
    """Evidence ids for the observations, reusing identical records already linked."""
    ids = []
    for item in observations:
        digest = _sha256(item.body)
        detail = json.loads(json.dumps(item.detail))
        reused = next(
            (
                int(evidence["evidence_id"])
                for evidence in existing
                if evidence["source"] == item.source
                and evidence["url"] == item.url
                and evidence["body_sha256"] == digest
                and evidence["detail"] == detail
            ),
            None,
        )
        if reused is None:
            reused = store.add_evidence(
                source=item.source,
                url=item.url,
                retrieved_at=item.retrieved_at,
                matched_identifier=identifier,
                body=item.body,
                detail=item.detail,
                run_id=run_id,
            )
        ids.append(reused)
    return ids


def _weight_alert(
    store: Store,
    run_id: int,
    target: _Target,
    kind: str,
    entry: Mapping[str, Any],
    cause: Mapping[str, Any],
    observations: Sequence[_Observation],
) -> None:
    """Open a weight-file alert, or carry the open one forward (FR-010, FR-013)."""
    identifier = entry["identifier"]
    cause_key = weight_cause_key(kind, identifier)
    severity = WEIGHT_SEVERITY[kind]
    existing = store.find_open_alert(target.model_id, cause_key)
    if existing is None:
        evidence_ids = _store_observations(store, run_id, identifier, observations)
        alert_id = store.insert_alert(
            model_id=target.model_id,
            kind=kind,
            cause_key=cause_key,
            cause=cause,
            severity=severity,
            severity_origin=POLICY_ORIGIN,
            opened_in_version=target.version,
            evidence_ids=evidence_ids,
        )
        target.summary["opened"].append(alert_id)
        return
    alert_id = existing["alert_id"]
    linked = store.alert_evidence(alert_id)
    for evidence_id in _store_observations(store, run_id, identifier, observations, linked):
        store.link_alert_evidence(alert_id, evidence_id)
    store.update_open_alert(
        alert_id,
        current_version=max(existing["current_version"], target.version),
        severity=severity,
        severity_origin=POLICY_ORIGIN,
        cause=cause,
    )
    if alert_id not in target.summary["carried_forward"]:
        target.summary["carried_forward"].append(alert_id)


def _watch(
    store: Store,
    run_id: int,
    target: _Target,
    kind: str,
    identifier: str,
    detail: Mapping[str, Any],
    observations: Sequence[_Observation],
) -> None:
    existing = store.get_watch_event(target.model_id, target.version, identifier, kind)
    linked = existing["evidence"] if existing else []
    evidence_ids = _store_observations(store, run_id, identifier, observations, linked)
    watch_event_id = store.record_watch_event(
        model_id=target.model_id,
        version=target.version,
        entry_identifier=identifier,
        kind=kind,
        detail=detail,
        evidence_ids=evidence_ids,
    )
    if watch_event_id not in target.summary["watch_events"]:
        target.summary["watch_events"].append(watch_event_id)


def _where(entry: Mapping[str, Any]) -> str | None:
    if entry.get("location"):
        return str(entry["location"])
    if entry.get("hub_repo"):
        return f"hf:{entry['hub_repo']}/{entry['hub_file']}"
    return None


# --- format rules: pickle_format watch events and the strict format policy ------------------------


def _apply_format_rules(store: Store, run_id: int, target: _Target) -> None:
    capable = _code_capable(target.entries)
    now = store.now()
    for entry in capable:
        detail = {
            "format": entry["format"],
            "reason": PICKLE_REASON,
            "suggestion": SUGGESTION,
            "location": _where(entry),
        }
        record = {"identifier": entry["identifier"], "can_run_code": True, **detail}
        observation = _Observation(FORMAT_RULE_SOURCE, "", now, _json_body(record), detail)
        _watch(store, run_id, target, PICKLE_FORMAT, entry["identifier"], detail, [observation])

    model = store.get_model(target.model_id) or {}
    if model.get("format_policy") != "strict":
        _clear_format_policy(store, run_id, target, model, now)
        return
    code_free_beside = any(
        entry["kind"] == "weight_file" and entry["can_run_code"] is False
        for entry in target.entries
    )
    if code_free_beside:
        return  # FR-021: a code-free file beside it suppresses the policy alert
    policy = {
        "model_id": target.model_id,
        "format_policy": "strict",
        "set_by": model.get("format_policy_set_by"),
        "set_at": model.get("format_policy_set_at"),
    }
    body = _json_body(policy)  # the owner's recorded policy is the primary source (constitution I)
    for entry in capable:
        detail = {
            "format": entry["format"],
            "policy": "strict",
            "set_by": policy["set_by"],
            "set_at": policy["set_at"],
            "location": _where(entry),
        }
        cause = {"identifier": entry["identifier"], **detail, "suggestion": SUGGESTION}
        observation = _Observation(FORMAT_POLICY_SOURCE, "", now, body, detail)
        _weight_alert(store, run_id, target, FORMAT_POLICY_ALERT, entry, cause, [observation])


def _clear_format_policy(
    store: Store, run_id: int, target: _Target, model: Mapping[str, Any], now: Any
) -> None:
    """The owner switched the policy away from ``strict``: the owner's recorded policy is the
    source of a ``format_policy`` alert, so its change clears the alert (constitution III 1.0.2)."""
    alerts = [
        alert
        for alert in store.alerts_for(target.model_id, ["open"])
        if alert["kind"] == FORMAT_POLICY_ALERT
    ]
    if not alerts:
        return
    policy = {
        "model_id": target.model_id,
        "format_policy": model.get("format_policy"),
        "set_by": model.get("format_policy_set_by"),
        "set_at": model.get("format_policy_set_at"),
    }
    body = _json_body(policy)
    for alert in alerts:
        identifier = alert["cause"]["identifier"]
        detail = {
            "format": alert["cause"].get("format"),
            "policy": policy["format_policy"],
            "set_by": policy["set_by"],
            "set_at": policy["set_at"],
            "location": alert["cause"].get("location"),
        }
        observation = _Observation(FORMAT_POLICY_SOURCE, "", now, body, detail)
        linked = store.alert_evidence(alert["alert_id"])
        ids = _store_observations(store, run_id, identifier, [observation], linked)
        _close(store, target, alert, "cleared", ids)


# --- picklescan: static scans of local files ------------------------------------------------------


@dataclass
class _LocalScan:
    path: Path
    retrieved_at: Any
    report: pickle_scan.ScanReport | None = None
    actual_sha256: str | None = None
    read_error: str | None = None


def _local_path(target: _Target, location: str) -> Path:
    path = Path(location)
    if not path.is_absolute() and target.base_dir is not None:
        path = Path(target.base_dir) / path
    return path.resolve()


def _read_local_scans(
    store: Store, targets: Sequence[_Target]
) -> dict[tuple[str, int, str], _LocalScan]:
    """Scan every local code-capable file before anything changes; a file is never loaded."""
    scans: dict[tuple[str, int, str], _LocalScan] = {}
    for target in targets:
        for entry in _code_capable(target.entries):
            if entry.get("hub_repo") or not entry.get("location"):
                continue
            path = _local_path(target, entry["location"])
            scan = _LocalScan(path, store.now())
            try:
                data = path.read_bytes()
            except OSError as error:
                scan.read_error = f"cannot read the file: {error.strerror or error}"
            else:
                scan.actual_sha256 = _sha256(data)
                if f"sha256:{scan.actual_sha256}" == entry["identifier"]:
                    scan.report = pickle_scan.scan(data, path.name)
            scans[(target.model_id, target.version, entry["identifier"])] = scan
    return scans


def _apply_local_scans(
    store: Store, run_id: int, target: _Target, scans: Mapping[tuple[str, int, str], _LocalScan]
) -> None:
    for entry in _code_capable(target.entries):
        identifier = entry["identifier"]
        scan = scans.get((target.model_id, target.version, identifier))
        if scan is None:
            continue
        url = scan.path.as_uri()
        location = entry["location"]
        if scan.report is None and scan.read_error is None:
            detail = {
                "scanner": pickle_scan.SCANNER,
                "location": location,
                "inventory_sha256": identifier.removeprefix("sha256:"),
                "actual_sha256": scan.actual_sha256,
            }
            observation = _Observation(
                pickle_scan.SCANNER, url, scan.retrieved_at, _json_body(detail), detail
            )
            _watch(store, run_id, target, HASH_MISMATCH, identifier, detail, [observation])
            continue
        if scan.report is None:
            detail = {
                "scanner": pickle_scan.SCANNER,
                "scanner_version": pickle_scan.SCANNER_VERSION,
                "position": 0,
                "size": entry.get("size"),
                "reason": scan.read_error,
                "location": location,
            }
            observation = _Observation(
                pickle_scan.SCANNER, url, scan.retrieved_at, _json_body(detail), detail
            )
            _watch(store, run_id, target, SCAN_INCOMPLETE, identifier, detail, [observation])
            continue

        report = scan.report
        body = _json_body(report.as_record())
        base = {
            "scanner": report.scanner,
            "scanner_version": report.scanner_version,
            "location": location,
            "format": entry["format"],
        }
        if report.dangerous:
            detail = {
                **base,
                "dangerous": report.dangerous,
                "suspicious": report.suspicious,
                "complete": report.complete,
                "position": report.position,
            }
            cause = {"identifier": identifier, **detail}
            observation = _Observation(report.scanner, url, scan.retrieved_at, body, detail)
            _weight_alert(store, run_id, target, WEIGHT_SCAN_ALERT, entry, cause, [observation])
        if report.suspicious:
            detail = {**base, "suspicious": report.suspicious}
            observation = _Observation(report.scanner, url, scan.retrieved_at, body, detail)
            _watch(store, run_id, target, SCAN_SUSPICIOUS, identifier, detail, [observation])
        if not report.complete:
            detail = {
                **base,
                "position": report.position,
                "size": report.size,
                "reason": report.error,
            }
            observation = _Observation(report.scanner, url, scan.retrieved_at, body, detail)
            _watch(store, run_id, target, SCAN_INCOMPLETE, identifier, detail, [observation])


# --- hf-scan: the hub's verdicts ------------------------------------------------------------------


def _hub_files(target: _Target) -> list[Mapping[str, Any]]:
    return [
        entry
        for entry in target.entries
        if entry["kind"] == "weight_file"
        and entry["pinned"]
        and entry.get("hub_repo")
        and entry.get("hub_file")
    ]


def _read_hub(
    store: Store, security: hub.HubSecurity, targets: Sequence[_Target]
) -> dict[tuple[str, str], hub.FileVerdict]:
    """Every verdict the run needs, read before anything changes (FR-016).

    A file with an open ``hub_scan`` alert has its clean verdict confirmed against the tree, so an
    explicit safe verdict for the matching hash can clear the alert (FR-023).
    """
    alerted = {
        alert["cause"]["identifier"]
        for target in targets
        for alert in store.alerts_for(target.model_id, ["open"])
        if alert["kind"] == HUB_SCAN_ALERT
    }
    statuses: dict[str, hub.SecurityStatus] = {}
    verdicts: dict[tuple[str, str], hub.FileVerdict] = {}
    for target in targets:
        for entry in _hub_files(target):
            repo, file = entry["hub_repo"], entry["hub_file"]
            if repo not in statuses:
                statuses[repo] = security.status(repo)
            confirm = entry["identifier"] in alerted
            known = verdicts.get((repo, file))
            if known is None or (confirm and known.state == hub.CLEAN and not known.tree_response):
                verdicts[(repo, file)] = security.verdict(statuses[repo], file, confirm=confirm)
    return verdicts


def _explicitly_safe(verdict: hub.FileVerdict, sha256: str) -> bool:
    """The hub lists the file as ``safe`` for the matching hash; nothing less clears an alert."""
    file_status = verdict.file_status or {}
    return (
        verdict.state == hub.CLEAN
        and verdict.hub_sha256 == sha256
        and file_status.get("status") == "safe"
    )


def _hub_observations(verdict: hub.FileVerdict, detail: dict[str, Any]) -> list[_Observation]:
    found = []
    for response in (verdict.status.response, verdict.tree_response):
        if response is not None:
            found.append(
                _Observation(
                    source_of(response.url),
                    response.url,
                    response.retrieved_at,
                    response.body,
                    detail,
                )
            )
    return found


def _apply_hub(
    store: Store, run_id: int, target: _Target, verdicts: Mapping[tuple[str, str], hub.FileVerdict]
) -> None:
    for entry in _hub_files(target):
        verdict = verdicts.get((entry["hub_repo"], entry["hub_file"]))
        if verdict is None:
            continue
        identifier = entry["identifier"]
        sha256 = identifier.removeprefix("sha256:")
        if verdict.state == hub.CLEAN:
            alert = store.find_open_alert(target.model_id, weight_cause_key(HUB_SCAN_ALERT, sha256))
            if alert is not None and _explicitly_safe(verdict, sha256):
                detail = {
                    "scanner": HF_SCAN,
                    "verdict": verdict.state,
                    "file_status": "safe",
                    "level": verdict.level,
                    "scanners": verdict.scanners,
                    "hub_repo": verdict.repo,
                    "hub_file": verdict.file,
                    "hub_commit": verdict.status.commit,
                    "hub_sha256": verdict.hub_sha256,
                    "location": _where(entry),
                }
                observations = _hub_observations(verdict, detail)
                linked = store.alert_evidence(alert["alert_id"])
                ids = _store_observations(store, run_id, identifier, observations, linked)
                _close(store, target, alert, "cleared", ids)
            continue
        detail: dict[str, Any] = {
            "scanner": HF_SCAN,
            "verdict": verdict.state,
            "level": verdict.level,
            "scanners": verdict.scanners,
            "hub_repo": verdict.repo,
            "hub_file": verdict.file,
            "hub_commit": verdict.status.commit,
            "location": _where(entry),
        }
        if verdict.state in (hub.PENDING, hub.MISSING, hub.UNRECOGNISED):
            detail["reason"] = verdict.reason
            observations = _hub_observations(verdict, detail)
            _watch(store, run_id, target, HUB_SCAN_UNKNOWN, identifier, detail, observations)
            continue
        if verdict.hub_sha256 != sha256:
            detail |= {"inventory_sha256": sha256, "hub_sha256": verdict.hub_sha256}
            observations = _hub_observations(verdict, detail)
            _watch(store, run_id, target, HASH_MISMATCH, identifier, detail, observations)
            continue
        observations = _hub_observations(verdict, detail)
        if verdict.state == hub.UNSAFE:
            cause = {"identifier": identifier, **detail}
            _weight_alert(store, run_id, target, HUB_SCAN_ALERT, entry, cause, observations)
        else:  # caution: the hub's counterpart of a suspicious import
            _watch(store, run_id, target, SCAN_SUSPICIOUS, identifier, detail, observations)


# --- registration and dismissal (US4) -------------------------------------------------------------

INVENTORY_SOURCE = "inventory"


def _package_finding(
    store: Store, alert: Mapping[str, Any], entries: Sequence[Mapping[str, Any]]
) -> tuple[bool, Mapping[str, Any] | None]:
    """Whether the new inventory still has the advisory's package at an affected version.

    The advisory is evaluated from the copy cached at the last check, so no source is consulted.
    An unpinned entry of the same package is not proof the cause is gone.
    """
    cause = alert["cause"]
    name = canonicalize_name(cause["package"])
    same = [
        entry
        for entry in entries
        if entry["kind"] == "package" and canonicalize_name(entry.get("name") or "") == name
    ]
    pinned = [entry for entry in same if entry["pinned"]]
    if not pinned:
        return bool(same), None
    for entry in pinned:
        if entry["identifier"] == cause["identifier"]:
            return True, entry
    cached = store.get_advisory(cause.get("source", SOURCE), cause["advisory_id"])
    for entry in pinned:
        if cached is None or advisory_affects(
            {"affected": cached["affected"] or []}, entry["name"], entry["version"]
        ):
            return True, entry
    return False, pinned[0]


def reevaluate_version(store: Store, model_id: str, version: int) -> dict[str, list[int]]:
    """Settle the model's open alerts against a newly registered version (FR-014, SC-004).

    A cause the new inventory no longer has closes its alert as ``fixed`` by that version, with
    the new inventory as evidence; a cause it still has carries the alert forward. Only the two
    inventories are compared: no source is consulted, so a failed source cannot affect it.
    """
    result: dict[str, list[int]] = {"fixed": [], "carried_forward": []}
    record = store.get_version(model_id, version)
    if record is None or version <= 1:
        return result
    entries = store.entries(model_id, version)
    weights = {entry["identifier"]: entry for entry in entries if entry["kind"] == "weight_file"}
    code_free = [
        entry["identifier"]
        for entry in entries
        if entry["kind"] == "weight_file" and entry["can_run_code"] is False
    ]
    for alert in store.alerts_for(model_id, ["open"]):
        if alert["current_version"] >= version:
            continue
        cause = dict(alert["cause"])
        detail: dict[str, Any] = {"previous_version": alert["current_version"], "version": version}
        if alert["kind"] == PACKAGE_ALERT:
            present, entry = _package_finding(store, alert, entries)
            if present and entry is None:
                continue  # only an unpinned entry: neither fixed nor shown again
            if present and entry is not None:
                cause |= {"version": entry["version"], "identifier": entry["identifier"]}
            detail["found"] = None if entry is None else entry["identifier"]
        elif alert["kind"] in DATASET_ALERTS:
            present = _dataset_present(cause, alert["kind"], entries)
            detail["found"] = cause["identifier"] if present else None
        else:
            entry = weights.get(cause["identifier"])
            present = entry is not None and bool(entry["pinned"])
            if present and entry is not None:
                cause["location"] = _where(entry)
            if alert["kind"] == FORMAT_POLICY_ALERT and present and code_free:
                present = False
                detail["code_free_beside"] = code_free
            detail["found"] = cause["identifier"] if present else None
        if present:
            store.update_open_alert(
                alert["alert_id"],
                current_version=version,
                severity=alert["severity"],
                severity_origin=alert["severity_origin"],
                cause=cause,
            )
            result["carried_forward"].append(alert["alert_id"])
            continue
        evidence_id = store.add_evidence(
            source=INVENTORY_SOURCE,
            url="",
            retrieved_at=store.now(),
            matched_identifier=alert["cause"]["identifier"],
            body=_json_body(record["inventory"]),
            detail=detail,
        )
        store.link_alert_evidence(alert["alert_id"], evidence_id)
        store.close_alert(alert["alert_id"], state="fixed", closed_by_version=version)
        result["fixed"].append(alert["alert_id"])
    return result


def dismiss_alert(
    store: Store, alert_id: int, *, reason: str, by: str, note: str | None = None
) -> dict[str, Any]:
    """Dismiss an open alert with a listed reason, recording who and when (FR-015)."""
    if reason not in DISMISSAL_REASONS:
        listed = ", ".join(DISMISSAL_REASONS)
        raise ValueError(f"dismissal reason must be one of {listed}, got {reason!r}")
    if not by.strip():
        raise ValueError("a dismissal needs the name of who dismissed it")
    alert = store.get_alert(alert_id)
    if alert is None:
        raise ValueError(f"no alert {alert_id}")
    if alert["state"] != "open":
        raise ValueError(f"alert {alert_id} is not open (it is {alert['state']})")
    store.close_alert(
        alert_id,
        state="dismissed",
        dismissal_reason=reason,
        dismissed_by=by.strip(),
        note=note,
    )
    closed = store.get_alert(alert_id)
    assert closed is not None
    return closed


# --- feature 002, US1: dataset retractions and removals (data-model.md, research U1 to U6) -----

DATASET_RETRACTED = "dataset_retracted"
PAPER_RETRACTED = "paper_retracted"
DATASET_REMOVED = "dataset_removed"
DATASET_NOT_FINDABLE = "dataset_not_findable"
DATASET_ALERTS = (DATASET_RETRACTED, PAPER_RETRACTED, DATASET_REMOVED, DATASET_NOT_FINDABLE)
DATASET_UNREACHABLE = "dataset_unreachable"
DATASET_MOVED = "dataset_moved"
UPSTREAM_NOTICE = "upstream_notice"
# Research U9: every US1 alert is HIGH by policy.
DATASET_SEVERITY = "HIGH"
NO_REASON = "no reason given"

HF_HUB = hub.DATASET_SOURCE
HF_TAKEDOWNS = hf_takedowns.SOURCE
CROSSREF = crossref.SOURCE
DATACITE = datacite.SOURCE
ZENODO = zenodo.SOURCE
FIGSHARE = figshare.SOURCE
UPSTREAM_SOURCES = (HF_HUB, HF_TAKEDOWNS, CROSSREF, DATACITE, ZENODO, FIGSHARE)
DOI_SOURCES = (CROSSREF, DATACITE, ZENODO, FIGSHARE)


def dataset_cause_key(kind: str, identifier: str, paper_doi: str | None = None) -> str:
    """Cause keys of data-model.md: kind + dataset DOI or identifier (+ paper DOI)."""
    return f"{kind}:{identifier}" if paper_doi is None else f"{kind}:{identifier}:{paper_doi}"


@dataclass
class _UpstreamRead:
    """Every upstream answer the run needs, read before anything changes (FR-018)."""

    statuses: dict[str, str]
    reads: dict[str, Any]


def _datasets(targets: Sequence[_Target]) -> list[dict[str, Any]]:
    return [
        entry
        for target in targets
        for entry in target.entries
        if entry["kind"] == "dataset" and entry["pinned"]
    ]


def _agency(store: Store, doi: str) -> str | None:
    routing = store.get_routing(doi)
    return None if routing is None else routing["agency"]


def _routed(store: Store, dois: Sequence[str], repository: str) -> dict[str, str]:
    found = {}
    for doi in dois:
        routing = store.get_routing(doi)
        if routing and routing["repository"] == repository and routing["repository_id"]:
            found[doi] = str(routing["repository_id"])
    return found


def _read_upstream(
    store: Store, fetcher: Fetcher, targets: Sequence[_Target], sources: Sequence[str]
) -> _UpstreamRead:
    """Read each requested upstream source in full; a failed one is recorded and not applied."""
    entries = _datasets(targets)
    hub_repos = list(dict.fromkeys(e["hub_repo"] for e in entries if e.get("hub_repo")))
    dataset_dois = list(dict.fromkeys(e["identifier"] for e in entries if not e.get("hub_repo")))
    paper_dois = [paper for entry in entries for paper in entry.get("paper_dois") or []]
    all_dois = list(dict.fromkeys(dataset_dois + paper_dois))
    if any(source in DOI_SOURCES for source in sources):
        # A DOI whose agency lookup failed at registration is looked up again (research U1).
        for doi in all_dois:
            ensure_agency(store, fetcher, doi)

    readers: dict[str, Callable[[], Any]] = {
        DATACITE: lambda: {
            doi: datacite.DataCite(fetcher).record(doi)
            for doi in dataset_dois
            if datacite.queried(_agency(store, doi))
        },
        ZENODO: lambda: {
            doi: zenodo.Zenodo(fetcher).record(rid)
            for doi, rid in _routed(store, dataset_dois, "zenodo").items()
        },
        FIGSHARE: lambda: {
            doi: figshare.Figshare(fetcher).article(rid)
            for doi, rid in _routed(store, dataset_dois, "figshare").items()
        },
        CROSSREF: lambda: {
            doi: crossref.Crossref(fetcher).work(doi)
            for doi in all_dois
            if crossref.queried(_agency(store, doi))
        },
        HF_HUB: lambda: {repo: hub.read_dataset(fetcher, repo) for repo in hub_repos},
        HF_TAKEDOWNS: lambda: hf_takedowns.TakedownIndex(fetcher).read() if hub_repos else None,
    }
    statuses: dict[str, str] = {}
    reads: dict[str, Any] = {}
    # In this order: DataCite's answers route DOIs to Zenodo and Figshare.
    for source in UPSTREAM_SOURCES:
        if source not in sources:
            continue
        try:
            reads[source] = readers[source]()
        except SourceFailedError as error:
            statuses[source] = f"failed: {error.reason}"
            continue
        statuses[source] = "ok"
        if source == DATACITE:
            for record in reads[source].values():
                datacite.remember_repository(store, record)
        if source == HF_TAKEDOWNS and reads[source] is not None:
            store.replace_takedown_notices(reads[source].notices)
    return _UpstreamRead(statuses, reads)


class _Observed:
    """Observations already stored in this run: one per item per source (data-model.md)."""

    def __init__(self, store: Store, run_id: int) -> None:
        self.store = store
        self.run_id = run_id
        self._seen: dict[tuple[str, str], dict[str, Any]] = {}

    def __call__(self, source: str, item: str, response: Any, **fields: Any) -> dict[str, Any]:
        key = (source, item)
        if key not in self._seen:
            observation = observe(self.store, self.run_id, source, item, response, **fields)
            if observation is None:
                raise ValueError(f"{source} HTTP {response.status} is not an answer")
            self._seen[key] = observation
        return self._seen[key]


def _link_new(store: Store, alert_id: int, evidence_ids: Sequence[int]) -> None:
    """Link evidence an alert does not already hold (same source, URL and stored body)."""
    held = {(e["source"], e["url"], e["body_sha256"]) for e in store.alert_evidence(alert_id)}
    for evidence_id in evidence_ids:
        evidence = store.get_evidence(evidence_id)
        if evidence is None:
            continue
        key = (evidence["source"], evidence["url"], evidence["body_sha256"])
        if key not in held:
            store.link_alert_evidence(alert_id, evidence_id)
            held.add(key)


def _upstream_alert(
    store: Store,
    target: _Target,
    kind: str,
    cause_key: str,
    cause: dict[str, Any],
    evidence_ids: Sequence[int],
) -> None:
    """Open an upstream alert, or carry the open one forward with any new evidence."""
    existing = store.find_open_alert(target.model_id, cause_key)
    if existing is None:
        alert_id = store.insert_alert(
            model_id=target.model_id,
            kind=kind,
            cause_key=cause_key,
            cause=cause,
            severity=DATASET_SEVERITY,
            severity_origin=POLICY_ORIGIN,
            opened_in_version=target.version,
            evidence_ids=list(dict.fromkeys(evidence_ids)),
        )
        target.summary["opened"].append(alert_id)
        return
    alert_id = existing["alert_id"]
    _link_new(store, alert_id, evidence_ids)
    store.update_open_alert(
        alert_id,
        current_version=max(existing["current_version"], target.version),
        severity=DATASET_SEVERITY,
        severity_origin=POLICY_ORIGIN,
        cause=cause,
    )
    if alert_id not in target.summary["carried_forward"]:
        target.summary["carried_forward"].append(alert_id)


def _upstream_watch(
    store: Store,
    target: _Target,
    kind: str,
    identifier: str,
    detail: Mapping[str, Any],
    evidence_ids: Sequence[int],
) -> None:
    watch_event_id = store.record_watch_event(
        model_id=target.model_id,
        version=target.version,
        entry_identifier=identifier,
        kind=kind,
        detail=detail,
        evidence_ids=evidence_ids,
    )
    if watch_event_id not in target.summary["watch_events"]:
        target.summary["watch_events"].append(watch_event_id)


def _apply_crossref(
    store: Store,
    target: _Target,
    observed: _Observed,
    dataset: str,
    doi: str,
    role: str,
    work: crossref.CrossrefWork,
) -> None:
    updates = [u.as_dict() for u in work.updates] if work.outcome == "reachable" else None
    evidence_id = observed(CROSSREF, doi, work.response, updates=updates)["evidence_ref"]
    not_found = work.not_found_kind(role)
    if not_found is not None:
        detail = {"source": CROSSREF, "http_status": work.response.status}
        detail |= {"dataset": dataset, "doi": doi}
        _upstream_watch(store, target, not_found, doi, detail, [evidence_id])
        return
    cause: dict[str, Any] = {"identifier": dataset, "dataset": dataset}
    if role == "dataset":
        kind, cause_key = DATASET_RETRACTED, dataset_cause_key(DATASET_RETRACTED, doi)
        cause["doi"] = doi
    else:
        kind, cause_key = PAPER_RETRACTED, dataset_cause_key(PAPER_RETRACTED, dataset, doi)
        cause["paper_doi"] = doi
    notices = [u.as_dict() for u in (*work.retractions, *work.notices)]
    if work.retractions:
        cause["notices"] = notices
        _upstream_alert(store, target, kind, cause_key, cause, [evidence_id])
        return
    existing = store.find_open_alert(target.model_id, cause_key)
    if existing is not None:
        # Research U12: Crossref no longer lists a retraction, withdrawal or removal.
        _close(store, target, existing, "withdrawn", [evidence_id])
    if work.notices:
        detail = {"source": CROSSREF, "dataset": dataset, "doi": doi, "notices": notices}
        _upstream_watch(store, target, UPSTREAM_NOTICE, doi, detail, [evidence_id])


def _apply_doi_dataset(
    store: Store,
    target: _Target,
    observed: _Observed,
    reads: Mapping[str, Any],
    entry: Mapping[str, Any],
) -> None:
    doi = entry["identifier"]
    base = {"identifier": doi, "dataset": doi}
    record = (reads.get(DATACITE) or {}).get(doi)
    if record is not None:
        evidence_id = observed(DATACITE, doi, record.response)["evidence_ref"]
        if record.outcome == "not_found":
            cause = base | {"doi": doi, "source": DATACITE, "http_status": record.response.status}
            key = dataset_cause_key(DATASET_NOT_FINDABLE, doi)
            _upstream_alert(store, target, DATASET_NOT_FINDABLE, key, cause, [evidence_id])
    removal = (reads.get(ZENODO) or {}).get(doi)
    if removal is not None:
        observation = observed(ZENODO, doi, removal.response, removal=removal.removal)
        evidence_id = observation["evidence_ref"]
        if removal.outcome == "removed":
            tombstone = removal.removal or {}
            cause = base | {
                "host": "zenodo",
                "record_id": removal.record_id,
                "removal_date": tombstone.get("removal_date"),
                "reason": tombstone.get("removal_reason") or NO_REASON,
            }
            key = dataset_cause_key(DATASET_REMOVED, doi)
            _upstream_alert(store, target, DATASET_REMOVED, key, cause, [evidence_id])
        elif removal.outcome == "not_found":
            detail = {"source": ZENODO, "http_status": 404, "record_id": removal.record_id}
            _upstream_watch(store, target, DATASET_UNREACHABLE, doi, detail, [evidence_id])
    article = (reads.get(FIGSHARE) or {}).get(doi)
    if article is not None:
        evidence_id = observed(FIGSHARE, doi, article.response)["evidence_ref"]
        kind = article.not_found_kind()
        if kind is not None:
            detail = {"source": FIGSHARE, "http_status": 404, "article_id": article.article_id}
            _upstream_watch(store, target, kind, doi, detail, [evidence_id])
    works = reads.get(CROSSREF) or {}
    if doi in works:
        _apply_crossref(store, target, observed, doi, doi, "dataset", works[doi])


def _apply_hub_dataset(
    store: Store,
    target: _Target,
    observed: _Observed,
    reads: Mapping[str, Any],
    entry: Mapping[str, Any],
) -> None:
    item, repo = entry["identifier"], entry["hub_repo"]
    log = reads.get(HF_TAKEDOWNS)
    notice: dict[str, str] | None = None
    notice_evidence: list[int] = []
    if log is not None:
        found = sorted(log.find(repo), key=lambda found_notice: found_notice["notice_date"])
        notice = found[-1] if found else None
        detail = hf_takedowns.evidence_detail(notice) if notice else {"matched": None}
        observation = observed(HF_TAKEDOWNS, item, log.response, detail=detail, removal=notice)
        if notice is not None:
            notice_evidence = [observation["evidence_ref"]]
    dataset = (reads.get(HF_HUB) or {}).get(repo)
    if dataset is None:
        return
    observation = observed(
        HF_HUB,
        item,
        dataset.response,
        disabled=dataset.disabled,
        gated=dataset.gated,
        head_revision=dataset.sha,
    )
    evidence_id = observation["evidence_ref"]
    status = dataset.response.status
    if dataset.outcome == "redirected":
        detail = {"source": HF_HUB, "http_status": status, "from": repo, "to": dataset.moved_to}
        detail["redirected_to"] = dataset.response.redirected_to
        _upstream_watch(store, target, DATASET_MOVED, item, detail, [evidence_id])
        return
    if dataset.outcome == "refused":
        detail = {"source": HF_HUB, "http_status": status}
        _upstream_watch(store, target, DATASET_UNREACHABLE, item, detail, [evidence_id])
        return
    if not dataset.disabled:
        return
    key = dataset_cause_key(DATASET_REMOVED, item)
    cause: dict[str, Any] = {
        "identifier": item,
        "dataset": item,
        "host": "huggingface",
        "disabled": True,
        "notice_date": None,
        "reason": NO_REASON,
    }
    if notice is not None:
        cause |= {
            "notice_date": notice["notice_date"],
            "notice_label": hf_takedowns.NOTICE_LABEL,
            "reported_content": notice["reported_content"],
        }
    elif log is None:
        # The log was not read in this run, so what an open alert shows of it stays (FR-018).
        existing = store.find_open_alert(target.model_id, key)
        if existing is not None:
            kept = ("notice_date", "notice_label", "reported_content")
            cause |= {name: existing["cause"][name] for name in kept if name in existing["cause"]}
    _upstream_alert(store, target, DATASET_REMOVED, key, cause, [evidence_id, *notice_evidence])


def _apply_upstream(
    store: Store, target: _Target, observed: _Observed, read: _UpstreamRead
) -> None:
    reads = {source: read.reads[source] for source in read.reads if read.statuses[source] == "ok"}
    for entry in target.entries:
        if entry["kind"] != "dataset" or not entry["pinned"]:
            continue
        if entry.get("hub_repo"):
            _apply_hub_dataset(store, target, observed, reads, entry)
        else:
            _apply_doi_dataset(store, target, observed, reads, entry)
        # Papers the owner ties to the dataset, whether it has a DOI or lives on the hub (FR-004).
        works = reads.get(CROSSREF) or {}
        for paper in entry.get("paper_dois") or []:
            if paper in works:
                dataset = entry["identifier"]
                _apply_crossref(store, target, observed, dataset, paper, "paper", works[paper])


def _dataset_present(
    cause: Mapping[str, Any], kind: str, entries: Sequence[Mapping[str, Any]]
) -> bool:
    """Whether a new inventory still depends on the alert's dataset (and its tied paper)."""
    for entry in entries:
        if entry["kind"] != "dataset" or not entry["pinned"]:
            continue
        if entry["identifier"] != cause["identifier"]:
            continue
        if kind != PAPER_RETRACTED or cause.get("paper_doi") in (entry.get("paper_dois") or []):
            return True
    return False

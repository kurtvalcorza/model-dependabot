"""Check runs, package alerts, watch events and evidence (data-model.md; FR-006 to FR-010, FR-016).

A check run reads each requested source in full before it changes anything. If a source fails
anywhere in the run, nothing that depends on it is changed: it is recorded as ``failed`` in the run
and every alert that depends on it is left as it was, while the sources that answered are applied
as usual (FR-016, SC-007).

For OSV, a package alert opens only when OSV lists the advisory for the exact pinned version and the
local PEP 440 evaluation of the record's ranges agrees (research R2); when the two disagree, a watch
event of kind ``advisory_unmatched`` is recorded instead (FR-007). An open alert is carried forward
rather than raised again (FR-010): its current version, severity and fixed versions follow the
source, and a changed record is added as new evidence beside the earlier one. A withdrawn advisory
closes its alerts as ``withdrawn`` with the withdrawn record as evidence (FR-009). OSV leaves
withdrawn records out of query answers, so the advisory of every open alert is fetched by id on each
run. A record OSV answers ``404`` for is gone, not withdrawn and not unaffected: it records an
``advisory_gone`` watch event with the 404 as evidence, raises nothing, and an alert that stands for
it stays open until a person dismisses it or a newer version drops the package (review F1, amended
2026-10-31). The rest of the OSV read is applied as usual.

One alert per vulnerability (feature 006): records OSV returns for the same package version that
alias each other, directly or through other records, form one group and raise one alert, keyed by
the group's primary id (``primary_advisory_id``) and listing every id in ``cause.advisory_ids``,
with the highest severity across them and every record as evidence. Open alerts stored for ids
that are now one group are merged at the next check: one is kept and the others close as
``cleared`` with a note naming it. Evidence is reused when a record's content is unchanged, compared
by the canonical hash of its JSON (``store.same_evidence``), so bytes that differ only in layout
add no evidence.

Weight files (research R4, R5; FR-011 to FR-013, FR-021, FR-022): every pinned code-capable file
gets a ``pickle_format`` watch event, and under the owner's ``strict`` format policy a
``format_policy`` alert when no code-free file is beside it in the version. These two rules read
only the inventory and the owner's recorded policy, and run whenever ``picklescan`` or ``hf-scan``
is requested. ``picklescan`` scans the local files (never loading them): a ``dangerous`` global
raises a ``weight_file_scan`` alert, a ``suspicious`` one a ``scan_suspicious`` watch event, and a
scan that stopped early a ``scan_incomplete`` watch event. ``hf-scan`` reads the hub's verdict: only
an explicit ``unsafe`` verdict for a file whose hub SHA-256 matches the inventory raises a
``hub_scan`` alert; anything else it cannot confirm is a watch event.

Closing (US4; FR-014, FR-015, FR-023, constitution III): registering a newer version closes an alert
as ``fixed`` when the new inventory no longer has its cause and carries it forward when it does,
consulting no source; a gap for the same dependency leaves it as it was. A check closes an alert as
``cleared`` when the source that answered in that run no longer shows the cause: OSV and the local
evaluation both agree the pinned version is unaffected, the hub gives an explicit ``safe`` verdict
for the matching hash, or the owner's recorded format policy is no longer ``strict``. A person
dismisses an alert with a listed reason.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from packaging.utils import canonicalize_name

from model_dependabot.inventory.build import HUB_DATASET_PREFIX, hash_stream, huggingface_purl
from model_dependabot.matching.severity import severity_of, severity_rank
from model_dependabot.matching.versions import (
    affected_ranges,
    evaluate_advisory,
    fixed_versions,
)
from model_dependabot.sources import (
    crossref,
    datacite,
    figshare,
    hf_takedowns,
    pickle_scan,
    zenodo,
)
from model_dependabot.sources import hf as hub
from model_dependabot.sources.doi_ra import NOT_REGISTERED, ask_agency, refresh_agency
from model_dependabot.sources.doi_ra import SOURCE as DOI_RA
from model_dependabot.sources.doi_ra import unknown as agency_unknown
from model_dependabot.sources.fetcher import Fetcher, Response, SourceFailedError, source_of
from model_dependabot.sources.osv import (
    SOURCE,
    BatchAnswer,
    GoneRecord,
    OsvClient,
    VulnRecord,
    aliases,
    pinned_packages,
    withdrawn,
)
from model_dependabot.store import DISMISSAL_REASONS, Store, content_key, same_evidence
from model_dependabot.upstream.changes import (
    LICENCE_SOURCES,
    appeared,
    changed,
    compare_licence,
    licence_reference,
    previous_answer,
    refusal_run,
)
from model_dependabot.upstream.licences import normalise
from model_dependabot.upstream.observe import observe

PACKAGE_ALERT = "package_advisory"
UNMATCHED = "advisory_unmatched"
GONE = "advisory_gone"

WEIGHT_SCAN_ALERT = "weight_file_scan"
HUB_SCAN_ALERT = "hub_scan"
FORMAT_POLICY_ALERT = "format_policy"
PICKLE_FORMAT = "pickle_format"
SCAN_SUSPICIOUS = "scan_suspicious"
SCAN_INCOMPLETE = "scan_incomplete"
HUB_SCAN_UNKNOWN = "hub_scan_unknown"
HASH_MISMATCH = "hash_mismatch"
WEIGHT_FILE_ABSENT = "weight_file_absent"
RECORD_URL_PREFIX = "registration-record:sha256:"
ABSENT_REASON = (
    "the weight file's bytes are not on this machine: it was registered from a registration"
    " record and scanned where the weights are"
)

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
    record_sha256: str | None = None


@dataclass
class _OsvRead:
    batch: BatchAnswer
    records: dict[str, VulnRecord]
    gone: dict[str, GoneRecord] = field(default_factory=dict)


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
        targets.append(
            _Target(
                model_id,
                version,
                entries,
                summary,
                record.get("base_dir"),
                record.get("registration_record_sha256"),
            )
        )

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
                wanted.update(advisory_ids_of(alert))
    records: dict[str, VulnRecord] = {}
    gone: dict[str, GoneRecord] = {}
    for advisory_id in sorted(wanted):
        found = client.vuln(advisory_id)
        if isinstance(found, GoneRecord):
            gone[advisory_id] = found  # a 404 by id: the record is gone (review F1)
        else:
            records[advisory_id] = found
    return _OsvRead(batch, records, gone)


def advisory_ids_of(alert: Mapping[str, Any]) -> list[str]:
    """Every OSV record a package alert stands for, primary first (one before feature 006)."""
    cause = alert["cause"]
    return list(cause.get("advisory_ids") or [cause["advisory_id"]])


def primary_advisory_id(ids: Sequence[str]) -> str:
    """The id an alias group is known by: the first GHSA id if there is one, else the first id.

    "First" is lexicographic, so the choice depends only on the ids (feature 006, E2).
    """
    ghsa = sorted(advisory_id for advisory_id in ids if advisory_id.startswith("GHSA-"))
    return ghsa[0] if ghsa else sorted(ids)[0]


def _ordered_ids(ids: Sequence[str]) -> list[str]:
    primary = primary_advisory_id(ids)
    return [primary, *sorted(set(ids) - {primary})]


def alias_groups(records: Sequence[VulnRecord]) -> list[list[VulnRecord]]:
    """The records that are one vulnerability, each group ordered primary first.

    Two records are one vulnerability when one names the other in ``aliases``, or both name the
    same alias, directly or through other records (the alias relation is symmetric and
    transitive). A record that shares no alias with another is a group of its own.
    """
    parent: dict[str, str] = {}

    def root(name: str) -> str:
        parent.setdefault(name, name)
        while parent[name] != name:
            parent[name] = parent[parent[name]]
            name = parent[name]
        return name

    for record in records:
        for alias in aliases(record.advisory):
            parent[root(alias)] = root(record.advisory["id"])
    groups: dict[str, dict[str, VulnRecord]] = {}
    for record in records:
        groups.setdefault(root(record.advisory["id"]), {})[record.advisory["id"]] = record
    ordered = [[group[i] for i in _ordered_ids(list(group))] for group in groups.values()]
    return sorted(ordered, key=lambda group: group[0].advisory["id"])


def _evidence(
    store: Store,
    run_id: int,
    record: VulnRecord,
    identifier: str,
    detail: Mapping[str, Any],
    existing: Sequence[Mapping[str, Any]] = (),
) -> tuple[int, bool]:
    """The evidence id for this record, reusing a record of the same content already linked.

    A JSON body is compared by its canonical hash, so a re-serialised but unchanged advisory is the
    same evidence (feature 006, E1).
    """
    for evidence in existing:
        if same_evidence(evidence, SOURCE, record.response.url, record.response.body):
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


@dataclass
class _OsvApply:
    """One model's OSV pass: the batch detail stored once and the open alerts already settled."""

    store: Store
    run_id: int
    read: _OsvRead
    target: _Target
    open_alerts: list[dict[str, Any]]
    claimed: set[int] = field(default_factory=set)
    stored: dict[int, str] = field(default_factory=dict)

    def batch_detail_for(self, identifier: str) -> dict[str, Any]:
        response = self.read.batch.response_for(identifier)
        if response is None:
            return {}
        if id(response) not in self.stored:
            self.stored[id(response)] = self.store.put_body(response.body)
        return {"query_url": response.url, "query_sha256": self.stored[id(response)]}

    def related(self, package: str, ids: Sequence[str]) -> list[dict[str, Any]]:
        """Open alerts of this package about any of ``ids``, not yet settled in this pass."""
        name = canonicalize_name(package)
        return [
            alert
            for alert in self.open_alerts
            if alert["alert_id"] not in self.claimed
            and canonicalize_name(alert["cause"]["package"]) == name
            and set(advisory_ids_of(alert)) & set(ids)
        ]


def _apply_osv(store: Store, run_id: int, read: _OsvRead, target: _Target) -> None:
    open_alerts = [
        alert
        for alert in store.alerts_for(target.model_id, ["open"])
        if alert["kind"] == PACKAGE_ALERT
    ]
    run = _OsvApply(store, run_id, read, target, open_alerts)
    packages = {entry["identifier"]: entry for entry in pinned_packages(target.entries)}

    for identifier, entry in packages.items():
        affected: list[VulnRecord] = []
        details: dict[str, dict[str, Any]] = {}
        for advisory_id in read.batch.matches.get(identifier, []):
            if advisory_id in read.gone:
                _gone(run, identifier, read.gone[advisory_id])  # listed, but nothing to match
                continue
            record = read.records[advisory_id]
            if withdrawn(record.advisory):
                continue  # closed below if no other record keeps its alert open; never raised
            local = evaluate_advisory(record.advisory, entry["name"], entry["version"])
            match = {
                "osv_match": True,
                "local_match": local.affected,
                **run.batch_detail_for(identifier),
            }
            if not local.evaluated:
                match["local_unevaluated"] = list(local.reasons)
            if local.affected:
                affected.append(record)
                details[advisory_id] = match
            else:
                _unmatched(store, run_id, target, identifier, record, match)
        for group in alias_groups(affected):
            _raise_or_carry(run, entry, group, details)

    for alert in open_alerts:
        identifier = alert["cause"]["identifier"]
        missing = [read.gone[a] for a in advisory_ids_of(alert) if a in read.gone]
        for gone in missing:
            _gone(run, identifier, gone)
        if alert["alert_id"] in run.claimed:
            continue
        if missing:
            continue  # a gone record is no answer about the cause: the alert stays open (F1)
        records = [read.records[advisory_id] for advisory_id in advisory_ids_of(alert)]
        live = [record for record in records if not withdrawn(record.advisory)]
        if not live:
            # Every record the alert stands for is withdrawn (FR-009).
            evidence_ids = [_withdrawal(run, alert, record) for record in records]
            _close(store, target, alert, "withdrawn", evidence_ids)
            continue
        entry = packages.get(identifier)
        if entry is None:
            continue  # the package changed in this version: settled at registration
        listed = set(read.batch.matches.get(identifier, []))
        if any(record.advisory["id"] in listed for record in live):
            continue  # OSV lists it, the local evaluation does not: recorded above as unmatched
        undecided = False
        for record in live:
            local = evaluate_advisory(record.advisory, entry["name"], entry["version"])
            if local.affected or not local.evaluated:
                # OSV no longer lists it but the local check disagrees or cannot read the range:
                # a watch event, and the alert stays open (no clearance without agreement).
                match = {
                    "osv_match": False,
                    "local_match": local.affected,
                    **run.batch_detail_for(identifier),
                }
                if not local.evaluated:
                    match["local_unevaluated"] = list(local.reasons)
                _unmatched(store, run_id, target, identifier, record, match)
                undecided = True
        if undecided:
            continue
        # OSV and the local evaluation agree the pinned version is no longer affected by any
        # record the alert stands for: the source cleared it (FR-023).
        linked = store.alert_evidence(alert["alert_id"])
        evidence_ids = []
        for record in records:
            if withdrawn(record.advisory):
                evidence_ids.append(_withdrawal(run, alert, record))
                continue
            detail = {"osv_match": False, "local_match": False, **run.batch_detail_for(identifier)}
            evidence_id, _ = _evidence(store, run_id, record, identifier, detail, linked)
            _cache(store, record, evidence_id)
            evidence_ids.append(evidence_id)
        _close(store, target, alert, "cleared", evidence_ids)


def _gone(run: _OsvApply, identifier: str, gone: GoneRecord) -> None:
    """OSV answered 404 for a record: an ``advisory_gone`` watch event, never a closure (F1)."""
    store, target = run.store, run.target
    existing = store.get_watch_event(target.model_id, target.version, identifier, GONE)
    detail: dict[str, Any] = dict(existing["detail"]) if existing else {}
    advisories = dict(detail.get("advisories") or {})
    advisories[gone.advisory_id] = {"status": gone.response.status}
    detail["advisories"] = advisories
    response = gone.response
    evidence_id = next(
        (
            int(evidence["evidence_id"])
            for evidence in (existing["evidence"] if existing else [])
            if same_evidence(evidence, SOURCE, response.url, response.body)
        ),
        None,
    )
    if evidence_id is None:
        evidence_id = store.add_evidence(
            source=SOURCE,
            url=response.url,
            retrieved_at=response.retrieved_at,
            matched_identifier=identifier,
            body=response.body,
            detail={"status": response.status},
            run_id=run.run_id,
        )
    watch_event_id = store.record_watch_event(
        model_id=target.model_id,
        version=target.version,
        entry_identifier=identifier,
        kind=GONE,
        detail=detail,
        evidence_ids=[evidence_id],
    )
    if watch_event_id not in target.summary["watch_events"]:
        target.summary["watch_events"].append(watch_event_id)


def _withdrawal(run: _OsvApply, alert: Mapping[str, Any], record: VulnRecord) -> int:
    """Evidence that ``record`` is withdrawn, linked to ``alert`` and cached."""
    identifier = alert["cause"]["identifier"]
    detail = {"withdrawn": withdrawn(record.advisory), **run.batch_detail_for(identifier)}
    linked = run.store.alert_evidence(alert["alert_id"])
    evidence_id, _ = _evidence(run.store, run.run_id, record, identifier, detail, linked)
    run.store.link_alert_evidence(alert["alert_id"], evidence_id)
    _cache(run.store, record, evidence_id)
    return evidence_id


def _close(
    store: Store,
    target: _Target,
    alert: Mapping[str, Any],
    state: str,
    evidence_ids: Sequence[int],
    note: str | None = None,
) -> None:
    """Close an alert on the source's own observation, kept as evidence (constitution III)."""
    for evidence_id in evidence_ids:
        store.link_alert_evidence(alert["alert_id"], evidence_id)
    store.close_alert(alert["alert_id"], state=state, note=note)
    target.summary["closed"].append(alert["alert_id"])


def _group_cause(entry: Mapping[str, Any], group: Sequence[VulnRecord]) -> dict[str, Any]:
    """The cause of one alert for an alias group: every id and the union of what they publish."""
    name, version = entry["name"], entry["version"]
    ids = [record.advisory["id"] for record in group]
    alias_list: list[str] = []
    affected: list[Any] = []
    fixed: list[str] = []
    for record in group:
        others = [] if record is group[0] else [record.advisory["id"]]
        for alias in [*others, *aliases(record.advisory)]:
            if alias != ids[0] and alias not in alias_list:
                alias_list.append(alias)
        for item in affected_ranges(record.advisory, name):
            if item not in affected:
                affected.append(item)
        for value in fixed_versions(record.advisory, name):
            if value not in fixed:
                fixed.append(value)
    return {
        "advisory_id": ids[0],
        "advisory_ids": ids,
        "aliases": alias_list,
        "source": SOURCE,
        "package": name,
        "version": version,
        "identifier": entry["identifier"],
        "affected": affected,
        "fixed": fixed,
    }


def _group_severity(group: Sequence[VulnRecord]) -> tuple[str, str, str]:
    """The highest severity across the records, its origin and the record it came from (R3)."""
    rated = [(*severity_of(record.advisory), record.advisory["id"]) for record in group]
    return min(rated, key=lambda item: severity_rank(item[0]))  # min keeps the first of a tie


def _raise_or_carry(
    run: _OsvApply,
    entry: Mapping[str, Any],
    group: Sequence[VulnRecord],
    details: Mapping[str, Mapping[str, Any]],
) -> None:
    """One alert for an alias group: raise it, carry it forward or merge earlier ones into it."""
    store, target = run.store, run.target
    cause = _group_cause(entry, group)
    severity, origin, severity_from = _group_severity(group)
    cause["severity_from"] = severity_from
    cause_key = package_cause_key(cause["advisory_id"], entry["name"])
    related = run.related(entry["name"], cause["advisory_ids"])
    keeper = next((alert for alert in related if alert["cause_key"] == cause_key), None)
    if keeper is None and related:
        keeper = min(related, key=lambda alert: alert["alert_id"])
    if keeper is None:
        keeper = store.find_open_alert(target.model_id, cause_key)
    linked = store.alert_evidence(keeper["alert_id"]) if keeper else []
    evidence_ids = []
    for record in group:
        detail = details[record.advisory["id"]]
        evidence_id, _ = _evidence(store, run.run_id, record, entry["identifier"], detail, linked)
        evidence_ids.append(evidence_id)
    for alert in related:
        if keeper is None or alert["alert_id"] == keeper["alert_id"]:
            continue
        # The same vulnerability under another id: merged into the kept alert, with the records
        # that show it as evidence (constitution III).
        note = (
            f"merged into alert {keeper['alert_id']} ({cause['advisory_id']}): OSV lists"
            f" {', '.join(advisory_ids_of(alert))} as the same vulnerability"
        )
        _close(store, target, alert, "cleared", evidence_ids, note)
    if keeper is None:
        alert_id = store.insert_alert(
            model_id=target.model_id,
            kind=PACKAGE_ALERT,
            cause_key=cause_key,
            cause=cause,
            severity=severity,
            severity_origin=origin,
            opened_in_version=target.version,
            evidence_ids=evidence_ids,
        )
        target.summary["opened"].append(alert_id)
    else:
        alert_id = keeper["alert_id"]
        for evidence_id in evidence_ids:
            store.link_alert_evidence(alert_id, evidence_id)
        for advisory_id in advisory_ids_of(keeper):
            record = run.read.records.get(advisory_id)
            if record is not None and withdrawn(record.advisory):
                _withdrawal(run, keeper, record)  # a withdrawn alias, kept as evidence
        store.update_open_alert(
            alert_id,
            current_version=max(keeper["current_version"], target.version),
            severity=severity,
            severity_origin=origin,
            cause=cause,
            cause_key=cause_key,
        )
        target.summary["carried_forward"].append(alert_id)
    run.claimed.update(alert["alert_id"] for alert in related)
    run.claimed.add(alert_id)
    for record, evidence_id in zip(group, evidence_ids, strict=True):
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
    if match.get("local_unevaluated"):
        advisories[record.advisory["id"]]["local_unevaluated"] = list(match["local_unevaluated"])
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
    run_id: int | None,
    identifier: str,
    observations: Sequence[_Observation],
    existing: Sequence[Mapping[str, Any]] = (),
) -> list[int]:
    """Evidence ids for the observations, reusing identical records already linked."""
    ids = []
    for item in observations:
        detail = json.loads(json.dumps(item.detail))
        reused = next(
            (
                int(evidence["evidence_id"])
                for evidence in existing
                if same_evidence(evidence, item.source, item.url, item.body)
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
    run_id: int | None,
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
    run_id: int | None,
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
    absent: bool = False


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
            # Hashed, scanned and hashed again through one handle, in chunks, so the file is
            # never held whole in memory. picklescan seeks (a zip archive is read from its end),
            # so it cannot hash as it reads; the scan counts only if both hashes match the pinned
            # identifier. One handle means a file renamed over this one between the reads is not
            # the one scanned; the second hash catches a change written into it meanwhile, and a
            # changed file is a hash mismatch with the hash read last.
            try:
                with path.open("rb") as handle:
                    scan.actual_sha256, _ = hash_stream(handle)
                    if f"sha256:{scan.actual_sha256}" == entry["identifier"]:
                        report = pickle_scan.scan_handle(handle, path.name)
                        handle.seek(0)
                        scan.actual_sha256, _ = hash_stream(handle)
                        if f"sha256:{scan.actual_sha256}" == entry["identifier"]:
                            scan.report = report
            except OSError as error:
                if target.record_sha256 is not None and not path.exists():
                    scan.absent = True  # registered from a record: the bytes live elsewhere
                else:
                    scan.read_error = f"cannot read the file: {error.strerror or error}"
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
        if scan.absent:
            detail = {
                "scanner": pickle_scan.SCANNER,
                "location": location,
                "reason": ABSENT_REASON,
                "record_sha256": target.record_sha256,
            }
            observation = _Observation(
                pickle_scan.SCANNER,
                f"{RECORD_URL_PREFIX}{target.record_sha256}",
                scan.retrieved_at,
                _json_body(detail),
                detail,
            )
            _watch(store, run_id, target, WEIGHT_FILE_ABSENT, identifier, detail, [observation])
            continue
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
        _apply_report(store, run_id, target, entry, report, url, scan.retrieved_at, body)


def _apply_report(
    store: Store,
    run_id: int | None,
    target: _Target,
    entry: Mapping[str, Any],
    report: pickle_scan.ScanReport,
    url: str,
    retrieved_at: Any,
    body: bytes,
) -> None:
    """Alerts and watch events from one file's scan, made now or recorded where the file is."""
    identifier = entry["identifier"]
    location = entry["location"]
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
        observation = _Observation(report.scanner, url, retrieved_at, body, detail)
        _weight_alert(store, run_id, target, WEIGHT_SCAN_ALERT, entry, cause, [observation])
    if report.suspicious:
        detail = {**base, "suspicious": report.suspicious}
        observation = _Observation(report.scanner, url, retrieved_at, body, detail)
        _watch(store, run_id, target, SCAN_SUSPICIOUS, identifier, detail, [observation])
    if not report.complete:
        detail = {
            **base,
            "position": report.position,
            "size": report.size,
            "reason": report.error,
        }
        observation = _Observation(report.scanner, url, retrieved_at, body, detail)
        _watch(store, run_id, target, SCAN_INCOMPLETE, identifier, detail, [observation])


def apply_recorded_scans(
    store: Store,
    model_id: str,
    version: int,
    record_sha256: str,
    scans: Mapping[str, tuple[pickle_scan.ScanReport, Any, bytes]],
) -> dict[str, list[int]]:
    """Apply the local scans in a registration record to a version just registered from it.

    ``scans`` maps each local file's manifest location to its recorded report, scan time and the
    recorded scan as it stands in the record. The alerts and watch events are the ones a check's
    local scan of the same bytes makes (shared ``_apply_report``); the evidence is the recorded
    scan: source ``picklescan``, the record's SHA-256 in its URL, the scan time as its retrieval
    time and the scanner version in its detail (constitution I). It belongs to no check run.
    """
    record = store.get_version(model_id, version) or {}
    summary: dict[str, Any] = {
        "model_id": model_id,
        "version": version,
        "opened": [],
        "carried_forward": [],
        "closed": [],
        "watch_events": [],
    }
    target = _Target(
        model_id,
        version,
        store.entries(model_id, version),
        summary,
        record.get("base_dir"),
        record_sha256,
    )
    url = f"{RECORD_URL_PREFIX}{record_sha256}"
    for entry in _code_capable(target.entries):
        found = scans.get(entry.get("location") or "")
        if entry.get("hub_repo") or found is None:
            continue
        report, scanned_at, body = found
        _apply_report(store, None, target, entry, report, url, scanned_at, body)
    return {key: summary[key] for key in ("opened", "carried_forward", "watch_events")}


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
    explicit safe verdict for the matching hash can clear the alert (FR-023). So does a file pinned
    at a revision other than the hub's head commit, because the hub's verdict describes the head
    commit only: one tree request compares the head file's hash with the pinned hash.
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
            confirm = entry["identifier"] in alerted or _off_head(entry, statuses[repo])
            known = verdicts.get((repo, file))
            if known is None or (confirm and known.state == hub.CLEAN and not known.tree_response):
                verdicts[(repo, file)] = security.verdict(statuses[repo], file, confirm=confirm)
    return verdicts


def _off_head(entry: Mapping[str, Any], status: hub.SecurityStatus) -> bool:
    """The hub answered for a commit other than the entry's pinned revision."""
    return status.state == "answered" and entry.get("hub_revision") != status.commit


def _off_head_reason(verdict: hub.FileVerdict) -> str:
    if verdict.in_tree is False:
        return "the file is not at the hub's head commit"
    if verdict.in_tree:
        return "the hub publishes no SHA-256 for the file at its head commit"
    return "the tree at the hub's head commit could not be read"


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
        if (
            verdict.state == hub.CLEAN
            and _off_head(entry, verdict.status)
            and verdict.hub_sha256 != sha256
        ):
            # The clean verdict is for the head commit's file, not the pinned one.
            detail = {
                "scanner": HF_SCAN,
                "verdict": verdict.state,
                "level": verdict.level,
                "scanners": verdict.scanners,
                "hub_repo": verdict.repo,
                "hub_file": verdict.file,
                "hub_commit": verdict.status.commit,
                "pinned_revision": entry.get("hub_revision"),
                "location": _where(entry),
            }
            if verdict.in_tree and verdict.hub_sha256 is not None:
                detail |= {"inventory_sha256": sha256, "hub_sha256": verdict.hub_sha256}
                kind = HASH_MISMATCH
            else:
                detail["reason"] = _off_head_reason(verdict)
                kind = HUB_SCAN_UNKNOWN
            observations = _hub_observations(verdict, detail)
            _watch(store, run_id, target, kind, identifier, detail, observations)
            continue
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
    source = cause.get("source", SOURCE)
    cached = [store.get_advisory(source, advisory_id) for advisory_id in advisory_ids_of(alert)]
    for entry in pinned:
        for advisory in cached:  # every record of an alias group (feature 006)
            if advisory is None:
                return True, entry
            local = evaluate_advisory(
                {"affected": advisory["affected"] or []}, entry["name"], entry["version"]
            )
            if local.affected or not local.evaluated:
                return True, entry  # an unreadable range is not evidence the cause is gone
    return False, pinned[0]


def _file_keys(item: Mapping[str, Any]) -> set[tuple[str, str]]:
    """The hub repository and file, and the location, that name a weight file or a cause."""
    keys: set[tuple[str, str]] = set()
    if item.get("hub_repo") and item.get("hub_file"):
        keys.add(("hub", f"{item['hub_repo']}/{item['hub_file']}"))
    if item.get("location"):
        keys.add(("location", str(item["location"])))
    return keys


def _unpinned_at(
    cause: Mapping[str, Any],
    earlier: Sequence[Mapping[str, Any]],
    entries: Sequence[Mapping[str, Any]],
) -> bool:
    """Whether the new inventory has an unpinned entry for the file the cause was found in.

    The file is named by the cause and by the earlier version's entry with the cause's
    identifier. A gap (the hub was not reachable, say) is not proof the cause is gone.
    """
    wanted = _file_keys(cause)
    for entry in earlier:
        if entry["kind"] == "weight_file" and entry["identifier"] == cause["identifier"]:
            wanted |= _file_keys(entry)
    return any(
        bool(_file_keys(entry) & wanted)
        for entry in entries
        if entry["kind"] == "weight_file" and not entry["pinned"]
    )


def reevaluate_version(store: Store, model_id: str, version: int) -> dict[str, list[int]]:
    """Settle the model's open alerts against a newly registered version (FR-014, SC-004).

    A cause the new inventory no longer has closes its alert as ``fixed`` by that version, with
    the new inventory as evidence; a cause it still has carries the alert forward. Each cause is
    compared at its own identity (the identity and clearance table of 002's data-model.md): a
    disabled or unavailable base model and a disabled hub dataset are states of the repository,
    so a version pinning another revision of it carries the alert to that revision; every other
    cause is its exact file hash, revision or DOI. An unpinned entry (a gap) for the same package,
    weight file, dataset or repository is not proof the cause is gone, so the alert is left as it
    was. Only the two inventories are compared: no source is consulted, so a failed source
    cannot affect it.
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
        elif alert["kind"] in UPSTREAM_ITEM_ALERTS:
            earlier = store.entries(model_id, alert["current_version"])
            repository = _repository_of(cause, earlier)
            if _repository_scoped(alert["kind"], cause) and repository is not None:
                # A state of the whole hub repository: any pinned revision of it still has it.
                same = [entry for entry in entries if _in_repository(entry, repository)]
                if alert["kind"] == PAPER_RETRACTED:
                    # The paper must still be tied to the dataset (any revision of it).
                    paper = cause.get("paper_doi")
                    same = [e for e in same if paper in (e.get("paper_dois") or [])]
                pinned = [entry for entry in same if entry["pinned"]]
                if not pinned and same:
                    continue  # only a gap for the repository: neither fixed nor shown again
                present = bool(pinned)
                if present:
                    cause |= _repinned(alert["kind"], pinned[0])
            else:
                present = _dataset_present(cause, alert["kind"], entries)
                if not present and _gap_for(cause, repository, entries):
                    continue  # only a gap for the same dependency: neither fixed nor shown again
            detail["found"] = cause["identifier"] if present else None
        else:
            entry = weights.get(cause["identifier"])
            present = entry is not None and bool(entry["pinned"])
            if not present and _unpinned_at(
                cause, store.entries(model_id, alert["current_version"]), entries
            ):
                continue  # only an unpinned entry for the file: neither fixed nor shown again
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
PAPER_NOT_FOUND = "paper_not_found"
DATASET_MOVED = "dataset_moved"
UPSTREAM_NOTICE = "upstream_notice"
LICENCE_CHANGED = "licence_changed"
LICENCE_UNRECOGNISED = "licence_unrecognised"
LICENCE_MISSING = "licence_missing"
# Research U9: every US1 alert is HIGH by policy.
DATASET_SEVERITY = "HIGH"
NO_REASON = "no reason given"
# data-model.md, Alert: the base-model kinds (FR-011, FR-012, FR-019).
BASE_MODEL_DISABLED = "base_model_disabled"
BASE_MODEL_UNAVAILABLE = "base_model_unavailable"
BASE_MODEL_REFUSED = "base_model_refused"
BASE_MODEL_UNRECOGNISED = "base_model_unrecognised"
BASE_MODEL_MOVED = "base_model_moved"
BASE_MODEL_NEW_REVISION = "base_model_new_revision"
BASE_MODEL_NEW_VERSION_POINTER = "base_model_new_version_pointer"
GATING_CHANGED = "gating_changed"
CARD_CHANGED = "card_changed"
DATASET_NEW_VERSION = "dataset_new_version"
DATASET_REPLACED = "dataset_replaced"
BASE_MODEL_SEVERITY = {BASE_MODEL_DISABLED: "MODERATE", BASE_MODEL_UNAVAILABLE: "LOW"}
# FR-012: only what is confirmed; without an account a deletion and a move to private look alike.
UNAVAILABLE_STATEMENT = "no longer publicly available (deleted or made private)"

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


def base_model_repo(entry: Mapping[str, Any]) -> str:
    """The base model's repository identity: its purl without a version (data-model.md).

    A disabled or unavailable base model is a state of the whole repository, so its alerts are
    keyed by this and not by the pinned revision (identity and clearance table).
    """
    return huggingface_purl(entry["name"], None)


def hub_dataset_repo(repo: str) -> str:
    """A hub dataset's repository identity: ``hf-dataset:owner/name`` without a revision."""
    return f"{HUB_DATASET_PREFIX}{repo}"


def _hub_scope(entry: Mapping[str, Any]) -> str | None:
    """The hub repository identity a base model's or hub dataset's repository-level observations
    (licence, paper tie) are keyed by (identity table); ``None`` for a DOI dataset."""
    if entry["kind"] == "base_model":
        return base_model_repo(entry)
    if entry.get("hub_repo"):
        return hub_dataset_repo(entry["hub_repo"])
    return None


# Alert kinds whose cause is a state of a whole hub repository (identity and clearance table).
REPOSITORY_ALERTS = (BASE_MODEL_DISABLED, BASE_MODEL_UNAVAILABLE)
# Alert kinds about one upstream item that registering a version settles (identity table).
UPSTREAM_ITEM_ALERTS = (*DATASET_ALERTS, *REPOSITORY_ALERTS, LICENCE_CHANGED)


@dataclass
class _UpstreamRead:
    """Every upstream answer the run needs, read before anything changes (FR-018)."""

    statuses: dict[str, str]
    reads: dict[str, Any]
    sources: tuple[str, ...] = ()
    # doi.org's answers given in this run, by DOI (supporting evidence only, never an alert).
    agency_answers: dict[str, Response] = field(default_factory=dict)
    # Dataset DOIs asked at Zenodo by their own record id, not routed by DataCite (research U4).
    zenodo_by_doi: frozenset[str] = frozenset()


def _licence_fields(licence: str | None) -> dict[str, Any]:
    """An observation's declared licence and its normalised form (research U8)."""
    return {"declared_licence": licence, "licence_form": normalise(licence).form}


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
        if not routing or routing["repository"] != repository:
            continue
        if routing["repository_id"]:
            found[doi] = str(routing["repository_id"])
        elif repository == "zenodo" and (record_id := zenodo.record_id_from_doi(doi)):
            # Routed to Zenodo but the landing URL gave no id: never skip it silently (T061).
            found[doi] = record_id
    return found


def _zenodo_by_doi(store: Store, dois: Sequence[str], records: Mapping[str, Any]) -> dict[str, str]:
    """Zenodo DOIs asked at Zenodo with their own record id (research U1 exception, U4).

    A ``10.5281/zenodo.<digits>`` DOI is asked directly when its agency is unknown (doi.org's
    lookup failed or reports the DOI does not exist) and DataCite has not routed it, or when its
    agency is DataCite and DataCite answered 404. Only Zenodo's answer then decides.
    """
    found = {}
    for doi in dois:
        record_id = zenodo.record_id_from_doi(doi)
        if record_id is None:
            continue
        agency = _agency(store, doi)
        record = records.get(doi)
        missing = record is not None and record.outcome == "not_found"
        if (agency_unknown(agency) and (record is None or missing)) or (
            datacite.queried(agency) and missing
        ):
            found[doi] = record_id
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
    base_models = list(
        dict.fromkeys(
            entry["name"]
            for target in targets
            for entry in target.entries
            if entry["kind"] == "base_model" and entry["pinned"]
        )
    )
    agency_answers: dict[str, Response] = {}
    if any(source in DOI_SOURCES for source in sources):
        # A DOI whose agency lookup failed at registration is looked up again, and one doi.org
        # reported as not existing is asked again once per run (research U1).
        for doi in all_dois:
            answer = refresh_agency(store, fetcher, doi, recheck_unregistered=True)
            if answer is not None and answer.response is not None:
                agency_answers[doi] = answer.response
            elif doi in paper_dois and datacite.queried(_agency(store, doi)):
                # No retraction source reads a DataCite paper DOI, so doi.org's answer in this
                # run is the evidence of the watch event that says so (constitution IV).
                asked = ask_agency(fetcher, doi)
                if asked.response is not None:
                    agency_answers[doi] = asked.response

    def asked_at_datacite(doi: str) -> bool:
        agency = _agency(store, doi)
        unknown_zenodo = agency_unknown(agency) and zenodo.record_id_from_doi(doi) is not None
        return datacite.queried(agency) or unknown_zenodo

    by_doi: dict[str, str] = {}

    def read_zenodo() -> dict[str, zenodo.ZenodoRecord]:
        records = reads.get(DATACITE) if statuses.get(DATACITE) == "ok" else None
        by_doi.update(_zenodo_by_doi(store, dataset_dois, records or {}))
        routed = _routed(store, dataset_dois, "zenodo") | by_doi
        return {doi: zenodo.Zenodo(fetcher).record(rid) for doi, rid in routed.items()}

    readers: dict[str, Callable[[], Any]] = {
        DATACITE: lambda: {
            doi: datacite.DataCite(fetcher).record(doi)
            for doi in dataset_dois
            if asked_at_datacite(doi)
        },
        ZENODO: read_zenodo,
        FIGSHARE: lambda: {
            doi: figshare.Figshare(fetcher).article(rid)
            for doi, rid in _routed(store, dataset_dois, "figshare").items()
        },
        CROSSREF: lambda: {
            doi: crossref.Crossref(fetcher).work(doi)
            for doi in all_dois
            if crossref.queried(_agency(store, doi))
        },
        HF_HUB: lambda: (
            {("dataset", repo): hub.read_dataset(fetcher, repo) for repo in hub_repos}
            | {("model", repo): hub.read_model(fetcher, repo) for repo in base_models}
        ),
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
    return _UpstreamRead(statuses, reads, tuple(sources), agency_answers, frozenset(by_doi))


class _Observed:
    """Observations already stored in this run: one per item per source (data-model.md)."""

    def __init__(self, store: Store, run_id: int) -> None:
        self.store = store
        self.run_id = run_id
        self._seen: dict[tuple[str, str], dict[str, Any]] = {}
        self._agency: dict[str, int] = {}

    def agency(self, read: _UpstreamRead, doi: str) -> list[int]:
        """Evidence of doi.org's answer for ``doi`` in this run, stored once; none if not asked."""
        response = read.agency_answers.get(doi)
        if response is None:
            return []
        if doi not in self._agency:
            self._agency[doi] = self.store.add_response_evidence(
                response, source=DOI_RA, matched_identifier=doi, run_id=self.run_id
            )
        return [self._agency[doi]]

    def of_item(self, item: str) -> list[dict[str, Any]]:
        """The observations of ``item`` stored in this run, in the order they were stored."""
        return [observation for (_, seen), observation in self._seen.items() if seen == item]

    def __call__(self, source: str, item: str, response: Any, **fields: Any) -> dict[str, Any]:
        key = (source, item)
        if key not in self._seen:
            observation = observe(self.store, self.run_id, source, item, response, **fields)
            if observation is None:
                raise ValueError(f"{source} HTTP {response.status} is not an answer")
            self._seen[key] = observation
        return self._seen[key]


def _link_new(store: Store, alert_id: int, evidence_ids: Sequence[int]) -> None:
    """Link evidence an alert does not already hold (same source, URL and body content)."""
    held = {(e["source"], e["url"], content_key(e)) for e in store.alert_evidence(alert_id)}
    for evidence_id in evidence_ids:
        evidence = store.get_evidence(evidence_id)
        if evidence is None:
            continue
        key = (evidence["source"], evidence["url"], content_key(evidence))
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
    severity: str = DATASET_SEVERITY,
    *,
    each: bool = False,
) -> None:
    """Open an upstream alert, or carry the open one forward with any new evidence.

    ``each`` links every evidence id not yet linked, even one whose body equals a linked one: a
    refusal is the same body every time, and each refusal of the run is shown (FR-012).
    """
    existing = store.find_open_alert(target.model_id, cause_key)
    if existing is None:
        alert_id = store.insert_alert(
            model_id=target.model_id,
            kind=kind,
            cause_key=cause_key,
            cause=cause,
            severity=severity,
            severity_origin=POLICY_ORIGIN,
            opened_in_version=target.version,
            evidence_ids=list(dict.fromkeys(evidence_ids)),
        )
        target.summary["opened"].append(alert_id)
        return
    alert_id = existing["alert_id"]
    if each:
        held = {e["evidence_id"] for e in store.alert_evidence(alert_id)}
        for evidence_id in dict.fromkeys(evidence_ids):
            if evidence_id not in held:
                store.link_alert_evidence(alert_id, evidence_id)
    else:
        _link_new(store, alert_id, evidence_ids)
    store.update_open_alert(
        alert_id,
        current_version=max(existing["current_version"], target.version),
        severity=severity,
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
    scope: str | None = None,
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
        # Keyed by the dataset's repository when it is on the hub: the tie is to the dataset,
        # not to one revision of it (identity and clearance table).
        key_item = scope or dataset
        kind, cause_key = PAPER_RETRACTED, dataset_cause_key(PAPER_RETRACTED, key_item, doi)
        cause["paper_doi"] = doi
    notices = [u.as_dict() for u in (*work.retractions, *work.notices)]
    if work.retractions:
        cause["notices"] = notices
        _upstream_alert(store, target, kind, cause_key, cause, [evidence_id])
        return
    existing = store.find_open_alert(target.model_id, cause_key)
    if existing is not None:
        # Research U12: a well-formed answer no longer lists a retraction, withdrawal or removal.
        # That is the source's current state, not a published withdrawal of the notice, so the
        # alert is cleared; ``withdrawn`` is kept for explicit withdrawal evidence (an OSV record).
        _close(store, target, existing, "cleared", [evidence_id])
    if work.notices:
        detail = {"source": CROSSREF, "dataset": dataset, "doi": doi, "notices": notices}
        _upstream_watch(store, target, UPSTREAM_NOTICE, doi, detail, [evidence_id])


NOT_ASKED_REASONS = {
    None: "doi.org could not be asked which agency registered the DOI",
    NOT_REGISTERED: "doi.org reports the DOI does not exist",
}


DATACITE_PAPER_REASON = "registered with DataCite, which no retraction source reads"


def _not_asked_reason(agency: str | None, paper: bool = False) -> str | None:
    """Why no source can be asked about a DOI of this agency, or ``None`` if one can."""
    if agency in NOT_ASKED_REASONS:
        return NOT_ASKED_REASONS[agency]
    if paper and datacite.queried(agency):
        # Retractions are read at Crossref only; DataCite holds no retraction notices (U2).
        return DATACITE_PAPER_REASON
    if datacite.queried(agency) or crossref.queried(agency):
        return None
    return f"registered with {agency}, which no source reads"


def _not_asked(
    store: Store,
    target: _Target,
    observed: _Observed,
    read: _UpstreamRead,
    doi: str,
    dataset: str | None = None,
) -> None:
    """Constitution IV: a DOI no source could be asked about is a watch event naming why."""
    if not any(source in DOI_SOURCES for source in read.sources):
        return
    agency = _agency(store, doi)
    reason = _not_asked_reason(agency, paper=dataset is not None)
    if reason is None:
        return
    by_record_id = zenodo.record_id_from_doi(doi) is not None and agency_unknown(agency)
    if dataset is None and ZENODO in read.sources and by_record_id:
        return  # asked at Zenodo with its own record id (research U4)
    detail: dict[str, Any] = {"source": DOI_RA, "doi": doi, "reason": reason}
    kind = DATASET_UNREACHABLE if dataset is None else PAPER_NOT_FOUND
    if dataset is not None:
        detail["dataset"] = dataset
    _upstream_watch(store, target, kind, doi, detail, observed.agency(read, doi))


def _apply_doi_dataset(
    store: Store,
    target: _Target,
    observed: _Observed,
    read: _UpstreamRead,
    reads: Mapping[str, Any],
    entry: Mapping[str, Any],
) -> None:
    doi = entry["identifier"]
    base = {"identifier": doi, "dataset": doi}
    record = (reads.get(DATACITE) or {}).get(doi)
    supporting: list[int] = []
    if record is not None:
        fields = _licence_fields(record.licence) if record.outcome == "reachable" else {}
        if record.newer:
            fields["head_revision"] = record.newer[0]
        observation = observed(DATACITE, doi, record.response, **fields)
        evidence_id = observation["evidence_ref"]
        supporting.append(evidence_id)
        if record.outcome == "reachable":
            _dataset_versions(store, target, observed, doi, observation, record.replaced_by)
        # FR-006: a DataCite 404 alerts only for a DOI DataCite registered; for a DOI whose agency
        # is unknown it is supporting evidence only.
        if record.outcome == "not_found" and datacite.queried(_agency(store, doi)):
            cause = base | {"doi": doi, "source": DATACITE, "http_status": record.response.status}
            key = dataset_cause_key(DATASET_NOT_FINDABLE, doi)
            _upstream_alert(store, target, DATASET_NOT_FINDABLE, key, cause, [evidence_id])
    removal = (reads.get(ZENODO) or {}).get(doi)
    if removal is not None:
        fields = _licence_fields(removal.licence) if removal.outcome == "reachable" else {}
        if removal.newer:
            fields["head_revision"] = removal.newer
        observation = observed(ZENODO, doi, removal.response, removal=removal.removal, **fields)
        evidence_id = observation["evidence_ref"]
        if removal.outcome == "reachable":
            latest = removal.newer_response
            _dataset_versions(
                store, target, observed, doi, observation, latest=latest, record=removal
            )
        # Asked by its own record id: doi.org's and DataCite's answers support Zenodo's.
        support = supporting + observed.agency(read, doi) if doi in read.zenodo_by_doi else []
        if removal.outcome == "removed":
            tombstone = removal.removal or {}
            cause = base | {
                "host": "zenodo",
                "record_id": removal.record_id,
                "removal_date": tombstone.get("removal_date"),
                "reason": tombstone.get("removal_reason") or NO_REASON,
            }
            key = dataset_cause_key(DATASET_REMOVED, doi)
            _upstream_alert(store, target, DATASET_REMOVED, key, cause, [evidence_id, *support])
        elif removal.outcome == "not_found":
            detail = {"source": ZENODO, "http_status": 404, "record_id": removal.record_id}
            evidence = [evidence_id, *support]
            _upstream_watch(store, target, DATASET_UNREACHABLE, doi, detail, evidence)
    article = (reads.get(FIGSHARE) or {}).get(doi)
    if article is not None:
        fields = _licence_fields(article.licence) if article.outcome == "reachable" else {}
        evidence_id = observed(FIGSHARE, doi, article.response, **fields)["evidence_ref"]
        kind = article.not_found_kind()
        if kind is not None:
            detail = {"source": FIGSHARE, "http_status": 404, "article_id": article.article_id}
            _upstream_watch(store, target, kind, doi, detail, [evidence_id])
    works = reads.get(CROSSREF) or {}
    if doi in works:
        _apply_crossref(store, target, observed, doi, doi, "dataset", works[doi])
    _not_asked(store, target, observed, read, doi)


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
    dataset = (reads.get(HF_HUB) or {}).get(("dataset", repo))
    if dataset is None:
        return
    observation = observed(
        HF_HUB,
        item,
        dataset.response,
        disabled=dataset.disabled,
        gated=dataset.gated,
        head_revision=dataset.sha,
        **(_licence_fields(dataset.licence) if dataset.outcome == "reachable" else {}),
    )
    evidence_id = observation["evidence_ref"]
    status = dataset.response.status
    evidence = [evidence_id]
    moved: dict[str, Any] = {}
    if dataset.outcome == "redirected":
        detail = {"source": HF_HUB, "http_status": status, "from": repo, "to": dataset.moved_to}
        detail["redirected_to"] = dataset.response.redirected_to
        answer = dataset.target
        if answer is None:
            detail["target_error"] = dataset.target_error
        else:
            # FR-005: the target is read once; its answer is evidence of the move.
            evidence.append(_target_evidence(store, observed, item, answer.response))
            detail |= _target_detail(answer)
        _upstream_watch(store, target, DATASET_MOVED, item, detail, evidence)
        if answer is None or answer.outcome != "reachable" or not answer.disabled:
            return
        # A move to a disabled repository is a removal of the pinned repository (FR-005).
        moved = {"moved_to": dataset.moved_to}
    elif dataset.outcome == "refused":
        detail = {"source": HF_HUB, "http_status": status}
        _upstream_watch(store, target, DATASET_UNREACHABLE, item, detail, [evidence_id])
        return
    elif not dataset.disabled:
        return
    key = dataset_cause_key(DATASET_REMOVED, hub_dataset_repo(repo))
    cause: dict[str, Any] = {
        "identifier": item,
        "dataset": item,
        "repo": repo,
        "host": "huggingface",
        "disabled": True,
        "notice_date": None,
        "reason": NO_REASON,
    } | moved
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
    _upstream_alert(store, target, DATASET_REMOVED, key, cause, [*evidence, *notice_evidence])


def _target_evidence(store: Store, observed: _Observed, item: str, response: Response) -> int:
    """A redirect target's answer, stored as evidence for the pinned item (no observation)."""
    return store.add_response_evidence(
        response, source=HF_HUB, matched_identifier=item, run_id=observed.run_id
    )


def _target_detail(answer: Any) -> dict[str, Any]:
    """What a redirect target answered, for the move's watch event."""
    detail: dict[str, Any] = {
        "target_http_status": answer.response.status,
        "target_outcome": answer.outcome,
    }
    if answer.outcome == "reachable":
        detail["target_disabled"] = answer.disabled
    return detail


def _apply_base_model(
    store: Store,
    target: _Target,
    observed: _Observed,
    reads: Mapping[str, Any],
    entry: Mapping[str, Any],
) -> None:
    """The base model on the hub: disabled, refused or reachable (research U7; FR-011 to FR-013)."""
    model = (reads.get(HF_HUB) or {}).get(("model", entry["name"]))
    if model is None:
        return
    if model.outcome == "redirected":
        _apply_moved_base_model(store, target, observed, entry, model)
        return
    item = entry["identifier"]
    reachable = model.outcome == "reachable"
    fields = _licence_fields(model.licence) if reachable else {}
    if reachable:
        fields |= {"card_hash": model.card_hash, "new_version_pointer": model.new_version}
    observation = observed(
        HF_HUB,
        item,
        model.response,
        disabled=model.disabled,
        gated=model.gated,
        head_revision=model.sha,
        **fields,
    )
    evidence = [observation["evidence_ref"]]
    base: dict[str, Any] = {"identifier": item, "base_model": item, "repo": entry["name"]}
    if model.outcome == "refused":
        _apply_refusal(store, target, entry, base, observation)
        return
    # Any answer that is not a refusal, from any run, ends the run of refusals (research U7).
    unavailable = store.find_open_alert(
        target.model_id, dataset_cause_key(BASE_MODEL_UNAVAILABLE, base_model_repo(entry))
    )
    if unavailable is not None:
        _close(store, target, unavailable, "cleared", evidence)
    if not reachable:
        return
    _disabled_state(store, target, entry, base, model, evidence)
    _base_model_events(store, target, entry, observation)


def _disabled_state(
    store: Store,
    target: _Target,
    entry: Mapping[str, Any],
    base: Mapping[str, Any],
    model: hub.HubModel,
    evidence: list[int],
) -> None:
    """A reachable answer's ``disabled``: an alert, its clearance or the U7 fail-safe event."""
    item = entry["identifier"]
    key = dataset_cause_key(BASE_MODEL_DISABLED, base_model_repo(entry))
    if model.unrecognised is not None:
        # U7's fail-safe: not the recorded shape of a disabled model, so no alert.
        detail = {"source": HF_HUB, "http_status": model.response.status}
        detail |= {"disabled": _disabled_value(model.response), "reason": model.unrecognised}
        _upstream_watch(store, target, BASE_MODEL_UNRECOGNISED, item, detail, evidence)
    elif model.disabled:
        cause = dict(base) | {"disabled": True, "source": HF_HUB}
        severity = BASE_MODEL_SEVERITY[BASE_MODEL_DISABLED]
        _upstream_alert(store, target, BASE_MODEL_DISABLED, key, cause, evidence, severity)
    elif model.disabled is False:
        # The hub reports the model enabled again: the cause is gone (constitution 1.0.2).
        disabled = store.find_open_alert(target.model_id, key)
        if disabled is not None:
            _close(store, target, disabled, "cleared", evidence)


def _apply_moved_base_model(
    store: Store,
    target: _Target,
    observed: _Observed,
    entry: Mapping[str, Any],
    model: hub.HubModel,
) -> None:
    """A renamed base model: the hub redirects the pinned name (held-out scoring HO-097).

    A ``base_model_moved`` watch event names the target. The target's answer, read once, decides
    the rest, keyed by the pinned repository so a re-pin to the new name carries an alert forward:
    disabled opens ``base_model_disabled``; a refusal counts towards the refusal-span rule; any
    other reachable answer ends a refusal run and clears as a reachable answer does. A redirect
    whose target cannot be read writes no observation, so it opens, closes and ends nothing.
    """
    item = entry["identifier"]
    detail: dict[str, Any] = {
        "source": HF_HUB,
        "http_status": model.response.status,
        "from": entry["name"],
        "to": model.moved_to,
        "redirected_to": model.response.redirected_to,
    }
    answer = model.target
    if answer is None:
        detail["target_error"] = model.target_error
        evidence = [_target_evidence(store, observed, item, model.response)]
        _upstream_watch(store, target, BASE_MODEL_MOVED, item, detail, evidence)
        return
    refused = answer.outcome == "refused"
    observation = observed(HF_HUB, item, model.response, outcome="refused" if refused else None)
    evidence = [observation["evidence_ref"]]
    evidence.append(_target_evidence(store, observed, item, answer.response))
    detail |= _target_detail(answer)
    _upstream_watch(store, target, BASE_MODEL_MOVED, item, detail, evidence)
    base = {"identifier": item, "base_model": item, "repo": entry["name"]}
    base["moved_to"] = model.moved_to
    if refused:
        _apply_refusal(store, target, entry, base, observation, evidence[1:])
        return
    unavailable = store.find_open_alert(
        target.model_id, dataset_cause_key(BASE_MODEL_UNAVAILABLE, base_model_repo(entry))
    )
    if unavailable is not None:
        _close(store, target, unavailable, "cleared", evidence)
    _disabled_state(store, target, entry, base, answer, evidence)


def _base_model_events(
    store: Store, target: _Target, entry: Mapping[str, Any], observation: Mapping[str, Any]
) -> None:
    """Watch events, never alerts, for what changed on the hub (FR-013, research U7)."""
    item = entry["identifier"]
    previous = previous_answer(store, observation)
    evidence = [observation["evidence_ref"]]
    source = {"source": HF_HUB}
    newest = observation["head_revision"]
    pinned = entry.get("version")
    if newest and newest != pinned and appeared(previous, observation, "head_revision"):
        detail = source | {"pinned": pinned, "newest": newest}
        _upstream_watch(store, target, BASE_MODEL_NEW_REVISION, item, detail, evidence)
    if appeared(previous, observation, "new_version_pointer"):
        detail = source | {"new_version": observation["new_version_pointer"]}
        if previous is not None:
            detail["previous"] = previous.get("new_version_pointer")
        _upstream_watch(store, target, BASE_MODEL_NEW_VERSION_POINTER, item, detail, evidence)
    if previous is not None and changed(previous, observation, "gated"):
        detail = source | {"from": previous["gated"], "to": observation["gated"]}
        _upstream_watch(store, target, GATING_CHANGED, item, detail, evidence)
    if previous is not None and changed(previous, observation, "card_hash"):
        detail = source | {
            "previous_card_hash": previous["card_hash"],
            "card_hash": observation["card_hash"],
        }
        _upstream_watch(store, target, CARD_CHANGED, item, detail, evidence)


def _recorded(store: Store, target: _Target, kind: str, item: str) -> dict[str, Any] | None:
    """This version's watch event of ``kind`` for ``item``, if one is recorded."""
    for event in store.watch_events(target.model_id, target.version):
        if event["kind"] == kind and event["entry_identifier"] == item:
            return event
    return None


def _dataset_versions(
    store: Store,
    target: _Target,
    observed: _Observed,
    doi: str,
    observation: Mapping[str, Any],
    replaced_by: Sequence[str] = (),
    latest: Response | None = None,
    record: zenodo.ZenodoRecord | None = None,
) -> None:
    """FR-007: a newer version or a replacing record is a watch event naming it, never an alert.

    For a Zenodo record, the event also shows the newer version's declared licence, as declared
    and normalised (``record``); it is shown, never compared, so it raises nothing (FR-007).
    """
    evidence = [observation["evidence_ref"]]
    source = observation["source"]
    if appeared(previous_answer(store, observation), observation, "head_revision"):
        newer = observation["head_revision"]
        detail = {"source": source, "dataset": doi, "newer": newer}
        if latest is not None:
            detail["newer_url"] = latest.redirected_to or latest.url
            evidence.append(
                store.add_response_evidence(
                    latest, source=source, matched_identifier=doi, run_id=observed.run_id
                )
            )
        if record is not None and record.newer_licence_response is not None:
            licence = normalise(record.newer_licence)
            detail |= {
                "newer_declared_licence": record.newer_licence,
                "newer_licence": licence.normalised,
                "newer_licence_form": licence.form,
            }
            if record.newer_licence_response is not latest:
                evidence.append(
                    store.add_response_evidence(
                        record.newer_licence_response,
                        source=source,
                        matched_identifier=doi,
                        run_id=observed.run_id,
                    )
                )
        elif record is not None and record.newer_licence_error:
            detail["newer_licence_error"] = record.newer_licence_error
        _upstream_watch(store, target, DATASET_NEW_VERSION, doi, detail, evidence)
    if replaced_by:
        before = _recorded(store, target, DATASET_REPLACED, doi)
        if before is None or before["detail"].get("replaced_by") != replaced_by[0]:
            detail = {"source": source, "dataset": doi, "replaced_by": replaced_by[0]}
            if len(replaced_by) > 1:
                detail["also_replaced_by"] = list(replaced_by[1:])
            _upstream_watch(store, target, DATASET_REPLACED, doi, detail, evidence[:1])


def _disabled_value(response: Response) -> Any:
    try:
        return json.loads(response.body).get("disabled")
    except (ValueError, AttributeError):
        return None


def _apply_refusal(
    store: Store,
    target: _Target,
    entry: Mapping[str, Any],
    base: Mapping[str, Any],
    observation: Mapping[str, Any],
    target_evidence: Sequence[int] = (),
) -> None:
    """The refusal-span rule (research U7, FR-012): an alert, or a ``base_model_refused`` event.

    ``target_evidence`` is this run's answer of a renamed base model's target, which the hub
    refused; the observation is then the redirect, recorded as ``refused``.
    """
    item = entry["identifier"]
    run = refusal_run(store.observations(item, HF_HUB))
    key = dataset_cause_key(BASE_MODEL_UNAVAILABLE, base_model_repo(entry))
    if run.counted and run.qualifies:
        refusals = [
            {
                "run_id": refusal["run_id"],
                "observed_at": refusal["observed_at"],
                "http_status": refusal["http_status"],
            }
            | ({"redirected_to": refusal["redirected_to"]} if refusal.get("redirected_to") else {})
            for refusal in run.refusals
        ]
        cause = dict(base) | {
            "statement": UNAVAILABLE_STATEMENT,
            "source": HF_HUB,
            "refusals": refusals,
            "first_refused_at": refusals[0]["observed_at"],
            "latest_refused_at": refusals[-1]["observed_at"],
        }
        evidence = [refusal["evidence_ref"] for refusal in run.refusals]
        evidence.extend(target_evidence)
        severity = BASE_MODEL_SEVERITY[BASE_MODEL_UNAVAILABLE]
        _upstream_alert(
            store, target, BASE_MODEL_UNAVAILABLE, key, cause, evidence, severity, each=True
        )
        return
    if store.find_open_alert(target.model_id, key) is not None:
        return  # an on-demand refusal changes nothing (it neither counts nor breaks the run)
    detail = {
        "source": HF_HUB,
        "http_status": observation["http_status"],
        "trigger": observation["trigger"],
        "observed_at": observation["observed_at"],
        "scheduled_refusals_in_run": len(run.refusals),
        "first_refused_at": run.refusals[0]["observed_at"] if run.refusals else None,
    }
    if observation.get("redirected_to"):
        detail["redirected_to"] = observation["redirected_to"]
    evidence = [observation["evidence_ref"], *target_evidence]
    _upstream_watch(store, target, BASE_MODEL_REFUSED, item, detail, evidence)


def _apply_licence(
    store: Store, target: _Target, observed: _Observed, entry: Mapping[str, Any]
) -> None:
    """Compare this run's declared licences of one item with its reference (FR-009, FR-010).

    The reference is the recorded licence, or the first stored observation that declared one
    (the baseline). One alert per item: a further change updates it. The alert's cause names each
    source that reports the change (``sources``); a source drops out only when it answers in a run
    with the reference again, and the alert closes as ``cleared`` once none is left (FR-018,
    research U8, U12). A source that failed or was not asked in the run keeps its report, whatever
    the other sources say.
    """
    item = entry["identifier"]
    seen = [o for o in observed.of_item(item) if o["source"] in LICENCE_SOURCES]
    seen = [o for o in seen if o["outcome"] == "reachable"]
    scope = _hub_scope(entry)
    reference = licence_reference(store, entry, scope) if seen else None
    if reference is None:
        return
    declared_any = any(o["declared_licence"] for o in seen)
    changed: list[dict[str, Any]] = []
    same: list[dict[str, Any]] = []
    for observation in seen:
        finding = compare_licence(reference, observation)
        detail = {
            "source": observation["source"],
            "declared_licence": observation["declared_licence"],
            "recorded_licence": reference.licence.normalised,
            "recorded_from": reference.origin,
        }
        evidence = [observation["evidence_ref"]]
        if finding == "missing":
            # "No longer declares": the source declared one before, or, seen for the first time,
            # no source in this run declares one.
            before = store.previous_observation(
                item, observation["source"], observation["observation_id"]
            )
            if (before is not None and before["declared_licence"]) or (
                before is None and not declared_any
            ):
                _upstream_watch(store, target, LICENCE_MISSING, item, detail, evidence)
        elif finding == "unrecognised":
            _upstream_watch(store, target, LICENCE_UNRECOGNISED, item, detail, evidence)
        elif finding == "changed":
            changed.append(observation)
        elif finding == "same":
            same.append(observation)
    key = dataset_cause_key(LICENCE_CHANGED, scope or item)
    existing = store.find_open_alert(target.model_id, key)
    returned = {o["source"] for o in same}
    reporting = [s for s in _reporting_sources(existing) if s not in returned]
    reporting = list(dict.fromkeys(reporting + [o["source"] for o in changed]))
    if changed:
        latest = changed[-1]
        cause = {
            "identifier": item,
            "item": item,
            "recorded_licence": reference.licence.normalised,
            "recorded_from": reference.origin,
            "declared_licence": latest["declared_licence"],
            "declared_normalised": normalise(latest["declared_licence"]).normalised,
            "source": latest["source"],
            "sources": reporting,
        }
        evidence_ids = [o["evidence_ref"] for o in changed]
        _upstream_alert(store, target, LICENCE_CHANGED, key, cause, evidence_ids)
        return
    if existing is None or not same:
        return
    evidence_ids = [o["evidence_ref"] for o in same]
    if not reporting:
        _close(store, target, existing, "cleared", evidence_ids)
        return
    if reporting != _reporting_sources(existing):
        # Some reporting sources answered with the reference again; the others still report it.
        cause = dict(existing["cause"]) | {"sources": reporting, "source": reporting[-1]}
        _link_new(store, existing["alert_id"], evidence_ids)
        store.update_open_alert(
            existing["alert_id"],
            current_version=max(existing["current_version"], target.version),
            severity=existing["severity"],
            severity_origin=existing["severity_origin"],
            cause=cause,
        )
        if existing["alert_id"] not in target.summary["carried_forward"]:
            target.summary["carried_forward"].append(existing["alert_id"])


def _reporting_sources(alert: Mapping[str, Any] | None) -> list[str]:
    """The sources an open licence alert says report the change (an alert written before causes
    listed them names only its latest one, ``source``)."""
    if alert is None:
        return []
    cause = alert["cause"]
    listed = cause.get("sources")
    if isinstance(listed, list) and listed:
        return [str(source) for source in listed]
    return [str(cause["source"])] if cause.get("source") else []


def _apply_upstream(
    store: Store, target: _Target, observed: _Observed, read: _UpstreamRead
) -> None:
    reads = {source: read.reads[source] for source in read.reads if read.statuses[source] == "ok"}
    for entry in target.entries:
        if entry["kind"] == "base_model" and entry["pinned"]:
            _apply_base_model(store, target, observed, reads, entry)
            _apply_licence(store, target, observed, entry)
            continue
        if entry["kind"] != "dataset" or not entry["pinned"]:
            continue
        if entry.get("hub_repo"):
            _apply_hub_dataset(store, target, observed, reads, entry)
        else:
            _apply_doi_dataset(store, target, observed, read, reads, entry)
        _apply_licence(store, target, observed, entry)
        # Papers the owner ties to the dataset, whether it has a DOI or lives on the hub (FR-004).
        works = reads.get(CROSSREF) or {}
        dataset = entry["identifier"]
        for paper in entry.get("paper_dois") or []:
            if paper in works:
                _apply_crossref(
                    store,
                    target,
                    observed,
                    dataset,
                    paper,
                    "paper",
                    works[paper],
                    scope=_hub_scope(entry),
                )
            _not_asked(store, target, observed, read, paper, dataset)


def _dataset_present(
    cause: Mapping[str, Any], kind: str, entries: Sequence[Mapping[str, Any]]
) -> bool:
    """Whether a new inventory still pins the alert's exact item (and, for a paper, its tie).

    The item is a dataset DOI or hub dataset revision, or for a licence alert also a base model
    revision. A gap is not a pin: the caller decides what a gap for the same dependency means.
    """
    for entry in entries:
        if entry["kind"] not in ("dataset", "base_model") or not entry["pinned"]:
            continue
        if entry["identifier"] != cause["identifier"]:
            continue
        if kind != PAPER_RETRACTED or cause.get("paper_doi") in (entry.get("paper_dois") or []):
            return True
    return False


def _repository_scoped(kind: str, cause: Mapping[str, Any]) -> bool:
    """Whether the cause is a state or observation of a whole hub repository (identity and
    clearance table): a disabled or unavailable base model, a disabled hub dataset, a licence
    read from a base model's or hub dataset's info, or a paper tied to a hub dataset."""
    identifier = str(cause.get("identifier") or "")
    on_hub = identifier.startswith((HUB_DATASET_PREFIX, "pkg:huggingface/"))
    return (
        kind in REPOSITORY_ALERTS
        or (kind == DATASET_REMOVED and cause.get("host") == "huggingface")
        or (kind == LICENCE_CHANGED and on_hub)
        or (kind == PAPER_RETRACTED and identifier.startswith(HUB_DATASET_PREFIX))
    )


def _repository_of(
    cause: Mapping[str, Any], earlier: Sequence[Mapping[str, Any]]
) -> tuple[str, str] | None:
    """The hub repository the cause's item is in, as (entry kind, owner/name), if it is in one.

    Read from the earlier version's entry for the item, else from the cause itself (an alert
    written before causes named their repository).
    """
    for entry in earlier:
        if entry.get("identifier") != cause["identifier"]:
            continue
        if entry["kind"] == "base_model" and entry.get("name"):
            return ("base_model", entry["name"])
        if entry["kind"] == "dataset" and entry.get("hub_repo"):
            return ("dataset", entry["hub_repo"])
    identifier = str(cause["identifier"])
    if identifier.startswith(HUB_DATASET_PREFIX):
        return ("dataset", identifier.removeprefix(HUB_DATASET_PREFIX).rsplit("@", 1)[0])
    if cause.get("repo") and identifier.startswith("pkg:huggingface/"):
        return ("base_model", str(cause["repo"]))
    if identifier.startswith("pkg:huggingface/"):
        return (
            "base_model",
            unquote(identifier.removeprefix("pkg:huggingface/").rsplit("@", 1)[0]),
        )
    return None


def _in_repository(entry: Mapping[str, Any], repository: tuple[str, str]) -> bool:
    kind, repo = repository
    if entry["kind"] != kind:
        return False
    return entry.get("name" if kind == "base_model" else "hub_repo") == repo


def _gap_for(
    cause: Mapping[str, Any],
    repository: tuple[str, str] | None,
    entries: Sequence[Mapping[str, Any]],
) -> bool:
    """Whether the new inventory names the cause's dependency only in a gap (FR-016 of 001):
    an unpinned entry with the same identifier, or in the same hub repository."""
    for entry in entries:
        if entry["pinned"] or entry["kind"] not in ("dataset", "base_model"):
            continue
        if entry.get("identifier") and entry["identifier"] == cause["identifier"]:
            return True
        if repository is not None and _in_repository(entry, repository):
            return True
    return False


def _repinned(kind: str, entry: Mapping[str, Any]) -> dict[str, Any]:
    """What a repository-wide cause shows of the revision the new version pins."""
    item = entry["identifier"]
    if kind == LICENCE_CHANGED:
        repo = entry["name"] if entry["kind"] == "base_model" else entry["hub_repo"]
        return {"identifier": item, "item": item, "repo": repo}
    if kind in REPOSITORY_ALERTS:
        return {"identifier": item, "base_model": item, "repo": entry["name"]}
    return {"identifier": item, "dataset": item, "repo": entry["hub_repo"]}

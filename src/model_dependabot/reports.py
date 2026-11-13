"""Per-model views: alerts by severity, watch events apart and the closed history (US5).

FR-018: per model, open alerts by severity (``CRITICAL``, ``HIGH``, ``MODERATE``, ``LOW``,
``UNKNOWN``; the older alert first within a severity), the watch events of the current version as
a separate list and the closed history with how each alert ended (``fixed``, ``dismissed``,
``withdrawn`` or ``cleared``), oldest closure first. FR-019 and SC-003: every item carries its
evidence (source, retrieval time and the exact identifier matched), so the evidence is in the view
itself and ``alert show`` is one step away. The payloads are the ``--json`` output of ``alerts``
and ``history`` (contracts/cli.md); the text functions render the same payloads for people.

Reading only: nothing here writes to the store.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from model_dependabot.assurance.trust import (
    CODE_FREE,
    IDENTITY,
    LEGACY,
    latest_check,
    needs_confirmation,
)
from model_dependabot.matching.severity import severity_rank
from model_dependabot.rules import rule_for
from model_dependabot.store import SCOPE_ALL as SCOPE_ALL  # moved to the store (feature 003)
from model_dependabot.store import Store

CLOSED_STATES = ("fixed", "dismissed", "withdrawn", "cleared")
EVIDENCE_FIELDS = (
    "source",
    "url",
    "retrieved_at",
    "matched_identifier",
    "original_sha256",
    "body_sha256",
    "canonical_sha256",
    "redacted_fields",
    "detail",
)
STATE_FILTERS: dict[str, tuple[str, ...] | None] = {
    "open": ("open",),
    "excepted": ("open",),  # an excepted alert is stored open (feature 004, research S4)
    "closed": CLOSED_STATES,
    "all": None,
}
EXCEPTED = "excepted"


def is_excepted(alert: Mapping[str, Any]) -> bool:
    """Stored open with ``excepted_at`` set: every global that raised it is excepted (S4)."""
    return alert["state"] == "open" and bool(alert.get("excepted_at"))


def view_state(alert: Mapping[str, Any]) -> str:
    """``excepted`` when stored open and excepted; otherwise the stored state (data-model.md)."""
    return EXCEPTED if is_excepted(alert) else str(alert["state"])


def evidence_view(evidence: Mapping[str, Any]) -> dict[str, Any]:
    return {key: evidence[key] for key in EVIDENCE_FIELDS}


def alert_view(store: Store, alert: Mapping[str, Any]) -> dict[str, Any]:
    rule = rule_for(alert["kind"])
    return {
        "alert_id": alert["alert_id"],
        "rule_id": rule.rule_id,
        "rule_doc": rule.page,
        "kind": alert["kind"],
        "state": view_state(alert),
        "severity": alert["severity"],
        "severity_origin": alert["severity_origin"],
        "cause": alert["cause"],
        "opened_in_version": alert["opened_in_version"],
        "current_version": alert["current_version"],
        "opened_at": alert["opened_at"],
        "closed_at": alert["closed_at"],
        "closed_by_version": alert["closed_by_version"],
        "dismissal_reason": alert["dismissal_reason"],
        "dismissed_by": alert["dismissed_by"],
        "note": alert["note"],
        "evidence": [evidence_view(e) for e in store.alert_evidence(alert["alert_id"])],
    }


def watch_view(event: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "kind": event["kind"],
        "version": event["version"],
        "identifier": event["entry_identifier"],
        "detail": event["detail"],
        "first_seen": event["first_seen"],
        "last_seen": event["last_seen"],
        "evidence": [evidence_view(e) for e in event["evidence"]],
    }


def history_view(store: Store, alert: Mapping[str, Any]) -> dict[str, Any]:
    rule = rule_for(alert["kind"])
    return {
        "alert_id": alert["alert_id"],
        "rule_id": rule.rule_id,
        "rule_doc": rule.page,
        "kind": alert["kind"],
        "outcome": alert["state"],
        "severity": alert["severity"],
        "cause": alert["cause"],
        "opened_in_version": alert["opened_in_version"],
        "closed_at": alert["closed_at"],
        "closed_by_version": alert["closed_by_version"],
        "dismissal_reason": alert["dismissal_reason"],
        "dismissed_by": alert["dismissed_by"],
        "note": alert["note"],
        "evidence": [evidence_view(e) for e in store.alert_evidence(alert["alert_id"])],
    }


def by_severity(alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Most severe first; within a severity, the older alert first."""
    return sorted(alerts, key=lambda alert: (severity_rank(alert["severity"]), alert["alert_id"]))


def alerts_report(store: Store, model_id: str, *, state: str = "open") -> dict[str, Any]:
    """The ``alerts`` payload: alerts in ``state`` by severity, the excepted ones in their own
    list (feature 004: ``alerts`` never holds an excepted alert), then the watch events."""
    if state not in STATE_FILTERS:
        raise ValueError(f"state must be one of {', '.join(STATE_FILTERS)}, got {state!r}")
    version = store.latest_version(model_id)
    listed = by_severity(store.alerts_for(model_id, STATE_FILTERS[state]))
    excepted = [alert for alert in listed if is_excepted(alert)]
    others = [] if state == EXCEPTED else [alert for alert in listed if not is_excepted(alert)]
    events = [] if version is None else store.watch_events(model_id, version)
    run = store.latest_check_run([model_id, SCOPE_ALL])
    return {
        "model_id": model_id,
        "current_version": version,
        "alerts": [alert_view(store, alert) for alert in others],
        "excepted": [alert_view(store, alert) for alert in excepted],
        "watch_events": [watch_view(event) for event in events],
        "last_check": None if run is None else _last_check(run),
    }


def _last_check(run: Mapping[str, Any]) -> dict[str, Any]:
    """The latest run: its id, whether it was ``scheduled`` or ``on_demand``, and each source."""
    return {"run_id": run["run_id"], "trigger": run["trigger"], "sources": run["sources"]}


def history_report(store: Store, model_id: str) -> dict[str, Any]:
    """The ``history`` payload: closed alerts with how and when they closed, oldest first."""
    closed = sorted(
        store.alerts_for(model_id, CLOSED_STATES),
        key=lambda alert: (alert["closed_at"] or "", alert["alert_id"]),
    )
    return {
        "model_id": model_id,
        "current_version": store.latest_version(model_id),
        "history": [history_view(store, alert) for alert in closed],
    }


# --- text ---------------------------------------------------------------------------------------


def _cause_text(kind: str, cause: Mapping[str, Any]) -> str:
    if kind == "package_advisory":
        fixed = ", ".join(cause.get("fixed") or []) or "none published"
        others = [i for i in cause.get("advisory_ids") or [] if i != cause["advisory_id"]]
        also = f" (also {', '.join(others)})" if others else ""
        package = f"{cause['package']}=={cause['version']}"
        return f"{cause['advisory_id']}{also} {package} (fixed: {fixed})"
    if cause.get("location") is not None:
        text = f"{kind} {cause['location']} ({cause.get('identifier')})"
        if kind == "format_policy" and cause.get("rule"):
            # Feature 003 (FR-005): say the alert follows the trust rule and name the claims.
            claims = "; ".join(
                f"{claim.get('location') or claim['identifier']} {claim['outcome']}"
                f" (origin {claim['origin']})"
                for claim in cause.get("unconfirmed_claims") or []
            )
            text += f"; {cause['rule']}: {claims}"
        return text
    # The upstream kinds (feature 002) name a base model or dataset, not a file.
    text = f"{kind} {cause.get('identifier')}"
    if kind == "licence_changed":
        recorded = _one_line(cause.get("recorded_licence"))
        declared = _one_line(cause.get("declared_normalised") or cause.get("declared_licence"))
        text += f": {recorded} -> {declared}"
    if cause.get("paper_doi"):
        text += f" (paper {cause['paper_doi']})"
    return text


def claim_note(
    entry: Mapping[str, Any], origin: str | None, checks: list[dict[str, Any]]
) -> str | None:
    """How far a weight file's code-free claim is established, for people (US1 scenario 2).

    ``None`` when the claim is the owner's or the file is not claimed code-free.
    """
    if entry.get("kind") != "weight_file" or entry.get("can_run_code") is not False:
        return None
    if not entry.get("pinned") or not needs_confirmation(entry, origin):
        return None
    source = entry.get("format_origin") or origin or LEGACY
    latest = latest_check(checks, entry.get("identifier"), CODE_FREE)
    identity = latest_check(checks, entry.get("identifier"), IDENTITY)
    if identity is not None and identity["outcome"] == "contradicted":
        return f"identity contradicted (origin {source}): {identity['reason']}"
    if latest is None or latest["outcome"] == "unreadable":
        return f"code-free claimed, unverified (origin {source})"
    if latest["outcome"] == "contradicted":
        return f"code-free claim contradicted (origin {source}): {latest['reason']}"
    return f"code-free claim confirmed (origin {source})"


def _one_line(licence: object) -> str:
    """A licence set, one entry per line when stored, on one line for text output."""
    return ", ".join(str(licence).splitlines()) if licence else "none"


def evidence_line(evidence: Mapping[str, Any]) -> str:
    line = (
        f"{evidence['source']} {evidence['url']} at {evidence['retrieved_at']}"
        f" for {evidence['matched_identifier']} (sha256 {evidence['body_sha256']})"
    )
    redacted = evidence.get("redacted_fields") or []
    if redacted:
        # Research U10: the stored body is the redacted copy; the received one is checkable too.
        line += f" original sha256 {evidence['original_sha256']}, redacted: {', '.join(redacted)}"
    return line


def alert_line(alert: Mapping[str, Any]) -> str:
    rule_id = alert.get("rule_id") or rule_for(alert["kind"]).rule_id
    head = f"  #{alert['alert_id']} {rule_id} {alert['severity']:<8} {alert['state']:<9}"
    return f"{head} {_cause_text(alert['kind'], alert['cause'])}"


def alerts_text(payload: Mapping[str, Any]) -> str:
    lines = [f"{payload['model_id']} v{payload['current_version']}"]
    lines.append(f"Alerts ({len(payload['alerts'])}):")
    for alert in payload["alerts"]:
        lines.append(alert_line(alert))
        if alert["evidence"]:
            lines.append(f"      evidence: {evidence_line(alert['evidence'][-1])}")
    excepted = payload.get("excepted") or []
    if excepted:
        lines.append(f"Excepted ({len(excepted)}):")
        for alert in excepted:
            lines.append(alert_line(alert))
            for item in alert["cause"].get("excepted") or []:
                lines.append(
                    f"      excepted: {item['global']} by exception {item['exception_id']}"
                    f" ({item['accepted_by']}, {item['recorded_at']})"
                )
    lines.append(f"Watch events ({len(payload['watch_events'])}):")
    for event in payload["watch_events"]:
        lines.append(f"  {event['kind']} {event['identifier']}")
        if event["evidence"]:
            lines.append(f"      evidence: {evidence_line(event['evidence'][-1])}")
    return "\n".join(lines)


def _how(item: Mapping[str, Any]) -> str:
    if item["outcome"] == "fixed" and item["closed_by_version"] is not None:
        return f"by version {item['closed_by_version']}"
    if item["outcome"] == "dismissed":
        note = f": {item['note']}" if item["note"] else ""
        return f"{item['dismissal_reason']} by {item['dismissed_by']}{note}"
    return "by its source"


def history_text(payload: Mapping[str, Any]) -> str:
    lines = [f"{payload['model_id']} v{payload['current_version']}"]
    lines.append(f"History ({len(payload['history'])}):")
    for item in payload["history"]:
        lines.append(
            f"  #{item['alert_id']} {item['outcome']:<9} at {item['closed_at']} {_how(item)};"
            f" {item['severity']} {_cause_text(item['kind'], item['cause'])}"
        )
        if item["evidence"]:
            lines.append(f"      evidence: {evidence_line(item['evidence'][-1])}")
    return "\n".join(lines)


# --- inventory audit (feature 003, US2) ---------------------------------------------------------


def _summary_line(summary: Mapping[str, Any]) -> str:
    return (
        f"Summary: {summary['alerts_open']} open alerts,"
        f" {summary.get('alerts_excepted', 0)} excepted, {summary['watch_events']} watch events;"
        f" {summary['entries']} entries: {summary['verified']} verified,"
        f" {summary['declared_but_unverified']} declared but unverified,"
        f" {summary['conflicting']} conflicting, {summary['unavailable']} unavailable;"
        f" {summary['gaps']} gaps, {summary['uncheckable']} uncheckable; sources:"
        f" {summary['sources_failed']} failed, {summary['sources_stale']} stale,"
        f" {summary['sources_not_checked']} not checked"
    )


def _coverage_line(item: Mapping[str, Any]) -> str:
    entries = len(item["relevant_entries"])
    if item["last_run_id"] is None:
        return f"  {item['source']}: not checked since registration ({entries} entries)"
    stale = ", stale" if item["stale"] else ""
    return (
        f"  {item['source']}: {item['status']} in run {item['last_run_id']} at"
        f" {item['last_finished_at']} ({item['age_hours']} h ago{stale}; {entries} entries;"
        f" last ok {item['last_ok_at'] or 'never'})"
    )


def audit_text(payload: Mapping[str, Any]) -> str:
    """The audit for people: the summary first, then findings, assurance and coverage."""
    findings = payload["findings"]
    lines = [
        f"{payload['model_id']} v{payload['version']} audit at {payload['produced_at']}",
        _summary_line(payload["summary"]),
        payload["statement"],
    ]
    sources = payload["coverage"]["sources"]
    if findings["state"] == "not_yet_checked":
        lines.append(
            "Findings: not yet checked"
            " (no relevant source has succeeded in a check of this version)"
        )
    else:
        partly = ""
        if findings["state"] == "partly_checked":
            partly = (
                f" (partly checked: {sum(bool(item['last_ok_at']) for item in sources)} of"
                f" {len(sources)} relevant sources have succeeded)"
            )
        lines.append(
            f"Findings: {len(findings['alerts'])} open alerts,"
            f" {len(findings['watch_events'])} watch events{partly}"
        )
    lines += [alert_line(alert) for alert in findings["alerts"]]
    if findings.get("excepted"):
        lines.append(f"Excepted ({len(findings['excepted'])}):")
        lines += [alert_line(alert) for alert in findings["excepted"]]
    lines += [f"  {event['kind']} {event['identifier']}" for event in findings["watch_events"]]
    assurance = payload["assurance"]
    lines.append(f"Assurance ({len(assurance['entries'])} entries):")
    for entry in assurance["entries"]:
        where = entry["location"] or ""
        reason = f": {entry['gap_reason']}" if entry["gap_reason"] else ""
        lines.append(
            f"  {entry['status']:<24} {entry['kind']:<12} {entry['identifier'] or ''} {where}"
            f"{reason}".rstrip()
        )
        for claim in entry["claims"]:
            if claim["verification"] in ("unverified", "contradicted"):
                why = f": {claim['reason']}" if claim.get("reason") else ""
                lines.append(
                    f"      {claim['claim']} {claim['verification']}"
                    f" (origin {claim['origin']}){why}"
                )
    undeclared = ", ".join(assurance["undeclared_kinds"]) or "none"
    lines.append(f"  Not declared at all: {undeclared}")
    coverage = payload["coverage"]
    lines.append(f"Coverage ({len(coverage['sources'])} relevant sources):")
    lines += [_coverage_line(item) for item in coverage["sources"]]
    lines.append(f"  Uncheckable ({len(coverage['uncheckable'])}):")
    for item in coverage["uncheckable"]:
        where = item["location"] or item["identifier"] or ""
        lines.append(f"    {item['kind']} {where}: {item['reason']}".replace("  :", " :"))
    return "\n".join(lines)


def _identity_text(item: Mapping[str, Any]) -> str:
    identity = item["identity"]
    kind = item["kind"]
    if kind == "weight_file":
        if "sha256" not in identity:
            return str(identity.get("path"))
        runs = "can run code" if identity.get("can_run_code") else "code-free"
        if identity.get("can_run_code") is None:
            runs = "may run code"
        return f"{identity['path']} sha256:{identity['sha256']} {identity['format']} ({runs})"
    if kind == "package":
        if identity.get("requirement"):
            return str(identity["requirement"])
        return f"{identity.get('name')}=={identity.get('version')}"
    if kind == "environment":
        return f"{identity['lock']} ({identity.get('packages')} packages, hash-locked)"
    if kind == "licence":
        spdx = identity.get("spdx")
        return str(identity.get("licence")) + (f" (SPDX {spdx})" if spdx else "")
    return str(identity.get("hub_repo") or identity.get("doi") or identity)


def discover_text(payload: Mapping[str, Any]) -> str:
    """Discovery for people: the statement first, then candidates, comparison and skips."""
    lookups = "with hub lookups" if payload["upstream"] else "no network requests"
    candidates = payload["candidates"]
    lines = [
        f"Discovery of {payload['project']} at {payload['observed_at']} ({lookups})",
        payload["statement"],
        f"Candidates ({len(candidates)}):",
    ]
    for item in candidates:
        extra = [f"gaps: {', '.join(item['gaps'])}"] if item["gaps"] else []
        if item.get("manifest"):
            value = item.get("manifest_value") if item["manifest"] == "conflicts" else None
            shown = ", ".join(str(v) for v in (value or {}).values() if v is not None)
            extra.append(f"manifest: {item['manifest']}" + (f" ({shown})" if shown else ""))
        if item.get("note"):
            extra.append(item["note"])
        if item.get("proposed_revision"):
            revision = item["proposed_revision"]
            extra.append(f"hub head {revision['revision']} ({revision['label']})")
        tail = f" [{'; '.join(extra)}]" if extra else ""
        lines.append(f"  {item['status']:<24} {item['kind']:<12} {_identity_text(item)}{tail}")
    if payload["declared_not_seen"]:
        lines.append(f"Declared in the manifest, not seen ({len(payload['declared_not_seen'])}):")
        for item in payload["declared_not_seen"]:
            identity = ", ".join(f"{k} {v}" for k, v in item["identity"].items() if v is not None)
            reason = f": {item['reason']}" if item.get("reason") else ""
            lines.append(f"  {item['kind']} {identity}{reason}")
    lines.append(f"Skipped ({len(payload['skipped'])}):")
    for item in payload["skipped"]:
        keys = f" ({', '.join(item['keys'])})" if item.get("keys") else ""
        lines.append(f"  {item['path']}: {item['reason']}{keys}")
    if payload.get("output"):
        lines.append(f"Proposed manifest written to {payload['output']['path']}")
    return "\n".join(lines)

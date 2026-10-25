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

from model_dependabot.matching.severity import severity_rank
from model_dependabot.store import Store

SCOPE_ALL = "all"
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
    "closed": CLOSED_STATES,
    "all": None,
}


def evidence_view(evidence: Mapping[str, Any]) -> dict[str, Any]:
    return {key: evidence[key] for key in EVIDENCE_FIELDS}


def alert_view(store: Store, alert: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "alert_id": alert["alert_id"],
        "kind": alert["kind"],
        "state": alert["state"],
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
    return {
        "alert_id": alert["alert_id"],
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
    """The ``alerts`` payload: alerts in ``state`` by severity, then the watch events."""
    if state not in STATE_FILTERS:
        raise ValueError(f"state must be one of {', '.join(STATE_FILTERS)}, got {state!r}")
    version = store.latest_version(model_id)
    listed = by_severity(store.alerts_for(model_id, STATE_FILTERS[state]))
    events = [] if version is None else store.watch_events(model_id, version)
    run = store.latest_check_run([model_id, SCOPE_ALL])
    return {
        "model_id": model_id,
        "current_version": version,
        "alerts": [alert_view(store, alert) for alert in listed],
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
        return f"{kind} {cause['location']} ({cause.get('identifier')})"
    # The upstream kinds (feature 002) name a base model or dataset, not a file.
    text = f"{kind} {cause.get('identifier')}"
    if kind == "licence_changed":
        recorded = _one_line(cause.get("recorded_licence"))
        declared = _one_line(cause.get("declared_normalised") or cause.get("declared_licence"))
        text += f": {recorded} -> {declared}"
    if cause.get("paper_doi"):
        text += f" (paper {cause['paper_doi']})"
    return text


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
    head = f"  #{alert['alert_id']} {alert['severity']:<8} {alert['state']:<9}"
    return f"{head} {_cause_text(alert['kind'], alert['cause'])}"


def alerts_text(payload: Mapping[str, Any]) -> str:
    lines = [f"{payload['model_id']} v{payload['current_version']}"]
    lines.append(f"Alerts ({len(payload['alerts'])}):")
    for alert in payload["alerts"]:
        lines.append(alert_line(alert))
        if alert["evidence"]:
            lines.append(f"      evidence: {evidence_line(alert['evidence'][-1])}")
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

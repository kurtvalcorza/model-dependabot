"""The advisory view of one alert (feature 010, contracts/cli.md, data-model.md).

``advice_view`` builds, from stored rows only, what a maintainer needs beside the unchanged alert:
the affected entry and its places, how the entry relates to the model and on what basis, runtime
use, what the alert's evidence establishes (each statement citing its evidence rows), what it does
not establish, the rule's limitations, the entry's claim states, the owner's decision and the
rule's numbered review steps. Impact always reads ``impact undetermined``: the view scores
nothing, ranks nothing and settles no impact (constitution I, FR-011, FR-012).

Reading only: the functions take an open ``Store`` and call only its reading methods; nothing here
writes to the store or asks a source (FR-002).
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

from model_dependabot.assurance.affected import (
    matched_entries,
    model_versions,
    relationship,
    resolve_entry,
    runtime_use,
)
from model_dependabot.assurance.trust import claim_verification
from model_dependabot.reports import view_state
from model_dependabot.rules import CLOSING, rule_for, texts_for
from model_dependabot.store import Store

SCHEMA = "advice/1"
IMPACT = "impact undetermined"
NOT_RECORDED = "not recorded"
EXCEPTION_SOURCE = "exception"
SEVERITY_NOTES = {
    "policy": "fixed by the service for this alert kind",
    "database_specific": "as published by the source",
    "cvss_v3": "band of the source's CVSS vector",
    "cvss_v4": "band of the source's CVSS vector",
    "unknown": "the source gave no severity",
}
EMPTY_MODEL_NOTE = (
    "No alert is open for this model. That is not an assessment of the model or of how complete"
    " its inventory is."
)
MARKER_LIMITATION = (
    "This inventory does not record environment markers, so it cannot say whether the package is"
    " installed where the model runs."
)
_PLACEHOLDER = re.compile(r"\{([a-z_]+)\}")
_CAUSE_FIELDS = ("identifier", "location", "package", "version", "dataset", "paper_doi", "repo")


def severity_note(origin: str) -> str:
    """The fixed note of a severity origin; any other origin is refused (FR-004)."""
    if origin not in SEVERITY_NOTES:
        raise ValueError(f"no severity note for origin {origin!r}")
    return SEVERITY_NOTES[origin]


def _values(alert: Mapping[str, Any]) -> dict[str, str | None]:
    """The placeholder values: the alert's own stored fields only (FR-014, research R4)."""
    cause = alert["cause"]
    values: dict[str, str | None] = {
        "alert_id": str(alert["alert_id"]),
        "model_id": alert["model_id"],
        "rule_doc": rule_for(alert["kind"]).page,
    }
    for name in _CAUSE_FIELDS:
        value = cause.get(name)
        values[name] = None if value in (None, "") else str(value)
    values["item"] = None if not cause.get("item") else str(cause["item"])
    ids = cause.get("advisory_ids") or ([cause["advisory_id"]] if cause.get("advisory_id") else [])
    values["advisory_ids"] = ", ".join(ids) if ids else None
    return values


def fill(text: str, values: Mapping[str, str | None]) -> str:
    """``text`` with each placeholder replaced; a value the alert does not hold is
    ``not recorded``."""
    return _PLACEHOLDER.sub(lambda m: values.get(m.group(1)) or NOT_RECORDED, text)


def _evidence_item(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "evidence_id": row["evidence_id"],
        "source": row["source"],
        "url": row["url"],
        "retrieved_at": row["retrieved_at"],
        "matched_identifier": row["matched_identifier"],
        "redacted_fields": list(row.get("redacted_fields") or []),
    }


def _statement_text(row: Mapping[str, Any]) -> str:
    text = f"{row['source']} reported {row['matched_identifier']} at {row['retrieved_at']}"
    if row["url"]:
        text += f" ({row['url']})"
    redacted = row.get("redacted_fields") or []
    if redacted:
        text += f"; redacted: {', '.join(redacted)}"
    return text


def established(
    alert: Mapping[str, Any], rows: Sequence[Mapping[str, Any]]
) -> list[dict[str, Any]]:
    """One statement per evidence row, in ``evidence_id`` order, citing that row (FR-009); an
    exception's row is left to the owner-decision block. A withdrawn or cleared alert adds the
    closing row as the source's withdrawal or clearance (research R6)."""
    facts = [row for row in sorted(rows, key=lambda r: r["evidence_id"])]
    facts = [row for row in facts if row["source"] != EXCEPTION_SOURCE]
    result = [
        {
            "kind": "established",
            "text": _statement_text(row),
            "evidence_ids": [row["evidence_id"]],
            "evidence": [_evidence_item(row)],
        }
        for row in facts
    ]
    if alert["state"] in ("withdrawn", "cleared") and facts:
        closing = facts[-1]
        verb = "withdrew" if alert["state"] == "withdrawn" else "cleared"
        result.append(
            {
                "kind": "established",
                "text": f"the source {verb} the cause ({closing['source']} at"
                f" {closing['retrieved_at']})",
                "evidence_ids": [closing["evidence_id"]],
                "evidence": [_evidence_item(closing)],
            }
        )
    return result


def _absent(store: Store, alert: Mapping[str, Any], version: int, identifier: str) -> bool:
    return any(
        event["kind"] == "weight_file_absent" and event["entry_identifier"] == identifier
        for event in store.watch_events(alert["model_id"], version)
    )


def not_established(
    store: Store,
    alert: Mapping[str, Any],
    entry: Mapping[str, Any],
    first: Mapping[str, Any] | None,
) -> list[dict[str, Any]]:
    """The impact question, the rule's questions, then the conditional items of research R6."""
    values = _values(alert)
    texts = [
        fill(text, values) for text in texts_for(rule_for(alert["kind"]).rule_id).not_established
    ]
    if entry["status"] == "unresolved":
        texts.append(f"which inventory entry this alert is about: {entry['reason']}")
    if first is not None:
        stored, origin = first["entry"], first["origin"]
        if origin == "import":
            texts.append(
                f"whether the imported declaration of {entry['identifier']} is accurate: it is"
                " not the owner's own"
            )
        if (
            stored["kind"] == "weight_file"
            and stored.get("hub_repo")
            and not stored.get("location")
        ):
            texts.append(
                "what the file holds: no local scan read this file; the hub's own verdict is the"
                " source"
            )
        if stored["kind"] == "weight_file" and _absent(
            store, alert, first["version"], stored["identifier"]
        ):
            texts.append(
                "whether the file's bytes match their record: the bytes were not read in this place"
            )
    if alert["kind"] == "package_advisory":
        texts.append(
            f"whether {values['package'] or NOT_RECORDED} is installed where the model runs"
        )
    return [{"kind": "not_established", "text": text} for text in texts]


def limitations(alert: Mapping[str, Any]) -> list[dict[str, Any]]:
    """The rule's limitations text, unchanged; a package alert adds the marker limitation (Q1)."""
    texts = [texts_for(rule_for(alert["kind"]).rule_id).limitations]
    if alert["kind"] == "package_advisory":
        texts.append(MARKER_LIMITATION)
    return [{"kind": "limitation", "text": text} for text in texts]


def claims(store: Store, alert: Mapping[str, Any], first: Mapping[str, Any] | None) -> list[Any]:
    """The claim states of the entry in ``places[0]``'s version (FR-013): never statements."""
    if first is None:
        return []
    checks = store.claim_checks(alert["model_id"], first["version"])
    # data-model.md names the claim ``field``; ``claim_verification`` calls it ``claim``.
    return [
        {"field": c["claim"], **{k: v for k, v in c.items() if k != "claim"}}
        for c in claim_verification(first["entry"], first["origin"], checks)
    ]


def owner_decision(store: Store, alert: Mapping[str, Any]) -> dict[str, Any] | None:
    """A dismissal or the exceptions of an excepted alert (research R7); never an impact."""
    state = view_state(alert)
    if state == "dismissed":
        item = {
            "by": alert.get("dismissed_by"),
            "at": alert.get("closed_at"),
            "reason": alert.get("dismissal_reason"),
            "note": alert.get("note"),
        }
        return {"type": "dismissal", "items": [item]}
    if state != "excepted":
        return None
    items = []
    for excepted in sorted(alert["cause"].get("excepted") or [], key=lambda e: e["exception_id"]):
        record = store.get_exception(excepted["exception_id"])
        rows = store.exception_evidence(excepted["exception_id"])
        items.append(
            {
                "global": excepted["global"],
                "exception_id": excepted["exception_id"],
                "by": excepted.get("accepted_by"),
                "at": excepted.get("recorded_at"),
                "expires_on": excepted.get("expires_on"),
                "reason": None if record is None else record.get("reason"),
                "evidence_id": rows[0] if rows else None,
            }
        )
    return {"type": "exception", "items": items}


def review_steps(alert: Mapping[str, Any]) -> list[dict[str, Any]]:
    """The rule's steps, numbered from 1 and filled from the alert's stored fields, then how the
    alert closes (FR-015)."""
    texts = texts_for(rule_for(alert["kind"]).rule_id)
    values = _values(alert)
    lines = [fill(step, values) for step in texts.steps] + [CLOSING + texts.closes]
    return [{"number": number, "text": text} for number, text in enumerate(lines, start=1)]


def _same_identifier(
    alert: Mapping[str, Any], others: Sequence[Mapping[str, Any]], versions: Mapping[int, Any]
) -> list[Mapping[str, Any]]:
    """The model's other alerts whose resolved entry has the same identifier as this one's."""
    mine = {m["entry"]["identifier"] for m in matched_entries(alert, versions)}
    mine.add(alert["cause"].get("identifier"))
    same = []
    for other in others:
        if other["alert_id"] == alert["alert_id"]:
            continue
        theirs = {m["entry"]["identifier"] for m in matched_entries(other, versions)}
        theirs.add(other["cause"].get("identifier"))
        if (mine & theirs) - {None}:
            same.append(other)
    return same


def advice_view(
    store: Store,
    alert: Mapping[str, Any],
    *,
    versions: Mapping[int, Any] | None = None,
    model_alerts: Sequence[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """The advisory view of ``alert`` (a ``store.get_alert`` record), field order of
    data-model.md. ``versions`` and ``model_alerts`` may be passed when listing many alerts of one
    model, so the model is read once."""
    rule = rule_for(alert["kind"])
    if versions is None:
        versions = model_versions(store, alert["model_id"])
    if model_alerts is None:
        model_alerts = store.alerts_for(alert["model_id"])
    entry = resolve_entry(alert, versions)
    found = matched_entries(alert, versions)
    first = found[0] if found else None
    return {
        "schema": SCHEMA,
        "alert_id": alert["alert_id"],
        "severity": {
            "value": alert["severity"],
            "origin": alert["severity_origin"],
            "note": severity_note(alert["severity_origin"]),
        },
        "entry": entry,
        "relationship": relationship(entry, alert, entry["places"]),
        "runtime_use": runtime_use(alert, _same_identifier(alert, model_alerts, versions)),
        "established": established(alert, store.alert_evidence(alert["alert_id"])),
        "not_established": not_established(store, alert, entry, first),
        "limitations": limitations(alert),
        "claims": claims(store, alert, first),
        "impact": IMPACT,
        "owner_decision": owner_decision(store, alert),
        "review_steps": review_steps(alert),
        "rule_doc": rule.page,
    }


def advice_summary(listed: int) -> dict[str, Any]:
    """``advice_summary`` of ``alerts ID --advice``: the views listed and, for none, the note."""
    return {"alerts_listed": listed, "note": EMPTY_MODEL_NOTE if listed == 0 else None}


# --- text ---------------------------------------------------------------------------------------


def _entry_lines(entry: Mapping[str, Any]) -> list[str]:
    if entry["status"] == "unresolved":
        return [f"  Entry: unresolved: {entry['reason']} ({entry['identifier']})"]
    if entry["in_current_version"]:
        where = f"in the current version (v{entry['last_held_in_version']})"
    else:
        where = "not in the current version"
    line = f"  Entry: {entry['kind']} {entry['identifier']}, {where}"
    line += f"; opened in v{entry['opened_in_version']}"
    if not entry["in_current_version"]:
        line += f"; last held in v{entry['last_held_in_version']}"
        if entry["closed_by_version"] is not None:
            line += f", fixed by v{entry['closed_by_version']}"
    lines = [line]
    for place in entry["places"]:
        parts = [f"v{place['version']} {place['origin'] or 'legacy'}"]
        parts.append(place["section"] or "no manifest section")
        parts += [value for value in (place["location"], place["revision"]) if value]
        lines.append("    " + ", ".join(parts))
    return lines


def _relationship_line(view: Mapping[str, Any]) -> str:
    found = view["relationship"]
    if found is None:
        return "  Relationship: none"
    basis = found["basis"]
    value = found["value"]
    if view["entry"]["kind"] == "weight_file":
        location = view["entry"]["places"][0]["location"] or NOT_RECORDED
        value += f" ({'hub' if location.startswith('hf:') else 'local'}) {location}"
    who = {"owner": "owner", "imported": "imported", "legacy": "legacy"}[basis["declared_by"]]
    return f"  Relationship: {value} ({who} declaration, v{basis['version']})"


def _runtime_lines(use: Mapping[str, Any]) -> list[str]:
    if use["state"] == "declared":
        basis = use["basis"]
        note = f": {basis['note']}" if basis["note"] else ""
        return [
            f"  Runtime use: declared {use['polarity']} by {basis['by']} at {basis['at']}{note}"
        ]
    lines = [f"  Runtime use: {use['state']}: {use['basis']['why']}"]
    for other in use["context"]:
        lines.append(
            f"    alert #{other['alert_id']} on the same identifier was dismissed"
            f" not_used_at_runtime by {other['by']} at {other['at']}"
        )
    return lines


def _list(title: str, items: Sequence[str]) -> list[str]:
    if not items:
        return [f"  {title}: none"]
    return [f"  {title}:"] + [f"    - {item}" for item in items]


def _owner_lines(decision: Mapping[str, Any] | None) -> list[str]:
    if decision is None:
        return ["  Owner decision: none"]
    if decision["type"] == "dismissal":
        item = decision["items"][0]
        note = f": {item['note']}" if item["note"] else ""
        return [
            f"  Owner decision: dismissed {item['reason']} by {item['by']} at {item['at']}{note}"
        ]
    lines = []
    for item in decision["items"]:
        expires = f", expires {item['expires_on']}" if item["expires_on"] else ""
        lines.append(
            f"  Owner decision: exception {item['exception_id']} for {item['global']} by"
            f" {item['by']} at {item['at']}{expires}: {item['reason']}"
        )
    return lines


def advice_text(view: Mapping[str, Any]) -> str:
    """The advice block of contracts/cli.md, without a trailing blank line."""
    rule_id = view["rule_doc"].rsplit("/", 1)[-1].removesuffix(".md")
    severity = view["severity"]
    lines = [f"Advice for #{view['alert_id']} {rule_id} ({view['rule_doc']})"]
    lines.append(f"  Severity: {severity['value']} ({severity['origin']}, {severity['note']})")
    lines += _entry_lines(view["entry"])
    lines.append(_relationship_line(view))
    lines += _runtime_lines(view["runtime_use"])
    lines += _list(
        "Established",
        [
            f"{s['text']} [evidence {', '.join(map(str, s['evidence_ids']))}]"
            for s in view["established"]
        ],
    )
    lines += _list("Not established", [s["text"] for s in view["not_established"]])
    lines += _list("Limitations", [s["text"] for s in view["limitations"]])
    lines += _list(
        "Claims",
        [f"{c['field']} (origin {c['origin']}): {c['verification']}" for c in view["claims"]],
    )
    lines.append(f"  Impact: {view['impact']}")
    lines += _owner_lines(view["owner_decision"])
    lines.append("  Review steps:")
    lines += [f"    {step['number']}. {step['text']}" for step in view["review_steps"]]
    return "\n".join(lines)

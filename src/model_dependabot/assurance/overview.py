"""The check overview: what each source asked in a run covered, per model and overall (US3).

A check run tallies, per model and check source, the alerts it opened or carried forward, the
alerts it closed, the watch events it recorded and the entries it could not finish (research S6).
This module turns those tallies into the rows of data-model.md (Check overview), stored with the
run in ``check_run_overview``, and reads them back for ``check`` and ``run show``. State, first
match wins: ``failed`` (the source failed or was skipped), ``incomplete`` (an entry could not be
finished, owner's ruling D4), ``alerted`` (an alert tallied to it is open and not excepted at the
end of the run) and ``passed``. The format rules and the globals policy are tallied under
``policy``. A failed source has null counts: nothing it would have changed was changed.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from model_dependabot.assurance.audit import relevant_sources
from model_dependabot.matching.severity import SEVERITIES, severity_rank
from model_dependabot.rules import rule_for
from model_dependabot.store import Store

POLICY = "policy"
UNCHECKABLE = "uncheckable"
WEIGHT_SOURCES = ("picklescan", "hf-scan", "format-check")
STATES = ("failed", "incomplete", "alerted", "passed")  # worst first
COUNTS = (
    "entries",
    "incomplete",
    "alerts_open",
    "alerts_excepted",
    "watch_events",
    "dismissals_held",
)
NOTHING_NEEDED = "no entry needed this source"
NOT_CHECKABLE = "no entry of this model can be checked by the sources asked"
ALL_FAILED = "every source that could check this model failed"
NO_MODELS = "No models were checked"


def _failed(status: str | None) -> bool:
    return status is None or status.startswith("failed") or status == "skipped"


def _reason(status: str | None) -> str:
    if status is None:
        return "not run"
    return status.removeprefix("failed: ") if status.startswith("failed") else status


def row_sources(sources: Sequence[str]) -> list[str]:
    """The sources asked, in order, then ``policy`` when a weight source was asked."""
    order = list(dict.fromkeys(sources))
    if any(source in WEIGHT_SOURCES for source in order):
        order.append(POLICY)
    return order


def entries_for(
    store: Store, entries: Iterable[Mapping[str, Any]], origin: str | None, source: str
) -> int:
    """Entries relevant to the source; for ``policy`` the pinned code-capable weight files."""
    if source == POLICY:
        return sum(
            1
            for entry in entries
            if entry["kind"] == "weight_file" and entry.get("pinned") and entry.get("can_run_code")
        )
    return sum(1 for entry in entries if source in relevant_sources(store, entry, origin))


def state_of(counts: Mapping[str, Any], status: str | None) -> str:
    if _failed(status):
        return "failed"
    if counts["incomplete"]:
        return "incomplete"
    if counts["alerts_open"]:
        return "alerted"
    return "passed"


def model_rows(
    store: Store,
    *,
    model_id: str,
    version: int,
    entries: Sequence[Mapping[str, Any]],
    origin: str | None,
    tally: Mapping[str, Mapping[str, set[Any]]],
    held: Mapping[str, Sequence[int]] | None,
    sources: Sequence[str],
    statuses: Mapping[str, str],
    uncheckable: Sequence[Mapping[str, Any]] = (),
) -> list[dict[str, Any]]:
    """One model's rows: one per source asked that has a relevant entry (research S6), and one
    ``uncheckable`` row listing items no source can ever read (review K3), its ``reason`` the
    list as JSON."""
    rows = []
    if uncheckable:
        rows.append(
            {"model_id": model_id, "version": version, "source": UNCHECKABLE, "state": "passed",
             "reason": json.dumps(list(uncheckable)), "entries": len(uncheckable)}
            | {key: None for key in COUNTS if key != "entries"}
        )  # fmt: skip
    for source in row_sources(sources):
        count = entries_for(store, entries, origin, source)
        if not count:
            continue
        status = "ok" if source == POLICY else statuses.get(source)
        row: dict[str, Any] = {
            "model_id": model_id,
            "version": version,
            "source": source,
            "entries": count,
        }
        if _failed(status):
            row |= {"state": "failed", "reason": _reason(status)}
            row |= {key: None for key in COUNTS if key != "entries"}
            rows.append(row)
            continue
        mine = tally.get(source, {})
        alerts = [store.get_alert(int(alert_id)) for alert_id in mine.get("alerts", ())]
        live = [a for a in alerts if a is not None and a["state"] == "open"]
        row |= {
            "reason": None,
            "incomplete": len(mine.get("incomplete", ())),
            "alerts_open": sum(1 for a in live if not a["excepted_at"]),
            "alerts_excepted": sum(1 for a in live if a["excepted_at"]),
            "watch_events": len(mine.get("watch_events", ())),
            "dismissals_held": len((held or {}).get(source, ())),
        }
        row["state"] = state_of(row, status)
        rows.append(row)
    return rows


def run_rows(
    rows: Sequence[Mapping[str, Any]], sources: Sequence[str], statuses: Mapping[str, str]
) -> list[dict[str, Any]]:
    """The run-wide row of each source: the worst state over models and the summed counts."""
    wide = []
    for source in row_sources(sources):
        status = "ok" if source == POLICY else statuses.get(source)
        mine = [row for row in rows if row["source"] == source and row["source"] != UNCHECKABLE]
        row: dict[str, Any] = {"model_id": None, "version": None, "source": source}
        if _failed(status):
            row |= {"state": "failed", "reason": _reason(status)}
            row |= {key: None for key in COUNTS}
            row["entries"] = sum(r["entries"] for r in mine)
        elif not mine:
            row |= {"state": "passed", "reason": NOTHING_NEEDED} | {key: 0 for key in COUNTS}
        else:
            row |= {key: sum(r[key] or 0 for r in mine) for key in COUNTS}
            row["state"] = min((r["state"] for r in mine), key=STATES.index)
            row["reason"] = None
        wide.append(row)
    return wide


def payload(store: Store, run_id: int) -> dict[str, Any]:
    """The overview of a stored run, as ``check`` and ``run show`` print it."""
    stored = store.check_run_overview(run_id)
    targets = store.check_run_target_versions(run_id)
    order = {source: index for index, source in enumerate(store.check_run_source_order(run_id))}

    def view(row: Mapping[str, Any]) -> dict[str, Any]:
        keys = ("source", "state", "reason", *COUNTS)
        return {key: row[key] for key in keys}

    def ordered(rows: Iterable[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
        return sorted(rows, key=lambda row: order.get(row["source"], len(order)))

    models = []
    for model_id, version in targets:
        mine = [row for row in stored if row["model_id"] == model_id]
        items = [
            item
            for row in mine
            if row["source"] == UNCHECKABLE
            for item in json.loads(row["reason"])
        ]
        rows = ordered(row for row in mine if row["source"] != UNCHECKABLE)
        # Review K1: the ``policy`` row judges the inventory and the owner's policy, not the bytes,
        # so it is not coverage (FR-021).
        covering = [row for row in rows if row["source"] != POLICY]
        checked = any(row["state"] != "failed" for row in covering)
        reason = None if checked else (ALL_FAILED if covering else NOT_CHECKABLE)
        models.append(
            {
                "model_id": model_id,
                "version": version,
                "checked": checked,
                "reason": reason,
                "sources": [view(row) for row in rows],
                "uncheckable": items,
            }
        )
    return {
        "sources": [view(row) for row in ordered(r for r in stored if r["model_id"] is None)],
        "models": models,
    }


HEADER = (
    f"  {'source':<13} {'state':<11} {'entries':>7}  {'incomplete':>10}  {'alerts':>6}"
    f"  {'excepted':>8}  {'held':>4}  {'watch events':>12}"
)


def _line(row: Mapping[str, Any]) -> str:
    def cell(key: str, width: int) -> str:
        value = row[key]
        return f"{'-' if value is None else value:>{width}}"

    text = (
        f"  {row['source']:<13} {row['state']:<11} {cell('entries', 7)}  {cell('incomplete', 10)}"
        f"  {cell('alerts_open', 6)}  {cell('alerts_excepted', 8)}  {cell('dismissals_held', 4)}"
        f"  {cell('watch_events', 12)}"
    )
    if row["state"] == "failed" and row.get("reason"):
        text += f"   {row['reason']}"
    return text


def text(run_id: int, scope: str, overview: Mapping[str, Any]) -> str:
    """The overview for people (contracts/cli.md, The check overview)."""
    lines = [f"Overview of run {run_id} ({scope})", HEADER]
    lines += [_line(row) for row in overview["sources"]]
    if not overview["models"]:
        lines.append(NO_MODELS)
    for model in overview["models"]:
        if model["checked"]:
            lines.append(f"{model['model_id']} v{model['version']}: checked")
            lines += [_line(row) for row in model["sources"]]
        for item in model.get("uncheckable") or []:
            lines.append(f"  uncheckable: {item['kind']} {item['identifier']}: {item['reason']}")
        else:
            lines.append(f"{model['model_id']} v{model['version']}: not checked: {model['reason']}")
    return "\n".join(lines)


# --- the gate (US5, research S5, owner's ruling D8, FR-021) -------------------------------------


def gate(
    store: Store,
    model_ids: Sequence[str],
    fail_on: str,
    covered: Mapping[str, Any],
    *,
    sources_failed: bool,
) -> dict[str, Any]:
    """The gate of ``check --fail-on``: what trips it and whether it decided the exit code.

    Every alert of every model in scope that is open, not excepted and at or above ``fail_on``
    (whichever run raised it), every overview row in the ``incomplete`` state, every model that
    reads ``checked: false`` and an empty scope trip it. With a failed source exit 2 decides.
    """
    if fail_on not in SEVERITIES:
        raise ValueError(f"--fail-on must be one of {', '.join(SEVERITIES)}, got {fail_on!r}")
    alerts = []
    for model_id in model_ids:
        for alert in store.alerts_for(model_id, ["open"]):
            if alert["excepted_at"] or severity_rank(alert["severity"]) > severity_rank(fail_on):
                continue
            alerts.append(
                {
                    "alert_id": alert["alert_id"],
                    "model_id": model_id,
                    "rule_id": rule_for(alert["kind"]).rule_id,
                    "kind": alert["kind"],
                    "severity": alert["severity"],
                }
            )
    incomplete = [
        {"model_id": model["model_id"], "source": row["source"]}
        for model in covered["models"]
        for row in model["sources"]
        if row["state"] == "incomplete"
    ]
    unchecked = [model["model_id"] for model in covered["models"] if not model["checked"]]
    empty_scope = not covered["models"]
    tripped = bool(alerts or incomplete or unchecked or empty_scope)
    return {
        "fail_on": fail_on,
        "tripped": tripped,
        "decided_exit": not sources_failed,
        "alerts": alerts,
        "incomplete": incomplete,
        "unchecked": unchecked,
        "empty_scope": empty_scope,
    }


def gate_text(found: Mapping[str, Any]) -> str:
    """The gate for people: one line per tripping alert, incomplete source and unchecked model."""
    verdict = "tripped" if found["tripped"] else "passed"
    if found["tripped"] and not found["decided_exit"]:
        verdict += " (a source failed: exit 2 decides)"
    lines = [f"Gate --fail-on {found['fail_on']}: {verdict}"]
    for alert in found["alerts"]:
        lines.append(
            f"  alert #{alert['alert_id']} {alert['rule_id']} {alert['severity']}"
            f" {alert['kind']} ({alert['model_id']})"
        )
    for item in found["incomplete"]:
        lines.append(f"  incomplete: {item['model_id']} {item['source']}")
    for model_id in found["unchecked"]:
        lines.append(f"  not checked: {model_id}")
    if found["empty_scope"]:
        lines.append("  the scope matched no model")
    return NEWLINE.join(lines)


NEWLINE = chr(10)

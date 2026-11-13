"""The inventory audit: findings, assurance and check coverage of one model version (FR-008-014).

Three separate answers from the stored data, so that "no alerts" is never read as "complete" or
"safe" (FR-012):

- **findings**: the open alerts and the version's watch events, with the state ``checked`` once
  every relevant source has succeeded in a run that checked the version, ``partly_checked`` while
  only some have and ``not_yet_checked`` while none has;
- **assurance**: every entry classified ``verified``, ``declared-but-unverified``, ``conflicting``
  or ``unavailable`` with each claim's origin and verification (``trust.claim_verification``), and
  the dependency kinds the inventory does not declare at all;
- **coverage**: for each source relevant to the version's entries, its latest result in a run
  after the version was registered whose scope covered the model and which asked that source, how
  old that result is and whether it failed; and the entries no source can check.

Research A12 gives the rules. The audit reads only: it contacts no source, runs no check, changes
no alert and writes nothing. The CLI opens the store read-only (``Store.open_read_only``), so a
database of an earlier version is read with defaults and never upgraded (FR-013).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

from model_dependabot.assurance.trust import (
    CODE_FREE,
    IDENTITY,
    claim_verification,
    latest_check,
    measured_entries,
    needs_confirmation,
)
from model_dependabot.reports import alert_view, watch_view
from model_dependabot.sources import crossref, datacite
from model_dependabot.sources.hf import is_commit
from model_dependabot.store import Store, utc_text

STATEMENT = "No alerts is not evidence that the inventory is complete or the model is safe."
DEFAULT_STALE_AFTER_HOURS = 24.0
SOURCE_ORDER = (
    "osv",
    "picklescan",
    "hf-scan",
    "format-check",
    "hf-hub",
    "hf-takedowns",
    "crossref",
    "datacite",
    "zenodo",
    "figshare",
)
STATUSES = ("verified", "declared-but-unverified", "conflicting", "unavailable")
UNKNOWN_FORMAT = "the file's format is unknown"
NO_AGENCY = "the DOI's registration agency is not known, so no source is asked about it"
NO_SOURCE = "no source checks this entry"
NOT_CHECKED = "not checked"
CHECKED = "checked"
PARTLY_CHECKED = "partly_checked"
NOT_YET_CHECKED = "not_yet_checked"
NO_COMMIT = (
    "format-check never reads a hub file not pinned to a commit, so its format claim cannot be"
    " confirmed"
)
NO_LOCATION = "format-check has no location to read, so the format claim cannot be confirmed"
KIND_NAMES = {
    "environment": "package",
    "base_model": "base_model",
    "datasets": "dataset",
    "weights": "weight_file",
}


def _where(entry: Mapping[str, Any]) -> str | None:
    if entry.get("location"):
        return str(entry["location"])
    if entry.get("hub_repo") and entry.get("hub_file"):
        return f"hf:{entry['hub_repo']}/{entry['hub_file']}"
    if entry.get("hub_repo"):
        return f"hf:{entry['hub_repo']}"
    if entry.get("kind") == "base_model" and entry.get("name"):
        return f"hf:{entry['name']}"
    return None


def _label(entry: Mapping[str, Any]) -> str:
    """How coverage names an entry: its identifier, else where it is."""
    return str(entry.get("identifier") or _where(entry) or entry["kind"])


def entry_status(
    entry: Mapping[str, Any], claims: Sequence[Mapping[str, Any]], latest: Mapping[str, Any] | None
) -> str:
    """``verified``, ``declared-but-unverified``, ``conflicting`` or ``unavailable`` (A12).

    ``latest`` is the entry's most recent claim check of any claim, if any.
    """
    if not entry.get("pinned"):
        return "unavailable"
    verifications = {claim["verification"] for claim in claims}
    if "contradicted" in verifications:
        return "conflicting"
    if latest is not None and latest.get("outcome") == "unreadable":
        return "unavailable"
    if "unverified" in verifications:
        return "declared-but-unverified"
    return "verified"


def _doi_sources(store: Store, doi: str) -> list[str]:
    routing = store.get_routing(doi) or {}
    found = []
    if crossref.queried(routing.get("agency")):
        found.append("crossref")
    if datacite.queried(routing.get("agency")):
        found.append("datacite")
    if routing.get("repository") in ("zenodo", "figshare"):
        found.append(str(routing["repository"]))
    return found


def relevant_sources(store: Store, entry: Mapping[str, Any], origin: str | None) -> list[str]:
    """The sources that can check an entry, by its kind (research A12)."""
    if not entry.get("pinned"):
        return []
    kind = entry["kind"]
    found: list[str] = []
    if kind == "package":
        found.append("osv")
    elif kind == "weight_file":
        if entry.get("hub_repo"):
            found.append("hf-scan")
        elif entry.get("can_run_code"):
            found.append("picklescan")
        if needs_confirmation(entry, origin) and _unconfirmable(entry) is None:
            found.append("format-check")
    elif kind == "base_model":
        found.append("hf-hub")
    elif kind == "dataset" and entry.get("hub_repo"):
        found += ["hf-hub", "hf-takedowns"]
    elif kind == "dataset":
        found += _doi_sources(store, str(entry["identifier"]))
    if kind == "dataset" and "crossref" not in found and _papers_at_crossref(store, entry):
        found.append("crossref")
    return found


def _papers_at_crossref(store: Store, entry: Mapping[str, Any]) -> bool:
    """Whether Crossref is asked about one of the papers tied to a dataset (PR #15 round 2, S2).

    The upstream check reads a paper's retraction from Crossref when Crossref registers its DOI,
    for a hub dataset as for a DOI dataset, so a failed Crossref read leaves that paper unchecked.
    """
    return any(
        crossref.queried((store.get_routing(paper) or {}).get("agency"))
        for paper in entry.get("paper_dois") or []
    )


def _unconfirmable(entry: Mapping[str, Any]) -> str | None:
    """Why ``format-check`` can never read a weight file's claim (as ``pending`` skips it)."""
    if entry.get("hub_repo") and not is_commit(entry.get("hub_revision")):
        return NO_COMMIT
    if not entry.get("hub_repo") and not entry.get("location"):
        return NO_LOCATION
    return None


def _uncheckable_reason(entry: Mapping[str, Any], sources: Sequence[str]) -> str | None:
    """Why no source can check an entry, or ``None`` when one can or none needs to."""
    if not entry.get("pinned"):
        return str(entry.get("gap_reason"))
    if sources:
        return None
    if entry["kind"] == "weight_file":
        if entry.get("can_run_code") is None:
            return UNKNOWN_FORMAT
        return None  # a local code-free file classified from its bytes: nothing to check
    if entry["kind"] == "dataset" and not entry.get("hub_repo"):
        return NO_AGENCY
    return NO_SOURCE


def _parse(stamp: str) -> datetime:
    return datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _coverage(
    source: str,
    entries: Sequence[str],
    runs: Sequence[Mapping[str, Any]],
    now: datetime,
    stale_after_hours: float,
) -> dict[str, Any]:
    asked = [run for run in runs if source in (run["sources"] or {})]
    latest = asked[0] if asked else None
    ok = next((run for run in asked if run["sources"][source] == "ok"), None)
    item: dict[str, Any] = {
        "source": source,
        "relevant_entries": list(entries),
        "last_run_id": None,
        "last_finished_at": None,
        "status": NOT_CHECKED,
        "last_ok_at": None if ok is None else ok["finished_at"],
        "age_hours": None,
        "stale": False,
    }
    if latest is None:
        return item
    age = (now - _parse(latest["finished_at"])).total_seconds() / 3600
    item |= {
        "last_run_id": latest["run_id"],
        "last_finished_at": latest["finished_at"],
        "status": latest["sources"][source],
        "age_hours": round(age, 2),
        "stale": age > stale_after_hours,
    }
    return item


def _undeclared(entries: Sequence[Mapping[str, Any]]) -> list[str]:
    kinds = {entry["kind"] for entry in entries}
    return [name for name, kind in KIND_NAMES.items() if kind not in kinds]


def audit_report(
    store: Store,
    model_id: str,
    version: int | None = None,
    *,
    stale_after_hours: float = DEFAULT_STALE_AFTER_HOURS,
) -> dict[str, Any]:
    """The audit report of one version (the latest by default); ``LookupError`` if unknown."""
    if store.get_model(model_id) is None:
        raise LookupError(f"no model {model_id!r} is registered")
    chosen = store.latest_version(model_id) if version is None else version
    record = None if chosen is None else store.get_version(model_id, chosen)
    if chosen is None or record is None:
        raise LookupError(f"model {model_id!r} has no version {version}")
    now = store.now()
    origin = record.get("origin")
    entries = store.entries(model_id, chosen)
    checks = store.claim_checks(model_id, chosen)
    # A run records the version it checked (PR #15 round 2, G1), so it counts for that version
    # only, whenever it started (round 3, T2). A legacy run, recorded before runs recorded their
    # targets, has no version: a check takes the latest version, so it counts if it started after
    # this version was registered and before the next one was (review F1), to the second. A
    # current run with no target row for the model did not check it and never counts (T3).
    since = record["registered_at"]
    until = store.registered_at(model_id, chosen + 1)
    runs = [
        run
        for run in store.check_runs_for(model_id, since="")
        if run["version"] == chosen
        or (
            run["version"] is None
            and run["legacy"]
            and run["started_at"] >= since
            and (until is None or run["started_at"] < until)
        )
    ]

    assured: list[dict[str, Any]] = []
    uncheckable: list[dict[str, Any]] = []
    relevant: dict[str, list[str]] = {}
    measured = measured_entries(entries, checks)
    for entry, seen in zip(entries, measured, strict=True):
        claims = claim_verification(entry, origin, checks)
        identifier = entry.get("identifier")
        latest = max(
            (
                check
                for check in (
                    latest_check(checks, identifier, CODE_FREE),
                    latest_check(checks, identifier, IDENTITY),
                )
                if check is not None
            ),
            key=lambda check: check["claim_check_id"],
            default=None,
        )
        assured.append(
            {
                "kind": entry["kind"],
                "identifier": identifier,
                "location": _where(entry),
                "status": entry_status(entry, claims, latest),
                "gap_reason": entry.get("gap_reason"),
                "claims": claims,
            }
        )
        sources = relevant_sources(store, seen, origin)
        for source in sources:
            relevant.setdefault(source, []).append(_label(entry))
        reason = _uncheckable_reason(seen, sources)
        weight = entry["kind"] == "weight_file" and entry.get("pinned")
        if reason is None and weight and needs_confirmation(entry, origin):
            reason = _unconfirmable(entry)
        if reason is not None:
            uncheckable.append(
                {
                    "kind": entry["kind"],
                    "identifier": identifier,
                    "location": _where(entry),
                    "reason": reason,
                }
            )

    coverage = [
        _coverage(source, relevant[source], runs, now, stale_after_hours)
        for source in SOURCE_ORDER
        if source in relevant
    ]
    alerts = [alert_view(store, alert) for alert in store.alerts_for(model_id, ["open"])]
    events = [watch_view(event) for event in store.watch_events(model_id, chosen)]
    counts = {status: sum(item["status"] == status for item in assured) for status in STATUSES}
    # The version is checked once every relevant source has succeeded in a run that checked it
    # (review F6, PR #15 round 2 G5), partly checked while only some have, and not yet checked
    # when none has; a version with nothing to check counts any run.
    succeeded = sum(bool(item["last_ok_at"]) for item in coverage)
    if not coverage:
        state = CHECKED if runs else NOT_YET_CHECKED
    elif succeeded == len(coverage):
        state = CHECKED
    else:
        state = PARTLY_CHECKED if succeeded else NOT_YET_CHECKED
    checked = state == CHECKED
    summary = {
        "checked": checked,
        "alerts_open": len(alerts),
        "watch_events": len(events),
        "entries": len(entries),
        "verified": counts["verified"],
        "declared_but_unverified": counts["declared-but-unverified"],
        "conflicting": counts["conflicting"],
        "unavailable": counts["unavailable"],
        "gaps": sum(not entry["pinned"] for entry in entries),
        "uncheckable": len(uncheckable),
        "sources_failed": sum(item["status"].startswith("failed") for item in coverage),
        "sources_stale": sum(item["stale"] for item in coverage),
        "sources_not_checked": sum(item["status"] == NOT_CHECKED for item in coverage),
    }
    return {
        "model_id": model_id,
        "version": chosen,
        "produced_at": utc_text(now),
        "stale_after_hours": int(stale_after_hours)
        if float(stale_after_hours).is_integer()
        else stale_after_hours,
        "statement": STATEMENT,
        "summary": summary,
        "findings": {
            "state": state,
            "alerts": alerts,
            "watch_events": events,
        },
        "assurance": {"entries": assured, "undeclared_kinds": _undeclared(entries)},
        "coverage": {"sources": coverage, "uncheckable": uncheckable},
    }

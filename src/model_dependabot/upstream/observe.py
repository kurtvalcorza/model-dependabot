"""One observation per upstream item per source per run (data-model.md, Upstream observation).

An observation records what a source answered: its HTTP status, the outcome that status means for
that source and the fields the adapter read. A failed request (timeout, connection error, HTTP 5xx)
is not an answer, so it writes no observation and no evidence (FR-018).
"""

from __future__ import annotations

from typing import Any

from model_dependabot.sources.fetcher import Response, SourceFailedError
from model_dependabot.store import OUTCOMES, Store

HUB_SOURCES = frozenset({"hf-hub"})
NOT_FOUND_SOURCES = frozenset({"datacite", "crossref", "figshare", "zenodo"})
# Only DataCite's 404 means "no longer findable" (FR-006); a Crossref or Figshare 404 confirms
# nothing about removal, so it is a watch event (research U2, U6).
ALERTING_NOT_FOUND = frozenset({"datacite"})

__all__ = ["OUTCOMES", "effect_of", "observe", "outcome_for"]


def outcome_for(source: str, status: int) -> str | None:
    """The outcome of an HTTP status from ``source``, or ``None`` when it is a failed request."""
    if 200 <= status < 300:
        return "reachable"
    if 300 <= status < 400:
        return "redirected"
    if source in HUB_SOURCES and status in (401, 403, 404):
        return "refused"
    if source == "zenodo" and status == 410:
        return "removed"
    if source in NOT_FOUND_SOURCES and status == 404:
        return "not_found"
    return None


def effect_of(source: str, outcome: str) -> str | None:
    """What a ``not_found`` outcome may lead to: ``alert`` or ``watch_event``; else ``None``."""
    if outcome != "not_found":
        return None
    return "alert" if source in ALERTING_NOT_FOUND else "watch_event"


def observe(
    store: Store,
    run_id: int,
    source: str,
    item: str,
    answer: Response | SourceFailedError,
    *,
    detail: dict[str, Any] | None = None,
    **fields: Any,
) -> dict[str, Any] | None:
    """Store the answer as evidence and one observation; return it, or ``None`` on failure."""
    if isinstance(answer, SourceFailedError):
        return None
    outcome = outcome_for(source, answer.status)
    if outcome is None:
        return None
    evidence_id = store.add_response_evidence(
        answer, source=source, matched_identifier=item, detail=detail, run_id=run_id
    )
    observation_id = store.add_observation(
        run_id=run_id,
        source=source,
        item=item,
        http_status=answer.status,
        redirected_to=answer.redirected_to,
        outcome=outcome,
        evidence_ref=evidence_id,
        **fields,
    )
    return store.get_observation(observation_id)

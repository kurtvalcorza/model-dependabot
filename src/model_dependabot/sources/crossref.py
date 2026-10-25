"""Crossref: retraction notices for Crossref-registered DOIs (FR-004, research U2).

``GET https://api.crossref.org/works/{doi}`` lists the notices that update a work in
``updated-by[]``; Crossref merges the Retraction Watch database into the same list, so one request
per DOI covers both. An entry of type ``retraction``, ``withdrawal`` or ``removal`` is a retraction;
``expression_of_concern`` and ``correction`` are notices. A 404 confirms nothing about removal
(Crossref has no findability state), so it is only ever a watch event. Only DOIs whose registration
agency is Crossref are asked (research U1). Bodies arrive redacted (research U10).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

from model_dependabot.sources.fetcher import Fetcher, Response, SourceFailedError

SOURCE = "crossref"
WORKS_ENDPOINT = "https://api.crossref.org/works/"
RETRACTION_TYPES = ("retraction", "withdrawal", "removal")
NOTICE_TYPES = ("expression_of_concern", "correction")
ROLES = ("dataset", "paper")


def works_url(doi: str) -> str:
    return WORKS_ENDPOINT + quote(doi.lower(), safe="/")


def queried(agency: str | None) -> bool:
    """Whether a DOI of this registration agency is asked of Crossref."""
    return agency is not None and agency.strip().lower() == "crossref"


@dataclass(frozen=True)
class Update:
    """One ``updated-by`` entry: what kind of notice, from whom, its DOI and date."""

    type: str
    source: str | None
    notice_doi: str | None
    record_id: str | None
    date: str | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "source": self.source,
            "notice_doi": self.notice_doi,
            "record_id": self.record_id,
            "date": self.date,
        }


def _date(updated: Any) -> str | None:
    if not isinstance(updated, dict):
        return None
    moment = updated.get("date-time")
    if isinstance(moment, str) and moment:
        return moment[:10]
    parts = updated.get("date-parts")
    if isinstance(parts, list) and parts and isinstance(parts[0], list) and parts[0]:
        numbers = [int(n) for n in parts[0][:3]] + [1, 1]
        return f"{numbers[0]:04d}-{numbers[1]:02d}-{numbers[2]:02d}"
    return None


def _update(entry: dict[str, Any]) -> Update | None:
    kind = entry.get("type")
    if not isinstance(kind, str):
        return None
    notice = entry.get("DOI")
    record = entry.get("record-id")
    return Update(
        type=kind.strip().lower(),
        source=entry.get("source"),
        notice_doi=notice.lower() if isinstance(notice, str) else None,
        record_id=None if record is None else str(record),
        date=_date(entry.get("updated")),
    )


@dataclass(frozen=True)
class CrossrefWork:
    """What Crossref answered for one DOI."""

    doi: str
    response: Response
    outcome: str
    updates: tuple[Update, ...] = ()

    @property
    def retractions(self) -> tuple[Update, ...]:
        return tuple(u for u in self.updates if u.type in RETRACTION_TYPES)

    @property
    def notices(self) -> tuple[Update, ...]:
        return tuple(u for u in self.updates if u.type in NOTICE_TYPES)

    def alert_kind(self, role: str) -> str | None:
        """``dataset_retracted`` or ``paper_retracted`` when a retraction is listed, else None."""
        if self.outcome != "reachable" or not self.retractions:
            return None
        return "dataset_retracted" if role == "dataset" else "paper_retracted"

    def not_found_kind(self, role: str) -> str | None:
        """The watch event a 404 records: never an alert (FR-006 covers DataCite DOIs only)."""
        if self.outcome != "not_found":
            return None
        return "dataset_unreachable" if role == "dataset" else "paper_not_found"


def parse_work(doi: str, response: Response) -> CrossrefWork:
    if response.status == 404:
        return CrossrefWork(doi, response, "not_found")
    if response.status != 200:
        raise SourceFailedError(SOURCE, f"HTTP {response.status} for {doi}")
    try:
        message = json.loads(response.body)["message"]
    except (ValueError, KeyError, TypeError) as error:
        raise SourceFailedError(SOURCE, f"unreadable answer for {doi}: {error}") from None
    entries = (message.get("updated-by") or []) if isinstance(message, dict) else []
    updates = tuple(u for u in (_update(e) for e in entries if isinstance(e, dict)) if u)
    return CrossrefWork(doi, response, "reachable", updates)


class Crossref:
    """Read-only access to ``/works/{doi}``."""

    def __init__(self, fetcher: Fetcher) -> None:
        self.fetcher = fetcher

    def work(self, doi: str) -> CrossrefWork:
        return parse_work(doi, self.fetcher.get(works_url(doi)))

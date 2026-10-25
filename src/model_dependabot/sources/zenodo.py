"""Zenodo: removals from the records API tombstone (FR-005, research U4).

``GET https://zenodo.org/api/records/{id}`` answers 200 for a live record and 410 with a
``tombstone`` for a removed one; the tombstone's ``removal_date`` and ``removal_reason.id`` are the
evidence. ``removed_by``, ``note`` and ``citation_text`` are removed by the fetcher before anything
is stored (research U10). A 404 says only that the record is not there.

A DOI ``10.5281/zenodo.<digits>`` that doi.org does not know, or whose DataCite record is 404, is
still asked here with that record id (``record_id_from_doi``): the one exception to research U1's
rule against routing by prefix, recorded there and in U4.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, replace
from typing import Any
from urllib.parse import quote, urlsplit

from model_dependabot.sources.fetcher import Fetcher, Response, SourceFailedError

SOURCE = "zenodo"
RECORDS_ENDPOINT = "https://zenodo.org/api/records/"
ZENODO_DOI = re.compile(r"10\.5281/zenodo\.(\d+)", re.IGNORECASE)


def record_id_from_doi(doi: str) -> str | None:
    """The Zenodo record id a ``10.5281/zenodo.<digits>`` DOI names, or ``None``."""
    found = ZENODO_DOI.fullmatch(doi.strip())
    return found.group(1) if found else None


def record_url(record_id: str) -> str:
    return RECORDS_ENDPOINT + quote(str(record_id), safe="")


@dataclass(frozen=True)
class ZenodoRecord:
    """What Zenodo answered for one record."""

    record_id: str
    response: Response
    outcome: str
    removal: dict[str, Any] | None = None
    licence: str | None = None
    newer: str | None = None
    newer_response: Response | None = None
    # The newer version's declared licence, for the dataset_new_version watch event only.
    newer_licence: str | None = None
    newer_licence_response: Response | None = None
    newer_licence_error: str | None = None


def _licence(body: bytes) -> str | None:
    """``metadata.license.id`` of a record."""
    try:
        licence = (json.loads(body).get("metadata") or {}).get("license")
    except (ValueError, AttributeError):
        return None
    value = licence.get("id") if isinstance(licence, dict) else licence
    return value if isinstance(value, str) and value.strip() else None


def _removal(body: bytes) -> dict[str, Any]:
    try:
        tombstone = json.loads(body).get("tombstone") or {}
    except (ValueError, AttributeError):
        tombstone = {}
    reason = tombstone.get("removal_reason") if isinstance(tombstone, dict) else None
    return {
        "removal_date": tombstone.get("removal_date") if isinstance(tombstone, dict) else None,
        "removal_reason": reason.get("id") if isinstance(reason, dict) else reason,
    }


def latest_link(body: bytes) -> str | None:
    """``links.latest`` of a record that is not the last of its versions, else ``None`` (U3)."""
    try:
        record = json.loads(body)
    except ValueError:
        return None
    if not isinstance(record, dict):
        return None
    versions = ((record.get("metadata") or {}).get("relations") or {}).get("version") or []
    last = versions[0].get("is_last") if versions and isinstance(versions[0], dict) else None
    link = (record.get("links") or {}).get("latest")
    return link if last is False and isinstance(link, str) and link else None


def newest_record(response: Response) -> str | None:
    """The record id ``links.latest`` leads to: its redirect target, or the record it returns."""
    if 300 <= response.status < 400:
        path = urlsplit(response.redirected_to or "").path.rstrip("/")
        prefix = "/api/records/"
        return path[len(prefix) :] if path.startswith(prefix) else None
    if response.status == 200:
        try:
            value = json.loads(response.body).get("id")
        except (ValueError, AttributeError):
            return None
        return str(value) if value else None
    if response.status in (404, 410):
        return None
    raise SourceFailedError(SOURCE, f"HTTP {response.status} for {response.url}")


def parse_record(record_id: str, response: Response) -> ZenodoRecord:
    if response.status == 200:
        return ZenodoRecord(record_id, response, "reachable", licence=_licence(response.body))
    if response.status == 410:
        return ZenodoRecord(record_id, response, "removed", _removal(response.body))
    if response.status == 404:
        return ZenodoRecord(record_id, response, "not_found")
    raise SourceFailedError(SOURCE, f"HTTP {response.status} for record {record_id}")


class Zenodo:
    """Read-only access to ``/api/records/{id}``."""

    def __init__(self, fetcher: Fetcher) -> None:
        self.fetcher = fetcher

    def record(self, record_id: str) -> ZenodoRecord:
        """The record; for one that is not its last version, also where ``links.latest`` leads."""
        record = parse_record(record_id, self.fetcher.get(record_url(record_id)))
        link = latest_link(record.response.body) if record.outcome == "reachable" else None
        if link is None:
            return record
        latest = self.fetcher.get(link, follow_redirects=False)
        newer = newest_record(latest)
        newer = newer if newer != record_id else None
        if newer is None:
            return record
        return replace(
            record, newer=newer, newer_response=latest, **self._licence_of(newer, latest)
        )

    def _licence_of(self, newer: str, latest: Response) -> dict[str, Any]:
        """The newer version's declared licence: from ``links.latest``'s answer when it is the
        record, else from one request for the record. A failure leaves only its reason, so the
        watch event still names the newer version (FR-007)."""
        answer = latest
        if latest.status != 200:
            try:
                answer = self.fetcher.get(record_url(newer))
            except SourceFailedError as error:
                return {"newer_licence_error": error.reason}
        if answer.status != 200:
            return {"newer_licence_error": f"HTTP {answer.status} for record {newer}"}
        return {"newer_licence": _licence(answer.body), "newer_licence_response": answer}

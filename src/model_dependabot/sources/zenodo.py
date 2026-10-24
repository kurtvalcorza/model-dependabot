"""Zenodo: removals from the records API tombstone (FR-005, research U4).

``GET https://zenodo.org/api/records/{id}`` answers 200 for a live record and 410 with a
``tombstone`` for a removed one; the tombstone's ``removal_date`` and ``removal_reason.id`` are the
evidence. ``removed_by``, ``note`` and ``citation_text`` are removed by the fetcher before anything
is stored (research U10). A 404 says only that the record is not there.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

from model_dependabot.sources.fetcher import Fetcher, Response, SourceFailedError

SOURCE = "zenodo"
RECORDS_ENDPOINT = "https://zenodo.org/api/records/"


def record_url(record_id: str) -> str:
    return RECORDS_ENDPOINT + quote(str(record_id), safe="")


@dataclass(frozen=True)
class ZenodoRecord:
    """What Zenodo answered for one record."""

    record_id: str
    response: Response
    outcome: str
    removal: dict[str, Any] | None = None


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


def parse_record(record_id: str, response: Response) -> ZenodoRecord:
    if response.status == 200:
        return ZenodoRecord(record_id, response, "reachable")
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
        return parse_record(record_id, self.fetcher.get(record_url(record_id)))

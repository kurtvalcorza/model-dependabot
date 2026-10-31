"""OSV.dev adapter (research R2).

Candidate advisories come from ``POST /v1/querybatch`` (ecosystem ``PyPI``, normalised name, exact
version) and each record from ``GET /v1/vulns/{id}``. Only package entries with ``pinned`` true are
queried (FR-003); gaps are never matched. More than ``BATCH_LIMIT`` distinct packages are split into
several batch requests, and a result that carries ``next_page_token`` is followed by re-sending only
those queries with ``page_token`` set, for at most ``MAX_PAGES`` further rounds.
OSV leaves withdrawn records out of query answers, so a withdrawal is seen by fetching an open
alert's advisory by its id. A ``404`` for a record fetched by its id is an answer, not a failure:
OSV no longer has that record, and ``vuln`` returns a ``GoneRecord`` (review F1, amended
2026-10-31). Any other failure to read the source, any other error status or an answer that cannot
be read is a ``SourceFailedError`` for ``osv.dev`` (FR-016).
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from model_dependabot.sources.fetcher import Fetcher, Response, SourceFailedError

OSV_API = "https://api.osv.dev/v1"
SOURCE = "osv.dev"
ECOSYSTEM = "PyPI"
BATCH_LIMIT = 1000  # queries per querybatch request, as OSV documents
MAX_PAGES = 10  # follow-up rounds for paginated results before the source counts as failed


@dataclass(frozen=True)
class BatchAnswer:
    """Candidate advisory ids per package identifier, with the responses they came from.

    ``responses`` holds every querybatch response in request order; ``origin`` maps an identifier
    to the index of the response that first answered it (its evidence).
    """

    responses: tuple[Response, ...]
    matches: dict[str, list[str]]
    origin: dict[str, int] = field(default_factory=dict)

    @property
    def response(self) -> Response | None:
        """The first batch response, or ``None`` when nothing was queried."""
        return self.responses[0] if self.responses else None

    def response_for(self, identifier: str) -> Response | None:
        """The batch response that answered ``identifier``."""
        index = self.origin.get(identifier)
        return self.responses[index] if index is not None else self.response


@dataclass(frozen=True)
class VulnRecord:
    """One OSV record and the response it was read from (the evidence)."""

    advisory: dict[str, Any]
    response: Response


@dataclass(frozen=True)
class GoneRecord:
    """OSV answered ``404`` for a record fetched by its id: the record is gone (review F1).

    A gone record is neither withdrawn nor unaffected, so it never closes an alert; the 404
    response is kept as evidence of the answer.
    """

    advisory_id: str
    response: Response


def pinned_packages(entries: Iterable[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    """The package entries with an exact identifier, in inventory order (FR-003)."""
    return [entry for entry in entries if entry.get("kind") == "package" and entry.get("pinned")]


def aliases(advisory: Mapping[str, Any]) -> list[str]:
    return list(advisory.get("aliases") or [])


def withdrawn(advisory: Mapping[str, Any]) -> str | None:
    return advisory.get("withdrawn") or None


def _read(response: Response) -> Any:
    if response.status != 200:
        raise SourceFailedError(SOURCE, f"HTTP {response.status} for {response.url}")
    try:
        return json.loads(response.body)
    except ValueError as error:
        raise SourceFailedError(SOURCE, f"unreadable answer from {response.url}: {error}") from None


class OsvClient:
    """Reads OSV.dev through a ``Fetcher``; the batch query is the only POST."""

    def __init__(self, fetcher: Fetcher, api: str = OSV_API) -> None:
        self.fetcher = fetcher
        self.api = api

    def query(self, entries: Iterable[Mapping[str, Any]]) -> BatchAnswer:
        packages = sorted(
            {
                (entry["name"], entry["version"], entry["identifier"])
                for entry in pinned_packages(entries)
            }
        )
        if not packages:
            return BatchAnswer((), {})
        responses: list[Response] = []
        matches: dict[str, set[str]] = {identifier: set() for _, _, identifier in packages}
        origin: dict[str, int] = {}
        # (name, version, identifier, page token or None) still to ask about
        pending: list[tuple[str, str, str, str | None]] = [(*package, None) for package in packages]
        rounds = 0
        while pending:
            if rounds > MAX_PAGES:
                raise SourceFailedError(
                    SOURCE, f"answers still paginated after {MAX_PAGES} follow-up rounds"
                )
            follow: list[tuple[str, str, str, str | None]] = []
            for start in range(0, len(pending), BATCH_LIMIT):
                chunk = pending[start : start + BATCH_LIMIT]
                response, results = self._post_batch(chunk)
                responses.append(response)
                for (name, version, identifier, _), result in zip(chunk, results, strict=True):
                    origin.setdefault(identifier, len(responses) - 1)
                    matches[identifier].update(vuln["id"] for vuln in result.get("vulns") or [])
                    token = result.get("next_page_token")
                    if token:
                        follow.append((name, version, identifier, token))
            pending = follow
            rounds += 1
        return BatchAnswer(
            tuple(responses),
            {identifier: sorted(ids) for identifier, ids in matches.items()},
            origin,
        )

    def _post_batch(
        self, chunk: list[tuple[str, str, str, str | None]]
    ) -> tuple[Response, list[Mapping[str, Any]]]:
        queries = []
        for name, version, _, token in chunk:
            query: dict[str, Any] = {
                "package": {"name": name, "ecosystem": ECOSYSTEM},
                "version": version,
            }
            if token is not None:
                query["page_token"] = token
            queries.append(query)
        body = json.dumps({"queries": queries}, separators=(",", ":")).encode("utf-8")
        response = self.fetcher.post(f"{self.api}/querybatch", body)
        answer = _read(response)
        results = answer.get("results") if isinstance(answer, dict) else None
        if not isinstance(results, list) or len(results) != len(chunk):
            raise SourceFailedError(SOURCE, "the batch answer does not match the queries")
        if not all(isinstance(result, dict) for result in results):
            raise SourceFailedError(SOURCE, "the batch answer holds a result that is not an object")
        return response, results

    def vuln(self, advisory_id: str) -> VulnRecord | GoneRecord:
        response = self.fetcher.get(f"{self.api}/vulns/{advisory_id}")
        if response.status == 404:
            return GoneRecord(advisory_id, response)
        advisory = _read(response)
        if not isinstance(advisory, dict) or advisory.get("id") != advisory_id:
            raise SourceFailedError(SOURCE, f"the record for {advisory_id} is not that advisory")
        return VulnRecord(advisory, response)

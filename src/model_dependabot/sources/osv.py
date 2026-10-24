"""OSV.dev adapter (research R2).

Candidate advisories come from ``POST /v1/querybatch`` (ecosystem ``PyPI``, normalised name, exact
version) and each record from ``GET /v1/vulns/{id}``. Only package entries with ``pinned`` true are
queried (FR-003); gaps are never matched. OSV leaves withdrawn records out of query answers, so a
withdrawal is seen by fetching an open alert's advisory by its id. Any failure to read the
source, an error status or an answer that cannot be read is a ``SourceFailedError`` for
``osv.dev`` (FR-016).
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from model_dependabot.sources.fetcher import Fetcher, Response, SourceFailedError

OSV_API = "https://api.osv.dev/v1"
SOURCE = "osv.dev"
ECOSYSTEM = "PyPI"
BATCH_LIMIT = 1000  # queries per querybatch request, as OSV documents


@dataclass(frozen=True)
class BatchAnswer:
    """Candidate advisory ids per package identifier, with the response they came from."""

    response: Response | None
    matches: dict[str, list[str]]


@dataclass(frozen=True)
class VulnRecord:
    """One OSV record and the response it was read from (the evidence)."""

    advisory: dict[str, Any]
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
            return BatchAnswer(None, {})
        if len(packages) > BATCH_LIMIT:
            raise SourceFailedError(SOURCE, f"{len(packages)} packages exceed one batch")
        query = {
            "queries": [
                {"package": {"name": name, "ecosystem": ECOSYSTEM}, "version": version}
                for name, version, _ in packages
            ]
        }
        body = json.dumps(query, separators=(",", ":")).encode("utf-8")
        response = self.fetcher.post(f"{self.api}/querybatch", body)
        results = _read(response).get("results")
        if not isinstance(results, list) or len(results) != len(packages):
            raise SourceFailedError(SOURCE, "the batch answer does not match the queries")
        matches: dict[str, list[str]] = {}
        for (_, _, identifier), result in zip(packages, results, strict=True):
            if result.get("next_page_token"):
                raise SourceFailedError(SOURCE, f"the answer for {identifier} is paginated")
            matches[identifier] = sorted(vuln["id"] for vuln in result.get("vulns") or [])
        return BatchAnswer(response, matches)

    def vuln(self, advisory_id: str) -> VulnRecord:
        response = self.fetcher.get(f"{self.api}/vulns/{advisory_id}")
        advisory = _read(response)
        if not isinstance(advisory, dict) or advisory.get("id") != advisory_id:
            raise SourceFailedError(SOURCE, f"the record for {advisory_id} is not that advisory")
        return VulnRecord(advisory, response)

"""DataCite: findability of DataCite DOIs and their repository (FR-006, research U1, U3).

``GET https://api.datacite.org/dois/{doi}``: a 404 means the DOI is no longer findable (DataCite
moves retracted or unpublished content from ``findable`` to ``registered``, and registered DOIs
leave the public API). The record's ``url`` routes the dataset to its repository: ``zenodo.org``
to Zenodo, ``figshare.com`` or a ``*.figshare.com`` portal to Figshare, anything else to
``other``. Only DOIs whose registration agency is DataCite are asked. Bodies arrive redacted
(research U10).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.parse import quote, urlsplit

from model_dependabot.doi import normalise_doi
from model_dependabot.sources.fetcher import (
    Fetcher,
    NoRecordingError,
    Response,
    SourceFailedError,
)
from model_dependabot.store import Store

SOURCE = "datacite"
DOIS_ENDPOINT = "https://api.datacite.org/dois/"


def doi_url(doi: str) -> str:
    return DOIS_ENDPOINT + quote(doi.lower(), safe="/")


def queried(agency: str | None) -> bool:
    """Whether a DOI of this registration agency is asked of DataCite."""
    return agency is not None and agency.strip().lower() == "datacite"


def _zenodo_id(segments: list[str]) -> str | None:
    for marker in ("records", "record"):
        if marker in segments:
            index = segments.index(marker)
            if index + 1 < len(segments) and segments[index + 1].isdigit():
                return segments[index + 1]
    return None


def _figshare_id(segments: list[str]) -> str | None:
    """The article id: the last numeric segment, or the one before a trailing version number."""
    if "articles" not in segments:
        return None
    after = segments[segments.index("articles") + 1 :]
    if len(after) >= 2 and after[-1].isdigit() and after[-2].isdigit():
        return after[-2]
    numbers = [segment for segment in after if segment.isdigit()]
    return numbers[-1] if numbers else None


def route(url: str) -> tuple[str, str | None]:
    """The repository (``zenodo``, ``figshare`` or ``other``) a landing URL names, and its id."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    segments = [segment for segment in parts.path.split("/") if segment]
    if host in ("zenodo.org", "www.zenodo.org"):
        return "zenodo", _zenodo_id(segments)
    if host == "figshare.com" or host.endswith(".figshare.com"):
        return "figshare", _figshare_id(segments)
    return "other", None


@dataclass(frozen=True)
class DataciteRecord:
    """What DataCite answered for one DOI."""

    doi: str
    response: Response
    outcome: str
    url: str | None = None
    repository: str | None = None
    repository_id: str | None = None


def parse_record(doi: str, response: Response) -> DataciteRecord:
    if response.status == 404:
        return DataciteRecord(doi, response, "not_found")
    if response.status != 200:
        raise SourceFailedError(SOURCE, f"HTTP {response.status} for {doi}")
    try:
        attributes = json.loads(response.body)["data"]["attributes"]
    except (ValueError, KeyError, TypeError) as error:
        raise SourceFailedError(SOURCE, f"unreadable answer for {doi}: {error}") from None
    url = attributes.get("url") if isinstance(attributes, dict) else None
    if not isinstance(url, str) or not url:
        return DataciteRecord(doi, response, "reachable", None, "other", None)
    repository, repository_id = route(url)
    return DataciteRecord(doi, response, "reachable", url, repository, repository_id)


class DataCite:
    """Read-only access to ``/dois/{doi}``."""

    def __init__(self, fetcher: Fetcher) -> None:
        self.fetcher = fetcher

    def record(self, doi: str) -> DataciteRecord:
        return parse_record(doi, self.fetcher.get(doi_url(doi)))


def remember_repository(store: Store, record: DataciteRecord) -> None:
    """Store the repository a findable record names (data-model.md, DOI routing)."""
    if record.outcome == "reachable" and record.repository is not None:
        store.set_routing(
            record.doi, repository=record.repository, repository_id=record.repository_id
        )


def ensure_repository(store: Store, fetcher: Fetcher, doi: str) -> None:
    """At registration: route a DataCite DOI to its repository once; a failure is tried later."""
    doi = normalise_doi(doi) or doi.lower()
    routing = store.get_routing(doi)
    if routing is None or not queried(routing["agency"]) or routing["repository"]:
        return
    try:
        record = DataCite(fetcher).record(doi)
    except (SourceFailedError, NoRecordingError):
        return
    remember_repository(store, record)

"""Which registration agency a DOI belongs to (research U1).

``GET https://doi.org/doiRA/{doi}`` answers ``[{"DOI": "…", "RA": "DataCite"}]``. An agency never
changes for a DOI, so it is looked up once (at registration) and cached in the store's DOI routing;
a failed lookup leaves the agency empty and is tried again next time.
"""

from __future__ import annotations

import json
from urllib.parse import quote

from model_dependabot.doi import normalise_doi
from model_dependabot.sources.fetcher import Fetcher, NoRecordingError, SourceFailedError
from model_dependabot.store import Store

DOI_RA_ENDPOINT = "https://doi.org/doiRA/"


def doi_ra_url(doi: str) -> str:
    return DOI_RA_ENDPOINT + quote(doi.lower(), safe="/")


def lookup_agency(fetcher: Fetcher, doi: str) -> str | None:
    """The agency ``doiRA`` names for ``doi``, or ``None`` if the lookup failed or named none."""
    try:
        response = fetcher.get(doi_ra_url(doi))
    except (SourceFailedError, NoRecordingError):
        return None
    if response.status != 200:
        return None
    try:
        answer = json.loads(response.body)
    except ValueError:
        return None
    if isinstance(answer, list) and answer and isinstance(answer[0], dict):
        agency = answer[0].get("RA")
        if isinstance(agency, str) and agency.strip():
            return agency.strip()
    return None


def ensure_agency(store: Store, fetcher: Fetcher, doi: str) -> str | None:
    """The cached agency of ``doi``, looking it up only while it is unknown."""
    doi = normalise_doi(doi) or doi.lower()
    routing = store.get_routing(doi)
    if routing is not None and routing["agency"]:
        return str(routing["agency"])
    agency = lookup_agency(fetcher, doi)
    store.set_routing(doi, agency=agency)
    return agency

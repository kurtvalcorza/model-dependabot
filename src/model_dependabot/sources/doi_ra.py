"""Which registration agency a DOI belongs to (research U1).

``GET https://doi.org/doiRA/{doi}`` answers ``[{"DOI": "…", "RA": "DataCite"}]``. An agency never
changes for a DOI, so it is looked up once (at registration) and cached in the store's DOI routing;
a failed lookup leaves the agency empty and is tried again next time.

For a DOI no agency has registered, doi.org answers ``[{"DOI": "…", "status": "DOI does not
exist"}]``. That is a definite answer, not a failed lookup: it is stored as the agency
``NOT_REGISTERED`` and asked again at most once per check run, in case the DOI is registered later
(data-model.md, DOI routing).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.parse import quote

from model_dependabot.doi import normalise_doi
from model_dependabot.sources.fetcher import (
    Fetcher,
    NoRecordingError,
    Response,
    SourceFailedError,
)
from model_dependabot.store import Store

DOI_RA_ENDPOINT = "https://doi.org/doiRA/"
SOURCE = "doi-ra"
# The stored agency of a DOI doi.org reports as not existing.
NOT_REGISTERED = "none"
DOES_NOT_EXIST = "doi does not exist"


def doi_ra_url(doi: str) -> str:
    return DOI_RA_ENDPOINT + quote(doi.lower(), safe="/")


@dataclass(frozen=True)
class AgencyAnswer:
    """What doi.org answered: an agency, ``NOT_REGISTERED``, or ``None`` when the lookup failed."""

    agency: str | None
    response: Response | None = None


def ask_agency(fetcher: Fetcher, doi: str) -> AgencyAnswer:
    """Ask doi.org which agency registered ``doi``."""
    try:
        response = fetcher.get(doi_ra_url(doi))
    except (SourceFailedError, NoRecordingError):
        return AgencyAnswer(None)
    if response.status != 200:
        return AgencyAnswer(None)
    try:
        answer = json.loads(response.body)
    except ValueError:
        return AgencyAnswer(None)
    if isinstance(answer, list) and answer and isinstance(answer[0], dict):
        agency = answer[0].get("RA")
        if isinstance(agency, str) and agency.strip():
            return AgencyAnswer(agency.strip(), response)
        status = answer[0].get("status")
        if isinstance(status, str) and status.strip().lower() == DOES_NOT_EXIST:
            return AgencyAnswer(NOT_REGISTERED, response)
    return AgencyAnswer(None)


def lookup_agency(fetcher: Fetcher, doi: str) -> str | None:
    """The agency ``doiRA`` names for ``doi``, ``NOT_REGISTERED``, or ``None`` if it failed."""
    return ask_agency(fetcher, doi).agency


def unknown(agency: str | None) -> bool:
    """Whether no agency is known for the DOI: the lookup failed or the DOI does not exist."""
    return agency is None or agency == NOT_REGISTERED


def refresh_agency(
    store: Store, fetcher: Fetcher, doi: str, *, recheck_unregistered: bool = False
) -> AgencyAnswer | None:
    """Look ``doi`` up while its agency is unknown; doi.org's answer, or ``None`` if not asked.

    A known agency is never asked again. ``NOT_REGISTERED`` is asked again only when
    ``recheck_unregistered`` is set (once per check run). A failed lookup never replaces a stored
    answer.
    """
    doi = normalise_doi(doi) or doi.lower()
    routing = store.get_routing(doi)
    stored = None if routing is None else routing["agency"]
    if stored is not None and (stored != NOT_REGISTERED or not recheck_unregistered):
        return None
    answer = ask_agency(fetcher, doi)
    if answer.agency is not None or routing is None:
        store.set_routing(doi, agency=answer.agency)
    return answer


def ensure_agency(store: Store, fetcher: Fetcher, doi: str) -> str | None:
    """The cached agency of ``doi``, looking it up only while it is unknown."""
    doi = normalise_doi(doi) or doi.lower()
    refresh_agency(store, fetcher, doi)
    routing = store.get_routing(doi)
    return None if routing is None else routing["agency"]

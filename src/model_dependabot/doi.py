"""DOI normalisation, shared by the manifest, the inventory builder and the DOI sources."""

from __future__ import annotations

import re

_DOI = re.compile(r"^10\.\d{4,9}/\S+$")
_DOI_PREFIXES = ("https://doi.org/", "http://doi.org/", "https://dx.doi.org/", "doi:")


def normalise_doi(text: str) -> str | None:
    """A DOI in its bare, lower-case form, or ``None`` if the text is not a DOI."""
    doi = text.strip()
    for prefix in _DOI_PREFIXES:
        if doi.lower().startswith(prefix):
            doi = doi[len(prefix) :]
            break
    doi = doi.lower()
    return doi if _DOI.match(doi) else None

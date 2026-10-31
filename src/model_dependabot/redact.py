"""Personal data removed from source responses before they are stored (research U10).

Feature 001 keeps every response as evidence. Some upstream responses can name people, so for those
sources the stored body is a copy with the listed fields removed, and the evidence keeps the SHA-256
of the response as received (``original_sha256``), the SHA-256 of the stored body (``body_sha256``)
and the fields removed (``redacted_fields``). A body with nothing to remove is stored unchanged, so
its two hashes are equal and ``redacted_fields`` is empty.

One rule set per source name:

- ``hf-takedowns`` (the takedown log ``index.csv``): the ``requesting_entity`` and ``file`` columns
  (a notice's file name can name the requesting party), leaving ``date`` and ``reported_content``;
- ``zenodo``: ``removed_by``, ``note`` and ``citation_text`` of the tombstone, the record's
  ``metadata.creators`` and ``metadata.contributors`` and its ``owners``;
- ``figshare``: ``authors`` and ``citation``, wherever they appear in the article;
- ``crossref`` and ``datacite``: ``author``, ``creators``, ``contributors`` and ``editor``, wherever
  they appear in the record (so a Crossref ``reference[].author`` goes too); Crossref also loses the
  free-text ``reference[].unstructured`` of each reference, keeping the rest of it;
- ``hf-hub`` (model and dataset info): nothing, as ``author`` is the repository namespace.

The takedown log's rule is applied to every hop of a request for the log, whatever host a redirect
leads to (the fetcher passes the source of the URL asked for), and it fails closed: a log body that
cannot be read as UTF-8 CSV raises ``RedactionError`` and is never stored (review F4, amended
2026-10-31).
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

TAKEDOWN_COLUMNS = ("requesting_entity", "file")
TOMBSTONE_FIELDS = ("removed_by", "note", "citation_text")
ZENODO_METADATA_FIELDS = ("creators", "contributors")
ZENODO_RECORD_FIELDS = ("owners",)
FIGSHARE_FIELDS = ("authors", "citation")
PERSON_FIELDS = ("author", "creators", "contributors", "editor")
CROSSREF_REFERENCE_TEXT = "unstructured"

# What each source loses, as the labels ``redacted_fields`` uses.
RULES: dict[str, tuple[str, ...]] = {
    "hf-takedowns": TAKEDOWN_COLUMNS,
    "zenodo": TOMBSTONE_FIELDS
    + tuple(f"metadata.{key}" for key in ZENODO_METADATA_FIELDS)
    + ZENODO_RECORD_FIELDS,
    "figshare": FIGSHARE_FIELDS,
    "crossref": (*PERSON_FIELDS, f"reference[].{CROSSREF_REFERENCE_TEXT}"),
    "datacite": PERSON_FIELDS,
    "hf-hub": (),
}

# The log's ``/resolve/main/index.csv`` answers 307 to ``/api/resolve-cache/datasets/<same repo>/…``
# (recorded 2026-10-24), so the rule matches the repository anywhere in a hub path.
TAKEDOWN_LOG_REPO = "/datasets/huggingface-legal/takedown-notices/"


class RedactionError(ValueError):
    """A body that a redaction rule applies to but that cannot be redacted; it must not be kept."""


@dataclass(frozen=True)
class Redacted:
    """A body as it may be stored, with both hashes and the fields removed."""

    body: bytes
    original_sha256: str
    body_sha256: str
    redacted_fields: tuple[str, ...]


def source_for_url(url: str) -> str | None:
    """The upstream source a request URL belongs to, or ``None`` for feature 001's sources."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    path = parts.path
    if host == "api.crossref.org":
        return "crossref"
    if host == "api.datacite.org":
        return "datacite"
    if host == "zenodo.org" and path.startswith("/api/"):
        return "zenodo"
    if host == "api.figshare.com":
        return "figshare"
    if host == "doi.org" and path.startswith("/doiRA/"):
        return "doi-ra"
    if host == "huggingface.co":
        if TAKEDOWN_LOG_REPO in path:
            return "hf-takedowns"
        if path.startswith("/api/"):
            return "hf-hub"
    return None


def _sha256(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def _drop_keys(value: Any, keys: frozenset[str], removed: set[str]) -> Any:
    if isinstance(value, dict):
        kept = {}
        for key, item in value.items():
            if key in keys:
                removed.add(key)
                continue
            kept[key] = _drop_keys(item, keys, removed)
        return kept
    if isinstance(value, list):
        return [_drop_keys(item, keys, removed) for item in value]
    return value


def _pop(mapping: Any, keys: tuple[str, ...], removed: set[str], prefix: str = "") -> None:
    if isinstance(mapping, dict):
        for key in keys:
            if key in mapping:
                del mapping[key]
                removed.add(prefix + key)


def _drop_reference_text(value: Any, removed: set[str], *, in_reference: bool = False) -> None:
    if isinstance(value, dict):
        if in_reference and CROSSREF_REFERENCE_TEXT in value:
            del value[CROSSREF_REFERENCE_TEXT]
            removed.add(f"reference[].{CROSSREF_REFERENCE_TEXT}")
        for key, item in value.items():
            _drop_reference_text(item, removed, in_reference=key == "reference")
    elif isinstance(value, list):
        for item in value:
            _drop_reference_text(item, removed, in_reference=in_reference)


def _redact_document(source: str, document: Any, removed: set[str]) -> Any:
    if source == "zenodo":
        if isinstance(document, dict):
            _pop(document.get("tombstone"), TOMBSTONE_FIELDS, removed)
            _pop(document.get("metadata"), ZENODO_METADATA_FIELDS, removed, "metadata.")
            _pop(document, ZENODO_RECORD_FIELDS, removed)
        return document
    if source == "figshare":
        return _drop_keys(document, frozenset(FIGSHARE_FIELDS), removed)
    document = _drop_keys(document, frozenset(PERSON_FIELDS), removed)
    if source == "crossref":
        _drop_reference_text(document, removed)
    return document


def _redact_json(source: str, body: bytes) -> tuple[bytes, set[str]]:
    try:
        document = json.loads(body)
    except ValueError:
        return body, set()
    removed: set[str] = set()
    document = _redact_document(source, document, removed)
    if not removed:
        return body, removed
    text = json.dumps(document, ensure_ascii=False, separators=(",", ":"))
    return text.encode("utf-8"), removed


def _redact_csv(body: bytes) -> tuple[bytes, set[str]]:
    try:
        text = body.decode("utf-8-sig")
        rows = list(csv.reader(io.StringIO(text, newline="")))
    except (UnicodeDecodeError, csv.Error) as error:
        raise RedactionError(f"the takedown log cannot be redacted: {error}") from None
    if not rows:
        return body, set()
    removed = {column for column in TAKEDOWN_COLUMNS if column in rows[0]}
    if not removed:
        return body, set()
    keep = [index for index, column in enumerate(rows[0]) if column not in removed]
    out = io.StringIO(newline="")
    writer = csv.writer(out, lineterminator="\n")
    for row in rows:
        writer.writerow([row[index] for index in keep if index < len(row)])
    return out.getvalue().encode("utf-8"), removed


def redact(source: str | None, body: bytes) -> Redacted:
    """The storable form of ``body`` under the rule set for ``source``.

    Raises ``RedactionError`` when ``source`` is ``hf-takedowns`` and the body is not readable CSV.
    """
    original = _sha256(body)
    rule = RULES.get(source or "", ())
    removed: set[str] = set()
    stored = body
    if rule and source == "hf-takedowns":
        stored, removed = _redact_csv(body)
    elif rule and source:
        stored, removed = _redact_json(source, body)
    return Redacted(stored, original, _sha256(stored), tuple(sorted(removed)))

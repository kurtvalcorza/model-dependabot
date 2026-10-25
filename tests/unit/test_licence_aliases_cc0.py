"""CC0 spellings of Zenodo and DataCite (held-out scoring 2026-10-25, research U8).

Zenodo declares CC0 as ``metadata.license.id`` ``cc-zero`` and DataCite as the rights text
``Creative Commons Zero - CC0 1.0``. No recording has either, so each is derived from a recorded
answer (``zenodo/record-3242074``, ``datacite/findable``) with only the licence changed.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

from conftest import fixture_json
from model_dependabot.sources import datacite, zenodo
from model_dependabot.sources.fetcher import Response
from model_dependabot.upstream.licences import normalise


def _response(url: str, body: object) -> Response:
    moment = datetime(2026, 10, 25, tzinfo=UTC)
    return Response(200, json.dumps(body).encode("utf-8"), url, moment)


def test_zenodo_cc_zero_normalises_to_cc0() -> None:
    body = fixture_json("zenodo/record-3242074")
    body["metadata"]["license"] = {"id": "cc-zero"}
    record = zenodo.parse_record("3242074", _response(zenodo.record_url("3242074"), body))
    assert record.licence == "cc-zero"
    licence = normalise(record.licence)
    assert (licence.normalised, licence.form) == ("CC0-1.0", "spdx")


def test_datacite_creative_commons_zero_text_normalises_to_cc0() -> None:
    body = fixture_json("datacite/findable")
    rights = body["data"]["attributes"]["rightsList"]
    rights[0] = {"rights": "Creative Commons Zero - CC0 1.0"}
    doi = body["data"]["attributes"]["doi"]
    record = datacite.parse_record(doi, _response(datacite.doi_url(doi), body))
    assert record.licence == "Creative Commons Zero - CC0 1.0"
    licence = normalise(record.licence)
    assert (licence.normalised, licence.form) == ("CC0-1.0", "spdx")


def test_the_cc0_aliases_match_ignoring_case() -> None:
    assert normalise("CC-ZERO").normalised == "CC0-1.0"
    assert normalise("creative commons zero - cc0 1.0").normalised == "CC0-1.0"

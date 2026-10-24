"""Zenodo removals: the records API tombstone (T022; FR-005, research U4, U10)."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from model_dependabot.sources.fetcher import RecordedFetcher
from model_dependabot.sources.zenodo import Zenodo, record_url
from model_dependabot.store import Store

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def test_the_record_url() -> None:
    assert record_url("3242074") == "https://zenodo.org/api/records/3242074"


def test_200_is_reachable_with_no_removal() -> None:
    record = Zenodo(RecordedFetcher(FIXTURES / "zenodo")).record("3242074")
    assert (record.outcome, record.removal) == ("reachable", None)


def test_410_is_removed_with_the_tombstone_date_and_reason() -> None:
    record = Zenodo(RecordedFetcher(FIXTURES / "zenodo")).record("12584226")
    assert record.outcome == "removed"
    assert record.removal == {
        "removal_date": "2024-08-26T14:40:13.975857",
        "removal_reason": "duplicate",
    }


def test_removed_by_note_and_citation_text_are_not_stored(
    derive_upstream: Callable[..., Path], tmp_path: Path
) -> None:
    def change(body: dict) -> dict:
        body["tombstone"] |= {
            "removed_by": {"user": "fixture-remover"},
            "note": "fixture note naming someone",
            "citation_text": "Fixturename, A. (2024). A record.",
        }
        return body

    root = derive_upstream(changes={"zenodo/deleted": change})
    record = Zenodo(RecordedFetcher(root / "zenodo")).record("12584226")
    with Store(tmp_path / "md.db") as store:
        evidence_id = store.add_response_evidence(
            record.response, source="zenodo", matched_identifier="x"
        )
        evidence = store.get_evidence(evidence_id)
        assert evidence is not None
        stored = store.read_body(evidence["body_sha256"])
    for text in (b"fixture-remover", b"fixture note", b"Fixturename"):
        assert text not in stored
    assert {"citation_text", "note", "removed_by"} <= set(evidence["redacted_fields"])
    assert record.removal is not None and record.removal["removal_reason"] == "duplicate"


@pytest.mark.parametrize(
    ("doi", "record_id"),
    [
        ("10.5281/zenodo.12584226", "12584226"),
        ("10.5281/ZENODO.3242074", "3242074"),
        ("10.5281/model-dependabot-fixture-does-not-exist", None),
        ("10.5281/zenodo.12584226.v2", None),
        ("10.1234/zenodo.12584226", None),
    ],
)
def test_only_a_zenodo_doi_names_a_record_id(doi: str, record_id: str | None) -> None:
    from model_dependabot.sources.zenodo import record_id_from_doi

    assert record_id_from_doi(doi) == record_id

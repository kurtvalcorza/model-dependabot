"""Crossref retraction notices (T020; FR-004, research U2, U10)."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from model_dependabot.sources.crossref import (
    NOTICE_TYPES,
    RETRACTION_TYPES,
    Crossref,
    queried,
    works_url,
)
from model_dependabot.sources.fetcher import RecordedFetcher
from model_dependabot.store import Store

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
RETRACTED = "10.1177/1758835919874651"
NOTICE = "10.1177/17588359211061903"
CORRECTED = "10.1088/1361-6595/aaebdb"
CONCERN = "10.1016/j.lungcan.2003.10.006"


def crossref(root: Path = FIXTURES / "crossref") -> Crossref:
    return Crossref(RecordedFetcher(root))


def test_the_works_url_names_the_doi() -> None:
    assert works_url(RETRACTED) == f"https://api.crossref.org/works/{RETRACTED}"


def test_retraction_entries_become_findings_with_notice_source_record_id_and_date() -> None:
    work = crossref().work(RETRACTED)
    assert work.outcome == "reachable"
    found = {(u.type, u.source, u.notice_doi, u.record_id, u.date) for u in work.retractions}
    assert found == {
        ("retraction", "retraction-watch", NOTICE, "34999", "2021-12-15"),
        ("retraction", "publisher", NOTICE, None, "2021-12-15"),
    }
    assert work.notices == ()
    assert work.alert_kind("dataset") == "dataset_retracted"
    assert work.alert_kind("paper") == "paper_retracted"
    assert work.not_found_kind("paper") is None


@pytest.mark.parametrize("kind", ["withdrawal", "removal"])
def test_withdrawal_and_removal_count_as_retractions(
    derive_upstream: Callable[..., Path], kind: str
) -> None:
    def change(body: dict) -> dict:
        body["message"]["updated-by"] = body["message"]["updated-by"][:1]
        body["message"]["updated-by"][0]["type"] = kind
        return body

    root = derive_upstream(changes={"crossref/retracted": change})
    work = crossref(root / "crossref").work(RETRACTED)
    assert [u.type for u in work.retractions] == [kind]
    assert kind in RETRACTION_TYPES


@pytest.mark.parametrize(
    ("doi", "kind"), [(CORRECTED, "correction"), (CONCERN, "expression_of_concern")]
)
def test_corrections_and_concerns_are_notices_not_retractions(doi: str, kind: str) -> None:
    work = crossref().work(doi)
    assert work.retractions == ()
    assert {u.type for u in work.notices} == {kind}
    assert kind in NOTICE_TYPES
    assert work.alert_kind("dataset") is None


def test_an_unretracted_work_lists_nothing() -> None:
    work = crossref().work("10.1038/nature14539")
    assert (work.outcome, work.updates, work.alert_kind("paper")) == ("reachable", (), None)


def test_a_404_is_not_found_and_only_ever_a_watch_event() -> None:
    work = crossref().work("10.1177/model-dependabot-fixture-does-not-exist")
    assert work.outcome == "not_found"
    assert work.alert_kind("dataset") is None and work.alert_kind("paper") is None
    assert work.not_found_kind("dataset") == "dataset_unreachable"
    assert work.not_found_kind("paper") == "paper_not_found"


def test_author_fields_never_reach_the_stored_evidence(
    derive_upstream: Callable[..., Path], tmp_path: Path
) -> None:
    def change(body: dict) -> dict:
        body["message"]["author"] = [{"given": "Fixture", "family": "Personname"}]
        body["message"]["editor"] = [{"given": "Fixture", "family": "Editorname"}]
        return body

    root = derive_upstream(changes={"crossref/retracted": change})
    work = crossref(root / "crossref").work(RETRACTED)
    with Store(tmp_path / "md.db") as store:
        evidence_id = store.add_response_evidence(
            work.response, source="crossref", matched_identifier=RETRACTED
        )
        evidence = store.get_evidence(evidence_id)
        assert evidence is not None
        stored = store.read_body(evidence["body_sha256"])
    assert b"Personname" not in stored and b"Editorname" not in stored
    assert {"author", "editor"} <= set(evidence["redacted_fields"])


@pytest.mark.parametrize(
    ("agency", "expected"),
    [("Crossref", True), ("crossref", True), ("DataCite", False), (None, False), ("mEDRA", False)],
)
def test_only_crossref_agency_dois_are_queried(agency: str | None, expected: bool) -> None:
    assert queried(agency) is expected

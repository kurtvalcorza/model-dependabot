"""DataCite findability and repository routing (T021; FR-006, research U1, U3)."""

from __future__ import annotations

from pathlib import Path

import pytest

from model_dependabot.sources.datacite import DataCite, doi_url, queried, route
from model_dependabot.sources.fetcher import RecordedFetcher

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def datacite() -> DataCite:
    return DataCite(RecordedFetcher(FIXTURES / "datacite"))


def test_the_doi_url() -> None:
    expected = "https://api.datacite.org/dois/10.5281/zenodo.3242074"
    assert doi_url("10.5281/zenodo.3242074") == expected


def test_a_findable_zenodo_doi_routes_to_zenodo_with_its_record_id() -> None:
    record = datacite().record("10.5281/zenodo.3242074")
    assert record.outcome == "reachable"
    assert record.url == "https://zenodo.org/record/3242074"
    assert (record.repository, record.repository_id) == ("zenodo", "3242074")


def test_a_figshare_doi_routes_to_figshare_with_its_article_id() -> None:
    record = datacite().record("10.6084/m9.figshare.29500136.v2")
    assert (record.repository, record.repository_id) == ("figshare", "29500136")


def test_another_repository_routes_to_other() -> None:
    record = datacite().record("10.1594/pangaea.958394")
    assert (record.repository, record.repository_id) == ("other", None)


def test_a_404_is_not_found() -> None:
    record = datacite().record("10.5281/model-dependabot-fixture-does-not-exist")
    assert record.outcome == "not_found"
    assert record.repository is None


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://zenodo.org/records/12584226", ("zenodo", "12584226")),
        ("https://zenodo.org/record/3242074", ("zenodo", "3242074")),
        ("https://figshare.com/articles/dataset/name/29500136/2", ("figshare", "29500136")),
        ("https://figshare.com/articles/dataset/name/29500136", ("figshare", "29500136")),
        ("https://springernature.figshare.com/articles/dataset/x/7104383", ("figshare", "7104383")),
        ("https://doi.pangaea.de/10.1594/PANGAEA.958394", ("other", None)),
        ("https://notfigshare.com/articles/1", ("other", None)),
    ],
)
def test_routing_by_url(url: str, expected: tuple[str, str | None]) -> None:
    assert route(url) == expected


@pytest.mark.parametrize(
    ("agency", "expected"),
    [("DataCite", True), ("datacite", True), ("Crossref", False), (None, False)],
)
def test_only_datacite_agency_dois_are_queried(agency: str | None, expected: bool) -> None:
    assert queried(agency) is expected

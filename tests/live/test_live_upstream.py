"""Live smoke tests for the upstream sources of feature 002 (T058; quickstart.md section 8).

One live answer per new source, checked against the shape recorded in ``tests/fixtures``. They use
the network, anonymously and with the generic User-Agent of ``UrlFetcher`` only, so they are marked
``live`` and left out of the default run. Run them on purpose:

    uv run pytest -m live

A failure here means a source changed; record it and re-record the fixtures with
``tools/record_fixtures.py upstream`` rather than editing them by hand.
"""

from __future__ import annotations

import pytest

from model_dependabot.sources.crossref import Crossref
from model_dependabot.sources.datacite import DataCite
from model_dependabot.sources.doi_ra import ask_agency
from model_dependabot.sources.fetcher import UrlFetcher
from model_dependabot.sources.figshare import Figshare
from model_dependabot.sources.hf import read_dataset, read_model
from model_dependabot.sources.hf_takedowns import TakedownIndex
from model_dependabot.sources.zenodo import Zenodo

pytestmark = pytest.mark.live

ZENODO_FINDABLE = "10.5281/zenodo.3242074"
RETRACTED = "10.1177/1758835919874651"


@pytest.fixture(scope="module")
def fetcher() -> UrlFetcher:
    return UrlFetcher()


def test_doi_ra_names_the_registration_agency(fetcher: UrlFetcher) -> None:
    assert ask_agency(fetcher, ZENODO_FINDABLE).agency == "DataCite"
    assert ask_agency(fetcher, RETRACTED).agency == "Crossref"


def test_the_hub_model_answer_keeps_its_recorded_fields(fetcher: UrlFetcher) -> None:
    model = read_model(fetcher, "openai-community/gpt2")
    assert (model.outcome, model.disabled, model.gated) == ("reachable", False, "false")
    assert model.sha and model.licence == "mit"


def test_the_disabled_hub_dataset_answers_200_with_disabled_true(fetcher: UrlFetcher) -> None:
    dataset = read_dataset(fetcher, "yavon/muxue")
    assert (dataset.response.status, dataset.outcome, dataset.disabled) == (200, "reachable", True)


def test_a_nonexistent_hub_dataset_answers_401(fetcher: UrlFetcher) -> None:
    dataset = read_dataset(fetcher, "model-dependabot/fixture-does-not-exist")
    assert (dataset.response.status, dataset.outcome) == (401, "refused")


def test_the_takedown_log_still_lists_the_recorded_notice(fetcher: UrlFetcher) -> None:
    notices = TakedownIndex(fetcher).read().find("yavon/muxue")
    assert [n["notice_date"] for n in notices] == ["2025-01-29"]
    assert set(notices[0]) == {"notice_date", "reported_content"}


def test_crossref_still_lists_the_retraction(fetcher: UrlFetcher) -> None:
    work = Crossref(fetcher).work(RETRACTED)
    assert work.outcome == "reachable"
    assert work.retractions


def test_datacite_routes_the_zenodo_doi(fetcher: UrlFetcher) -> None:
    record = DataCite(fetcher).record(ZENODO_FINDABLE)
    assert (record.outcome, record.repository, record.repository_id) == (
        "reachable",
        "zenodo",
        "3242074",
    )


def test_zenodo_answers_410_with_a_tombstone(fetcher: UrlFetcher) -> None:
    record = Zenodo(fetcher).record("12584226")
    assert (record.response.status, record.outcome) == (410, "removed")


def test_figshare_declares_the_recorded_licence(fetcher: UrlFetcher) -> None:
    article = Figshare(fetcher).article("34763127")
    assert (article.outcome, article.licence) == ("reachable", "CC BY 4.0")

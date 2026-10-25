"""Figshare: watch events only (T023; FR-005, research U6)."""

from __future__ import annotations

from pathlib import Path

import pytest

from model_dependabot.sources.fetcher import RecordedFetcher
from model_dependabot.sources.figshare import Figshare, article_id, article_url

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def figshare() -> Figshare:
    return Figshare(RecordedFetcher(FIXTURES / "figshare"))


def test_the_article_id_comes_from_the_datacite_url() -> None:
    url = "https://figshare.com/articles/dataset/_i_Chimonocalamus_fimbriatus_i_/29500136/2"
    assert article_id(url) == "29500136"
    assert article_id("https://zenodo.org/record/3242074") is None
    assert article_url("29500136") == "https://api.figshare.com/v2/articles/29500136"


def test_200_is_reachable() -> None:
    article = figshare().article("21108811")
    assert article.outcome == "reachable"
    assert article.licence == "All Rights Reserved"
    assert article.not_found_kind() is None


def test_404_is_not_found_and_a_dataset_unreachable_watch_event() -> None:
    article = figshare().article("1")
    assert article.outcome == "not_found"
    assert article.not_found_kind() == "dataset_unreachable"


@pytest.mark.parametrize("identifier", ["21108811", "34763127", "1"])
def test_no_figshare_answer_produces_a_removal_finding(identifier: str) -> None:
    article = figshare().article(identifier)
    assert article.removal is None
    assert article.alert_kind() is None

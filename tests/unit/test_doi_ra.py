"""DOI registration agency lookup (research U1, tasks T015)."""

from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime
from pathlib import Path

import pytest

from model_dependabot.sources.doi_ra import doi_ra_url, ensure_agency, lookup_agency
from model_dependabot.sources.fetcher import RecordedFetcher
from model_dependabot.store import Store

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "doi_ra"
NOW = datetime(2026, 10, 24, 2, 15, 0, tzinfo=UTC)
ZENODO = "10.5281/zenodo.3242074"
RETRACTED = "10.1177/1758835919874651"


@pytest.fixture
def store(tmp_path: Path) -> Store:
    with Store(tmp_path / "db.sqlite", now=lambda: NOW) as opened:
        yield opened


def test_the_url_is_doi_org_doira() -> None:
    assert doi_ra_url("10.5281/ZENODO.3242074") == f"https://doi.org/doiRA/{ZENODO}"


@pytest.mark.parametrize(("doi", "agency"), [(ZENODO, "DataCite"), (RETRACTED, "Crossref")])
def test_the_recorded_answers_name_the_agency(doi: str, agency: str) -> None:
    assert lookup_agency(RecordedFetcher(FIXTURES), doi) == agency


def test_dois_are_lower_cased(store: Store) -> None:
    fetcher = RecordedFetcher(FIXTURES)
    assert ensure_agency(store, fetcher, "10.5281/ZENODO.3242074") == "DataCite"
    assert fetcher.requests[0][1] == f"https://doi.org/doiRA/{ZENODO}"
    assert store.get_routing(ZENODO)["doi"] == ZENODO


def test_a_known_agency_is_not_looked_up_again(store: Store) -> None:
    fetcher = RecordedFetcher(FIXTURES)
    assert ensure_agency(store, fetcher, ZENODO) == "DataCite"
    assert ensure_agency(store, fetcher, ZENODO) == "DataCite"
    assert len(fetcher.requests) == 1


def test_a_failed_lookup_leaves_it_empty_and_is_retried(store: Store, tmp_path: Path) -> None:
    failing = tmp_path / "failing"
    failing.mkdir()
    meta = {"method": "GET", "url": f"https://doi.org/doiRA/{ZENODO}", "error": "timeout"}
    (failing / "fail.meta.json").write_text(json.dumps(meta), "utf-8")
    assert ensure_agency(store, RecordedFetcher(failing), ZENODO) is None
    routing = store.get_routing(ZENODO)
    assert routing is not None and routing["agency"] is None
    fetcher = RecordedFetcher(FIXTURES)
    assert ensure_agency(store, fetcher, ZENODO) == "DataCite"
    assert len(fetcher.requests) == 1


def test_an_unrecorded_lookup_counts_as_failed(store: Store, tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    assert ensure_agency(store, RecordedFetcher(empty), ZENODO) is None


def test_register_looks_up_every_dataset_and_paper_doi(tmp_path: Path) -> None:
    from model_dependabot.cli import main, make_handlers

    recordings = tmp_path / "rec"
    shutil.copytree(FIXTURES, recordings)
    manifest = tmp_path / "model.toml"
    manifest.write_text(
        f'[model]\nid = "m"\n[[datasets]]\ndoi = "{ZENODO.upper()}"\npaper_doi = ["{RETRACTED}"]\n',
        encoding="utf-8",
    )
    db = tmp_path / "db" / "md.db"
    handlers = make_handlers(fetcher=RecordedFetcher(recordings))
    assert main(["register", str(manifest), "--db", str(db)], handlers=handlers) == 0
    with Store(db) as store:
        assert store.get_routing(ZENODO)["agency"] == "DataCite"
        assert store.get_routing(RETRACTED)["agency"] == "Crossref"

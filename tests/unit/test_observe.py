"""Upstream observations and their comparison (data-model.md, tasks T010)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from model_dependabot.sources.fetcher import Headers, Response, SourceFailedError
from model_dependabot.store import Store
from model_dependabot.upstream.changes import compare
from model_dependabot.upstream.observe import OUTCOMES, effect_of, observe, outcome_for

NOW = datetime(2026, 10, 24, 2, 15, 0, tzinfo=UTC)
ITEM = "10.5281/zenodo.3242074"


def response(status: int, url: str = "https://zenodo.org/api/records/3242074", **extra) -> Response:
    return Response(status, b"{}", url, NOW, Headers(), **extra)


@pytest.fixture
def store(tmp_path: Path) -> Store:
    with Store(tmp_path / "db.sqlite", now=lambda: NOW) as opened:
        yield opened


def test_the_five_outcomes() -> None:
    assert OUTCOMES == ("reachable", "refused", "not_found", "removed", "redirected")


@pytest.mark.parametrize(
    ("source", "status", "outcome"),
    [
        ("hf-hub", 200, "reachable"),
        ("hf-hub", 401, "refused"),
        ("hf-hub", 403, "refused"),
        ("hf-hub", 404, "refused"),
        ("hf-hub", 307, "redirected"),
        ("datacite", 404, "not_found"),
        ("crossref", 404, "not_found"),
        ("figshare", 404, "not_found"),
        ("zenodo", 410, "removed"),
        ("zenodo", 200, "reachable"),
        ("crossref", 200, "reachable"),
    ],
)
def test_outcome_for_each_answer(source: str, status: int, outcome: str) -> None:
    assert outcome_for(source, status) == outcome


@pytest.mark.parametrize(
    ("source", "status"), [("hf-hub", 500), ("zenodo", 503), ("crossref", 502)]
)
def test_a_5xx_is_a_failure_not_an_outcome(source: str, status: int) -> None:
    assert outcome_for(source, status) is None


@pytest.mark.parametrize(
    ("source", "effect"),
    [("datacite", "alert"), ("crossref", "watch_event"), ("figshare", "watch_event")],
)
def test_only_a_datacite_not_found_can_open_an_alert(source: str, effect: str) -> None:
    assert effect_of(source, "not_found") == effect


def test_other_outcomes_carry_no_not_found_effect() -> None:
    assert effect_of("datacite", "reachable") is None


def test_observe_stores_one_observation_with_evidence(store: Store) -> None:
    run = store.start_check_run(scope="all", trigger="scheduled")
    observation = observe(
        store, run, "zenodo", ITEM, response(410), removal={"removal_date": "2024-01-01"}
    )
    assert observation is not None
    assert observation["outcome"] == "removed"
    assert observation["http_status"] == 410
    assert observation["removal"] == {"removal_date": "2024-01-01"}
    evidence = store.get_evidence(observation["evidence_ref"])
    assert evidence["url"] == "https://zenodo.org/api/records/3242074"
    assert evidence["matched_identifier"] == ITEM
    assert evidence["source"] == "zenodo"
    assert len(store.observations(ITEM, "zenodo")) == 1


def test_a_redirect_records_its_first_status_and_target(store: Store) -> None:
    run = store.start_check_run(scope="all")
    answer = response(
        307,
        "https://huggingface.co/api/datasets/the_pile_books3",
        redirected_from="https://huggingface.co/api/datasets/the_pile_books3",
        redirected_to="https://huggingface.co/api/datasets/defunct-datasets/the_pile_books3",
    )
    observation = observe(store, run, "hf-hub", "hf-dataset:x/y@" + "a" * 40, answer)
    assert observation["outcome"] == "redirected"
    assert observation["http_status"] == 307
    assert observation["redirected_to"].endswith("defunct-datasets/the_pile_books3")


def test_a_failed_request_writes_no_observation(store: Store) -> None:
    run = store.start_check_run(scope="all")
    assert observe(store, run, "zenodo", ITEM, response(503)) is None
    assert observe(store, run, "zenodo", ITEM, SourceFailedError("zenodo.org", "timeout")) is None
    assert store.observations(ITEM, "zenodo") == []
    assert store.conn.execute("SELECT count(*) FROM evidence").fetchone()[0] == 0


def test_the_first_observation_is_the_baseline(store: Store) -> None:
    run = store.start_check_run(scope="all")
    first = observe(store, run, "zenodo", ITEM, response(200), declared_licence="cc-by-4.0")
    comparison = compare(store, first)
    assert comparison.baseline is True
    assert comparison.previous is None
    assert comparison.changed == ()


def test_a_new_observation_is_compared_with_the_previous_one_of_the_same_source(
    store: Store,
) -> None:
    run = store.start_check_run(scope="all")
    observe(store, run, "zenodo", ITEM, response(200), declared_licence="cc-by-4.0")
    observe(
        store,
        run,
        "datacite",
        ITEM,
        response(200, "https://api.datacite.org/dois/x"),
        declared_licence="mit",
    )
    later = observe(store, run, "zenodo", ITEM, response(410), removal={"removal_date": "d"})
    comparison = compare(store, later)
    assert comparison.baseline is False
    assert comparison.previous["source"] == "zenodo"
    assert comparison.previous["declared_licence"] == "cc-by-4.0"
    assert set(comparison.changed) == {"http_status", "outcome", "declared_licence", "removal"}


def test_an_unchanged_observation_reports_no_change(store: Store) -> None:
    run = store.start_check_run(scope="all")
    observe(store, run, "zenodo", ITEM, response(200), declared_licence="cc-by-4.0")
    again = observe(store, run, "zenodo", ITEM, response(200), declared_licence="cc-by-4.0")
    comparison = compare(store, again)
    assert comparison.baseline is False
    assert comparison.changed == ()

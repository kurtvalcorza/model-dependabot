"""DOIs doi.org reports as not existing, and DOIs no source can be asked about (fix of 2026-10-24;
data-model.md DOI routing, research U1 and U4, constitution IV).

A Zenodo DOI whose agency is not DataCite, or whose DataCite record is 404, is still asked at
Zenodo with its record id, and only Zenodo's answer decides. Any other DOI no source can be asked
about gives a watch event naming why, never an alert. The answers are the recordings under
``tests/fixtures/doi_ra`` (``not-registered-*``), ``datacite/zenodo-deleted`` and
``zenodo/deleted``; every other state is derived in the test.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from model_dependabot.lifecycle import run_check
from model_dependabot.sources.doi_ra import NOT_REGISTERED, doi_ra_url
from model_dependabot.sources.fetcher import RecordedFetcher
from model_dependabot.sources.zenodo import record_url
from model_dependabot.store import Store

MOMENT = datetime(2026, 10, 24, 8, 0, tzinfo=UTC)
ALL = ("hf-hub", "hf-takedowns", "crossref", "datacite", "zenodo", "figshare")
ZENODO_FINDABLE = "10.5281/zenodo.3242074"
ZENODO_DELETED = "10.5281/zenodo.12584226"
MADE_UP = "10.5281/model-dependabot-fixture-does-not-exist"
DOES_NOT_EXIST = "doi.org reports the DOI does not exist"


@pytest.fixture
def store(tmp_path: Path) -> Store:
    with Store(tmp_path / "md.db", now=lambda: MOMENT) as opened:
        yield opened


def register(store: Store, entries: list[dict[str, Any]]) -> None:
    store.add_model("m")
    store.add_version("m", {}, "0" * 64, entries)


def doi_dataset(doi: str, papers: list[str] | None = None) -> dict[str, Any]:
    return {"kind": "dataset", "identifier": doi, "pinned": True, "paper_dois": papers}


def check(store: Store, fetcher: RecordedFetcher, sources: tuple[str, ...] = ALL) -> Any:
    return run_check(store, fetcher, ["m"], sources)


def urls(fetcher: RecordedFetcher) -> list[str]:
    return [url for _, url, _ in fetcher.requests]


def test_a_deleted_zenodo_doi_unknown_to_doi_org_opens_dataset_removed_from_the_410(
    store: Store, derive_upstream: Callable[..., Path]
) -> None:
    register(store, [doi_dataset(ZENODO_DELETED)])
    fetcher = RecordedFetcher(derive_upstream())
    outcome = check(store, fetcher)
    assert outcome.sources == dict.fromkeys(ALL, "ok")
    assert record_url("12584226") in urls(fetcher)
    (alert,) = store.alerts_for("m", ["open"])
    assert alert["kind"] == "dataset_removed"
    assert alert["cause_key"] == f"dataset_removed:{ZENODO_DELETED}"
    assert (alert["cause"]["host"], alert["cause"]["record_id"]) == ("zenodo", "12584226")
    assert (alert["cause"]["reason"], alert["severity"]) == ("duplicate", "HIGH")
    evidence = {e["source"]: e for e in store.alert_evidence(alert["alert_id"])}
    # The 410 decides; doi.org's and DataCite's answers are supporting evidence (FR-006).
    assert set(evidence) == {"zenodo", "doi-ra", "datacite"}
    assert evidence["zenodo"]["url"] == record_url("12584226")
    assert evidence["doi-ra"]["url"] == doi_ra_url(ZENODO_DELETED)
    assert store.watch_events("m") == []
    routing = store.get_routing(ZENODO_DELETED)
    assert routing is not None and routing["agency"] == NOT_REGISTERED


def test_a_made_up_doi_gives_a_dataset_unreachable_watch_event_naming_why(
    store: Store, derive_upstream: Callable[..., Path]
) -> None:
    register(store, [doi_dataset(MADE_UP)])
    fetcher = RecordedFetcher(derive_upstream())
    outcome = check(store, fetcher)
    assert outcome.sources == dict.fromkeys(ALL, "ok")
    assert store.alerts_for("m", ["open"]) == []
    (event,) = store.watch_events("m")
    assert (event["kind"], event["entry_identifier"]) == ("dataset_unreachable", MADE_UP)
    assert event["detail"]["reason"] == DOES_NOT_EXIST
    assert event["detail"]["source"] == "doi-ra"
    assert [e["source"] for e in event["evidence"]] == ["doi-ra"]
    assert outcome.models[0]["watch_events"] == [event["watch_event_id"]]
    # Not a Zenodo DOI: it is never asked at Zenodo, nor at DataCite.
    assert not [url for url in urls(fetcher) if "zenodo.org" in url or "datacite" in url]


def test_a_tied_paper_doi_org_does_not_know_gives_paper_not_found(
    store: Store, derive_upstream: Callable[..., Path]
) -> None:
    register(store, [doi_dataset(ZENODO_FINDABLE, [MADE_UP])])
    check(store, RecordedFetcher(derive_upstream()))
    assert store.alerts_for("m", ["open"]) == []
    (event,) = store.watch_events("m")
    assert (event["kind"], event["entry_identifier"]) == ("paper_not_found", MADE_UP)
    assert event["detail"]["reason"] == DOES_NOT_EXIST
    assert event["detail"]["dataset"] == ZENODO_FINDABLE


def test_does_not_exist_is_a_stored_answer_asked_again_once_per_check(
    store: Store, derive_upstream: Callable[..., Path]
) -> None:
    register(store, [doi_dataset(MADE_UP, [MADE_UP])])
    fetcher = RecordedFetcher(derive_upstream())
    for _ in range(2):
        fetcher.requests.clear()
        outcome = check(store, fetcher)
        assert outcome.sources == dict.fromkeys(ALL, "ok")
        assert urls(fetcher).count(doi_ra_url(MADE_UP)) == 1
        routing = store.get_routing(MADE_UP)
        assert routing is not None and routing["agency"] == NOT_REGISTERED


def test_a_failed_lookup_is_named_as_the_reason_and_keeps_a_stored_answer(
    store: Store, derive_upstream: Callable[..., Path]
) -> None:
    register(store, [doi_dataset(MADE_UP)])
    store.set_routing(MADE_UP, agency=NOT_REGISTERED)
    failing = derive_upstream(errors={"doi_ra/not-registered-made-up": "timeout"})
    check(store, RecordedFetcher(failing))
    routing = store.get_routing(MADE_UP)
    assert routing is not None and routing["agency"] == NOT_REGISTERED
    (event,) = store.watch_events("m")
    assert event["detail"]["reason"] == DOES_NOT_EXIST
    assert event["evidence"] == []

    store.set_routing(MADE_UP, agency=None)
    check(store, RecordedFetcher(failing))
    (event,) = store.watch_events("m")
    assert event["detail"]["reason"] == "doi.org could not be asked which agency registered the DOI"


def test_a_zenodo_doi_whose_agency_lookup_failed_is_still_checked_at_zenodo(
    store: Store, derive_upstream: Callable[..., Path]
) -> None:
    register(store, [doi_dataset(ZENODO_FINDABLE)])
    fetcher = RecordedFetcher(derive_upstream(errors={"doi_ra/datacite": "timeout"}))
    check(store, fetcher)
    assert record_url("3242074") in urls(fetcher)
    assert store.alerts_for("m", ["open"]) == []
    assert store.watch_events("m") == []
    (observation,) = store.observations(ZENODO_FINDABLE, "zenodo")
    assert observation["outcome"] == "reachable"


def test_a_zenodo_404_for_an_unknown_agency_doi_is_dataset_unreachable(
    store: Store, derive_upstream: Callable[..., Path]
) -> None:
    root = derive_upstream()
    # Derived state: the recorded tombstone answered as a plain 404.
    meta_path = root / "zenodo" / "deleted.meta.json"
    meta = json.loads(meta_path.read_text("utf-8"))
    meta["status"] = 404
    meta_path.write_text(json.dumps(meta), "utf-8")
    register(store, [doi_dataset(ZENODO_DELETED)])
    check(store, RecordedFetcher(root))
    assert store.alerts_for("m", ["open"]) == []
    (event,) = store.watch_events("m")
    assert (event["kind"], event["detail"]["source"]) == ("dataset_unreachable", "zenodo")
    assert {e["source"] for e in event["evidence"]} == {"zenodo", "doi-ra", "datacite"}


def test_no_watch_event_when_no_doi_source_is_requested(
    store: Store, derive_upstream: Callable[..., Path]
) -> None:
    register(store, [doi_dataset(MADE_UP)])
    check(store, RecordedFetcher(derive_upstream()), sources=("hf-hub",))
    assert store.watch_events("m") == []

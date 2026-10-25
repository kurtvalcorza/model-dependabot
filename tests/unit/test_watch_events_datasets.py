"""Dataset version and replacement watch events (T050; FR-007, research U2, U3).

The recordings: Zenodo record 8176941 (``zenodo/older-version``, ``relations.version[0].is_last:
false``) whose ``links.latest`` answers 301 to record 18180184 (``zenodo/older-version-latest``);
Zenodo record 3242074 (the newest of its versions); DataCite ``10.1594/pangaea.958394``
(``datacite/obsoleted``, ``IsObsoletedBy 10.1594/pangaea.997226``) and
``10.6084/m9.figshare.29500136.v2`` (``datacite/previous-version``, ``IsPreviousVersionOf
10.6084/m9.figshare.29500136``). ``HasVersion`` is derived from the latter. None is an alert.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from conftest import fixture_json
from model_dependabot.lifecycle import run_check
from model_dependabot.sources import datacite, zenodo
from model_dependabot.sources.fetcher import RecordedFetcher
from model_dependabot.store import Store

MOMENT = datetime(2026, 10, 24, 8, 0, tzinfo=UTC)
OLDER = "10.5281/zenodo.8176941"
NEWEST = "10.5281/zenodo.3242074"
OBSOLETED = "10.1594/pangaea.958394"
REPLACING = "10.1594/pangaea.997226"
PREVIOUS = "10.6084/m9.figshare.29500136.v2"
CONCEPT = "10.6084/m9.figshare.29500136"


def newer_record(licence: str = "cc-zero") -> dict[str, dict[str, Any]]:
    """Record 18180184, where ``links.latest`` leads; not recorded, so derived from the recorded
    older version with its id and declared licence changed (the newer version's licence is read,
    one request, for the watch event only)."""
    body = fixture_json("zenodo/older-version")
    body["id"] = 18180184
    body["metadata"]["license"] = {"id": licence}
    url = zenodo.record_url("18180184")
    return {"newer": {"url": url, "status": 200, "body": body}}


@pytest.fixture
def store(tmp_path: Path) -> Iterator[Store]:
    with Store(tmp_path / "md.db", now=lambda: MOMENT) as opened:
        yield opened


def register(store: Store, doi: str, repository: str | None = None, rid: str | None = None) -> None:
    store.add_model("m")
    entry = {"kind": "dataset", "identifier": doi, "pinned": True, "paper_dois": None}
    store.add_version("m", {}, "0" * 64, [entry])
    store.set_routing(doi, agency="DataCite", repository=repository, repository_id=rid)


def check(store: Store, root: Path, *sources: str) -> Any:
    return run_check(store, RecordedFetcher(root), ["m"], sources)


def events(store: Store, kind: str) -> list[dict[str, Any]]:
    return [e for e in store.watch_events("m") if e["kind"] == kind]


def test_zenodo_reads_the_newest_version_from_links_latest(
    derive_upstream: Callable[..., Path],
) -> None:
    record = zenodo.Zenodo(RecordedFetcher(derive_upstream(extra=newer_record()))).record("8176941")
    assert (record.outcome, record.newer) == ("reachable", "18180184")
    assert record.newer_response is not None
    assert record.newer_response.status == 301


def test_zenodo_reads_no_newer_version_for_the_last_one(
    derive_upstream: Callable[..., Path],
) -> None:
    record = zenodo.Zenodo(RecordedFetcher(derive_upstream())).record("3242074")
    assert (record.newer, record.newer_response) == (None, None)


def test_datacite_reads_newer_versions_and_replacements(
    derive_upstream: Callable[..., Path],
) -> None:
    client = datacite.DataCite(RecordedFetcher(derive_upstream()))
    obsoleted = client.record(OBSOLETED)
    assert (obsoleted.replaced_by, obsoleted.newer) == ((REPLACING,), ())
    previous = client.record(PREVIOUS)
    assert (previous.newer, previous.replaced_by) == ((CONCEPT,), ())


def test_datacite_has_version_is_a_newer_version(derive_upstream: Callable[..., Path]) -> None:
    def has_version(body: dict[str, Any]) -> dict[str, Any]:
        for related in body["data"]["attributes"]["relatedIdentifiers"]:
            related["relationType"] = "HasVersion"
        return body

    root = derive_upstream(changes={"datacite/previous-version": has_version})
    assert datacite.DataCite(RecordedFetcher(root)).record(PREVIOUS).newer == (CONCEPT,)


def test_a_newer_zenodo_version_is_one_watch_event_naming_it(
    store: Store, derive_upstream: Callable[..., Path]
) -> None:
    register(store, OLDER, "zenodo", "8176941")
    root = derive_upstream(extra=newer_record())
    check(store, root, "zenodo")
    check(store, root, "zenodo")
    [event] = events(store, "dataset_new_version")
    assert event["detail"]["source"] == "zenodo"
    assert event["detail"]["newer"] == "18180184"
    assert event["detail"]["newer_url"] == "https://zenodo.org/api/records/18180184"
    urls = {e["url"] for e in event["evidence"]}
    assert "https://zenodo.org/api/records/8176941/versions/latest" in urls
    assert store.alerts_for("m") == []


def test_the_newest_zenodo_version_records_nothing(
    store: Store, derive_upstream: Callable[..., Path]
) -> None:
    register(store, NEWEST, "zenodo", "3242074")
    check(store, derive_upstream(), "zenodo")
    assert events(store, "dataset_new_version") == []


def test_datacite_is_previous_version_of_is_one_watch_event(
    store: Store, derive_upstream: Callable[..., Path]
) -> None:
    register(store, PREVIOUS, "figshare", "29500136")
    root = derive_upstream()
    check(store, root, "datacite")
    check(store, root, "datacite")
    [event] = events(store, "dataset_new_version")
    assert (event["detail"]["source"], event["detail"]["newer"]) == ("datacite", CONCEPT)
    assert len(event["evidence"]) == 1
    assert store.alerts_for("m") == []


def test_datacite_is_obsoleted_by_is_one_dataset_replaced_naming_the_record(
    store: Store, derive_upstream: Callable[..., Path]
) -> None:
    register(store, OBSOLETED, "other")
    root = derive_upstream()
    check(store, root, "datacite")
    check(store, root, "datacite")
    [event] = events(store, "dataset_replaced")
    assert (event["detail"]["source"], event["detail"]["replaced_by"]) == ("datacite", REPLACING)
    assert len(event["evidence"]) == 1
    assert events(store, "dataset_new_version") == []
    assert store.alerts_for("m") == []


def test_a_newer_zenodo_version_shows_its_declared_licence_and_stays_a_watch_event(
    store: Store, derive_upstream: Callable[..., Path]
) -> None:
    # The pinned record declares cc-by-4.0; the newer one cc-zero. FR-007: never an alert.
    register(store, OLDER, "zenodo", "8176941")
    check(store, derive_upstream(extra=newer_record("cc-zero")), "zenodo")
    [event] = events(store, "dataset_new_version")
    detail = event["detail"]
    assert detail["newer_declared_licence"] == "cc-zero"
    assert (detail["newer_licence"], detail["newer_licence_form"]) == ("CC0-1.0", "spdx")
    assert zenodo.record_url("18180184") in {e["url"] for e in event["evidence"]}
    assert store.alerts_for("m") == []
    assert [e["kind"] for e in store.watch_events("m")] == ["dataset_new_version"]


def test_a_newer_zenodo_version_that_cannot_be_read_still_names_it(
    store: Store, derive_upstream: Callable[..., Path]
) -> None:
    register(store, OLDER, "zenodo", "8176941")
    extra = newer_record()
    extra["newer"] |= {"status": 500, "body": {"status": 500}}
    outcome = check(store, derive_upstream(extra=extra), "zenodo")
    assert outcome.sources == {"zenodo": "ok"}
    [event] = events(store, "dataset_new_version")
    assert event["detail"]["newer"] == "18180184"
    assert "newer_licence" not in event["detail"]
    assert event["detail"]["newer_licence_error"]

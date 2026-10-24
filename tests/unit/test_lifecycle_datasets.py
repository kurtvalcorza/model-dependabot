"""Dataset retraction and removal alerts and their watch events (T026; data-model.md, FR-004 to
FR-007, FR-018, FR-019, research U2 to U6, U9, U12).

Every changed state is derived in the test from the recordings under ``tests/fixtures``.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from conftest import fixture_json
from model_dependabot.lifecycle import reevaluate_version, run_check
from model_dependabot.sources.datacite import doi_url
from model_dependabot.sources.fetcher import RecordedFetcher
from model_dependabot.sources.figshare import article_url
from model_dependabot.sources.hf import dataset_info_url
from model_dependabot.sources.hf_takedowns import INDEX_URL, NOTICE_LABEL
from model_dependabot.store import Store

MOMENT = datetime(2026, 10, 24, 8, 0, tzinfo=UTC)
ALL = ("hf-hub", "hf-takedowns", "crossref", "datacite", "zenodo", "figshare")
RETRACTED = "10.1177/1758835919874651"
NOTICE = "10.1177/17588359211061903"
CORRECTED = "10.1088/1361-6595/aaebdb"
CONCERN = "10.1016/j.lungcan.2003.10.006"
UNRETRACTED = "10.1038/nature14539"
CROSSREF_MISSING = "10.1177/model-dependabot-fixture-does-not-exist"
ZENODO_FINDABLE = "10.5281/zenodo.3242074"
ZENODO_DELETED = "10.5281/zenodo.12584226"
DATACITE_MISSING = "10.5281/model-dependabot-fixture-does-not-exist"
FIGSHARE_DOI = "10.6084/m9.figshare.29500136.v2"
MUXUE_SHA = "9408684b4d7410bf12651eff99ad6da74d746811"
MUXUE = f"hf-dataset:yavon/muxue@{MUXUE_SHA}"
MISSING_REPO = "model-dependabot-fixture/does-not-exist"


@pytest.fixture
def store(tmp_path: Path) -> Store:
    with Store(tmp_path / "md.db", now=lambda: MOMENT) as opened:
        yield opened


def doi_dataset(doi: str, papers: list[str] | None = None) -> dict[str, Any]:
    return {"kind": "dataset", "identifier": doi, "pinned": True, "paper_dois": papers}


def hub_dataset(repo: str, sha: str = MUXUE_SHA) -> dict[str, Any]:
    return {
        "kind": "dataset",
        "identifier": f"hf-dataset:{repo}@{sha}",
        "pinned": True,
        "hub_repo": repo,
        "hub_revision": sha,
    }


def register(store: Store, model_id: str, entries: list[dict[str, Any]]) -> int:
    if store.get_model(model_id) is None:
        store.add_model(model_id)
    return store.add_version(model_id, {}, "0" * 64, entries)


def crossref(store: Store, *dois: str) -> None:
    for doi in dois:
        store.set_routing(doi, agency="Crossref")


def datacite(store: Store, doi: str, repository: str | None = None, rid: str | None = None) -> None:
    store.set_routing(doi, agency="DataCite", repository=repository, repository_id=rid)


def check(store: Store, root: Path, *models: str, sources: tuple[str, ...] = ALL) -> Any:
    return run_check(store, RecordedFetcher(root), list(models), sources)


def alerts(store: Store, model_id: str, states: tuple[str, ...] = ("open",)) -> list[dict]:
    return store.alerts_for(model_id, list(states))


def kinds(store: Store, model_id: str) -> list[str]:
    return sorted(event["kind"] for event in store.watch_events(model_id))


def datacite_answer(doi: str, url: str) -> dict[str, Any]:
    body = fixture_json("datacite/findable")
    body["data"]["id"] = doi
    body["data"]["attributes"]["doi"] = doi
    body["data"]["attributes"]["url"] = url
    return {"url": doi_url(doi), "status": 200, "body": body}


def assert_policy_high(alert: dict[str, Any]) -> None:
    assert (alert["severity"], alert["severity_origin"]) == ("HIGH", "policy")


def test_a_crossref_retraction_of_the_dataset_doi_opens_dataset_retracted(
    store: Store, derive_upstream: Callable[..., Path]
) -> None:
    register(store, "m", [doi_dataset(RETRACTED)])
    crossref(store, RETRACTED)
    outcome = check(store, derive_upstream(), "m")
    assert outcome.sources["crossref"] == "ok"
    (alert,) = alerts(store, "m")
    assert alert["kind"] == "dataset_retracted"
    assert alert["cause_key"] == f"dataset_retracted:{RETRACTED}"
    assert_policy_high(alert)
    assert {n["notice_doi"] for n in alert["cause"]["notices"]} == {NOTICE}
    assert {n["source"] for n in alert["cause"]["notices"]} == {"publisher", "retraction-watch"}
    (evidence,) = store.alert_evidence(alert["alert_id"])
    assert (evidence["source"], evidence["matched_identifier"]) == ("crossref", RETRACTED)
    assert evidence["url"] == f"https://api.crossref.org/works/{RETRACTED}"


def test_a_retracted_tied_paper_opens_paper_retracted_and_a_clean_dataset_nothing(
    store: Store, derive_upstream: Callable[..., Path]
) -> None:
    register(store, "m", [doi_dataset(ZENODO_FINDABLE, [RETRACTED, UNRETRACTED])])
    datacite(store, ZENODO_FINDABLE, "zenodo", "3242074")
    crossref(store, RETRACTED, UNRETRACTED)
    outcome = check(store, derive_upstream(), "m")
    assert set(outcome.sources.values()) == {"ok"}
    (alert,) = alerts(store, "m")
    assert alert["kind"] == "paper_retracted"
    assert alert["cause_key"] == f"paper_retracted:{ZENODO_FINDABLE}:{RETRACTED}"
    assert (alert["cause"]["dataset"], alert["cause"]["paper_doi"]) == (ZENODO_FINDABLE, RETRACTED)
    assert_policy_high(alert)
    assert kinds(store, "m") == []


def test_a_zenodo_410_routed_by_datacite_opens_dataset_removed_with_date_and_reason(
    store: Store, derive_upstream: Callable[..., Path]
) -> None:
    register(store, "m", [doi_dataset(ZENODO_DELETED)])
    datacite(store, ZENODO_DELETED)
    answer = datacite_answer(ZENODO_DELETED, "https://zenodo.org/records/12584226")
    check(store, derive_upstream(extra={"dc-deleted": answer}), "m")
    routing = store.get_routing(ZENODO_DELETED)
    assert routing is not None
    assert (routing["repository"], routing["repository_id"]) == ("zenodo", "12584226")
    (alert,) = alerts(store, "m")
    assert alert["kind"] == "dataset_removed"
    assert alert["cause_key"] == f"dataset_removed:{ZENODO_DELETED}"
    assert alert["cause"]["host"] == "zenodo"
    assert alert["cause"]["removal_date"] == "2024-08-26T14:40:13.975857"
    assert alert["cause"]["reason"] == "duplicate"
    assert_policy_high(alert)
    sources = {e["source"] for e in store.alert_evidence(alert["alert_id"])}
    assert "zenodo" in sources


def test_a_disabled_hub_dataset_listed_in_the_log_shows_the_notice_date(
    store: Store, derive_upstream: Callable[..., Path]
) -> None:
    log = "date,reported_content\n2026-09-04, yavon/muxue \n2023-03-06,Multiple\n"
    register(store, "m", [hub_dataset("yavon/muxue")])
    check(store, derive_upstream(changes={"hf_takedowns/index": lambda _: log}), "m")
    (alert,) = alerts(store, "m")
    assert alert["kind"] == "dataset_removed"
    assert alert["cause_key"] == f"dataset_removed:{MUXUE}"
    assert_policy_high(alert)
    cause = alert["cause"]
    assert (cause["host"], cause["disabled"]) == ("huggingface", True)
    assert (cause["notice_date"], cause["notice_label"]) == ("2026-09-04", NOTICE_LABEL)
    assert cause["reason"] == "no reason given"
    assert "file" not in cause and ".pdf" not in json.dumps(cause)
    urls = {e["url"] for e in store.alert_evidence(alert["alert_id"])}
    assert INDEX_URL in urls


def test_a_disabled_hub_dataset_not_in_the_log_says_no_reason_given(
    store: Store, derive_upstream: Callable[..., Path]
) -> None:
    # The recorded log lists yavon/muxue (2025-01-29); this state drops that row.
    def unlisted(text: str) -> str:
        return "".join(line for line in text.splitlines(True) if "yavon/muxue" not in line)

    register(store, "m", [hub_dataset("yavon/muxue")])
    check(store, derive_upstream(changes={"hf_takedowns/index": unlisted}), "m")
    (alert,) = alerts(store, "m")
    assert (alert["cause"]["notice_date"], alert["cause"]["reason"]) == (None, "no reason given")
    assert "notice_label" not in alert["cause"]


def test_the_recorded_log_lists_the_recorded_disabled_dataset(
    store: Store, derive_upstream: Callable[..., Path]
) -> None:
    register(store, "m", [hub_dataset("yavon/muxue")])
    check(store, derive_upstream(), "m")
    (alert,) = alerts(store, "m")
    assert (alert["cause"]["notice_date"], alert["cause"]["notice_label"]) == (
        "2025-01-29",
        NOTICE_LABEL,
    )


def test_a_takedown_log_row_alone_never_opens_an_alert(
    store: Store, derive_upstream: Callable[..., Path]
) -> None:
    body = {"id": "owner/listed", "disabled": False, "gated": False, "sha": MUXUE_SHA}
    root = derive_upstream(
        changes={
            "hf_takedowns/index": lambda _: "date,reported_content\n2026-09-04,owner/listed\n"
        },
        extra={"listed": {"url": dataset_info_url("owner/listed"), "status": 200, "body": body}},
    )
    register(store, "m", [hub_dataset("owner/listed")])
    check(store, root, "m")
    assert alerts(store, "m") == []


def test_a_datacite_404_opens_dataset_not_findable(
    store: Store, derive_upstream: Callable[..., Path]
) -> None:
    register(store, "m", [doi_dataset(DATACITE_MISSING)])
    datacite(store, DATACITE_MISSING)
    check(store, derive_upstream(), "m")
    (alert,) = alerts(store, "m")
    assert alert["kind"] == "dataset_not_findable"
    assert alert["cause_key"] == f"dataset_not_findable:{DATACITE_MISSING}"
    assert_policy_high(alert)


@pytest.mark.parametrize("paper", [CORRECTED, CONCERN])
def test_a_correction_or_concern_with_no_alert_open_is_an_upstream_notice(
    store: Store, derive_upstream: Callable[..., Path], paper: str
) -> None:
    register(store, "m", [doi_dataset(ZENODO_FINDABLE, [paper])])
    datacite(store, ZENODO_FINDABLE, "zenodo", "3242074")
    crossref(store, paper)
    check(store, derive_upstream(), "m")
    assert alerts(store, "m") == []
    assert kinds(store, "m") == ["upstream_notice"]


def _with_correction(body: dict) -> dict:
    body["message"]["updated-by"].append(
        {
            "DOI": "10.1177/fixture-correction",
            "type": "correction",
            "source": "publisher",
            "updated": {"date-time": "2022-01-10T00:00:00Z"},
        }
    )
    return body


def _no_retraction(body: dict) -> dict:
    body["message"].pop("updated-by")
    return body


def test_a_correction_adds_evidence_to_an_open_retraction_alert(
    store: Store, derive_upstream: Callable[..., Path]
) -> None:
    register(store, "m", [doi_dataset(RETRACTED)])
    crossref(store, RETRACTED)
    check(store, derive_upstream(), "m", sources=("crossref",))
    (first,) = alerts(store, "m")
    before = len(store.alert_evidence(first["alert_id"]))
    check(store, derive_upstream(changes={"crossref/retracted": _with_correction}), "m")
    (second,) = alerts(store, "m")
    assert second["alert_id"] == first["alert_id"]
    assert len(store.alert_evidence(second["alert_id"])) == before + 1
    assert kinds(store, "m") == []


def test_a_retraction_alert_closes_as_withdrawn_when_crossref_lists_none(
    store: Store, derive_upstream: Callable[..., Path]
) -> None:
    register(store, "m", [doi_dataset(ZENODO_FINDABLE, [RETRACTED])])
    datacite(store, ZENODO_FINDABLE, "zenodo", "3242074")
    crossref(store, RETRACTED)
    check(store, derive_upstream(), "m", sources=("crossref",))
    (alert,) = alerts(store, "m")
    outcome = check(store, derive_upstream(changes={"crossref/retracted": _no_retraction}), "m")
    assert alert["alert_id"] in outcome.models[0]["closed"]
    closed = store.get_alert(alert["alert_id"])
    assert closed is not None and closed["state"] == "withdrawn"
    latest = store.alert_evidence(alert["alert_id"])[-1]
    body = json.loads(store.read_body(latest["body_sha256"]))
    assert latest["source"] == "crossref" and "updated-by" not in body["message"]


def test_moves_refusals_and_404s_are_watch_events_never_alerts(
    store: Store, derive_upstream: Callable[..., Path]
) -> None:
    moved = dataset_info_url("owner/books3")
    target = dataset_info_url("defunct-datasets/books3")
    root = derive_upstream(
        extra={
            "moved": {
                "url": moved,
                "status": 307,
                "body": "Temporary Redirect.",
                "redirected_to": target,
            },
            "fig-404": {
                "url": article_url("29500136"),
                "status": 404,
                "body": {"message": "Entity not found: ArticleVersion"},
            },
        }
    )
    register(
        store,
        "m",
        [
            hub_dataset("owner/books3"),
            hub_dataset(MISSING_REPO),
            doi_dataset(FIGSHARE_DOI),
            doi_dataset(CROSSREF_MISSING),
            doi_dataset(ZENODO_FINDABLE, [CROSSREF_MISSING]),
        ],
    )
    datacite(store, FIGSHARE_DOI, "figshare", "29500136")
    datacite(store, ZENODO_FINDABLE, "zenodo", "3242074")
    crossref(store, CROSSREF_MISSING)
    outcome = check(store, root, "m")
    assert set(outcome.sources.values()) == {"ok"}
    assert alerts(store, "m") == []
    events = {(e["kind"], e["entry_identifier"]): e for e in store.watch_events("m")}
    assert set(events) == {
        ("dataset_moved", f"hf-dataset:owner/books3@{MUXUE_SHA}"),
        ("dataset_unreachable", f"hf-dataset:{MISSING_REPO}@{MUXUE_SHA}"),
        ("dataset_unreachable", FIGSHARE_DOI),
        ("dataset_unreachable", CROSSREF_MISSING),
        ("paper_not_found", CROSSREF_MISSING),
    }
    assert events[("dataset_moved", f"hf-dataset:owner/books3@{MUXUE_SHA}")]["detail"]["to"] == (
        "defunct-datasets/books3"
    )
    figshare = events[("dataset_unreachable", FIGSHARE_DOI)]["detail"]
    assert (figshare["source"], figshare["http_status"]) == ("figshare", 404)
    for event in events.values():
        assert event["evidence"], event["kind"]


def test_the_same_dataset_in_two_models_gives_each_its_own_alert(
    store: Store, derive_upstream: Callable[..., Path]
) -> None:
    for model_id in ("a", "b"):
        register(store, model_id, [doi_dataset(ZENODO_DELETED)])
    datacite(store, ZENODO_DELETED, "zenodo", "12584226")
    check(store, derive_upstream(), "a", "b", sources=("zenodo",))
    assert [a["kind"] for a in alerts(store, "a")] == ["dataset_removed"]
    assert [a["kind"] for a in alerts(store, "b")] == ["dataset_removed"]


def test_a_failed_source_opens_changes_or_closes_nothing(
    store: Store, derive_upstream: Callable[..., Path]
) -> None:
    register(store, "m", [doi_dataset(ZENODO_DELETED, [RETRACTED]), hub_dataset("yavon/muxue")])
    datacite(store, ZENODO_DELETED, "zenodo", "12584226")
    crossref(store, RETRACTED)
    check(store, derive_upstream(), "m", sources=("crossref",))
    (open_alert,) = alerts(store, "m")
    evidence = len(store.alert_evidence(open_alert["alert_id"]))
    root = derive_upstream(
        errors={
            "zenodo/deleted": "timeout",
            "crossref/retracted": "timeout",
            "hf_upstream/dataset-disabled": "timeout",
        },
        extra={"dc": datacite_answer(ZENODO_DELETED, "https://zenodo.org/records/12584226")},
    )
    outcome = check(store, root, "m")
    assert outcome.failed
    for source in ("zenodo", "crossref", "hf-hub"):
        assert outcome.sources[source].startswith("failed")
    (still,) = alerts(store, "m")
    assert still["alert_id"] == open_alert["alert_id"]
    assert len(store.alert_evidence(still["alert_id"])) == evidence
    assert outcome.models[0]["opened"] == outcome.models[0]["closed"] == []


def test_a_new_version_without_the_dataset_closes_its_alert_as_fixed(
    store: Store, derive_upstream: Callable[..., Path]
) -> None:
    register(store, "m", [doi_dataset(ZENODO_FINDABLE, [RETRACTED]), doi_dataset(ZENODO_DELETED)])
    datacite(store, ZENODO_DELETED, "zenodo", "12584226")
    crossref(store, RETRACTED)
    check(store, derive_upstream(), "m", sources=("crossref", "zenodo"))
    assert sorted(a["kind"] for a in alerts(store, "m")) == ["dataset_removed", "paper_retracted"]
    version = register(store, "m", [doi_dataset(ZENODO_FINDABLE, [RETRACTED])])
    result = reevaluate_version(store, "m", version)
    assert len(result["fixed"]) == 1 and len(result["carried_forward"]) == 1
    assert [a["kind"] for a in alerts(store, "m")] == ["paper_retracted"]
    version = register(store, "m", [doi_dataset(ZENODO_FINDABLE)])
    assert len(reevaluate_version(store, "m", version)["fixed"]) == 1
    assert alerts(store, "m") == []


def test_dois_whose_agency_lookup_failed_are_looked_up_at_the_start_of_a_check(
    store: Store, derive_upstream: Callable[..., Path]
) -> None:
    register(store, "m", [doi_dataset(ZENODO_FINDABLE, [RETRACTED])])
    store.set_routing(ZENODO_FINDABLE, agency=None)
    store.set_routing(RETRACTED, agency=None)
    check(store, derive_upstream(), "m")
    routing = store.get_routing(ZENODO_FINDABLE)
    assert routing is not None
    assert (routing["agency"], routing["repository"]) == ("DataCite", "zenodo")
    retry = store.get_routing(RETRACTED)
    assert retry is not None and retry["agency"] == "Crossref"
    assert [a["kind"] for a in alerts(store, "m")] == ["paper_retracted"]


def test_a_paper_tied_to_a_hub_dataset_is_checked_too(
    store: Store, derive_upstream: Callable[..., Path]
) -> None:
    entry = hub_dataset("yavon/muxue") | {"paper_dois": [RETRACTED]}
    register(store, "m", [entry])
    crossref(store, RETRACTED)
    check(store, derive_upstream(), "m", sources=("crossref",))
    (alert,) = alerts(store, "m")
    assert alert["cause_key"] == f"paper_retracted:{MUXUE}:{RETRACTED}"


# An obviously fictional paper DOI under arXiv's DataCite prefix; doi.org's answer is derived.
DATACITE_PAPER = "10.48550/model-dependabot-fixture-paper"


def test_a_paper_doi_registered_with_datacite_records_paper_not_found_never_an_alert(
    store: Store, derive_upstream: Callable[..., Path]
) -> None:
    """Constitution IV: no retraction source reads DataCite DOIs, so the paper is not skipped."""
    from model_dependabot.sources.doi_ra import doi_ra_url

    register(store, "m", [doi_dataset(ZENODO_FINDABLE, [DATACITE_PAPER])])
    datacite(store, ZENODO_FINDABLE, "zenodo", "3242074")
    datacite(store, DATACITE_PAPER)
    answer = [{"DOI": DATACITE_PAPER, "RA": "DataCite"}]
    extra = {"paper-ra": {"url": doi_ra_url(DATACITE_PAPER), "status": 200, "body": answer}}
    outcome = check(store, derive_upstream(extra=extra), "m")
    assert outcome.sources == dict.fromkeys(ALL, "ok")
    assert alerts(store, "m") == []
    events = {(e["kind"], e["entry_identifier"]): e for e in store.watch_events("m")}
    event = events[("paper_not_found", DATACITE_PAPER)]
    assert event["detail"]["reason"] == "registered with DataCite, which no retraction source reads"
    assert event["detail"]["dataset"] == ZENODO_FINDABLE
    assert [e["source"] for e in event["evidence"]] == ["doi-ra"]
    # The dataset DOI itself is read at DataCite, so it is not reported as not asked.
    assert ("dataset_unreachable", ZENODO_FINDABLE) not in events

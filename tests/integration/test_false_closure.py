"""False-closure regressions from the 2026-10-25 review (FR-016 of 001, FR-018 of 002).

Each test sets up a state the review reproduced: an open alert that the old code closed without
evidence that its cause had gone. Answers are served from memory (``Answers``) and every body is
written out in the test: a real recording (``fixture_json``) changed as named, or a malformed
envelope no recording has. Nothing reaches the network.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from conftest import fixture_json
from model_dependabot.lifecycle import reevaluate_version, run_check
from model_dependabot.sources.crossref import works_url
from model_dependabot.sources.datacite import doi_url
from model_dependabot.sources.fetcher import Response, SourceFailedError
from model_dependabot.sources.figshare import article_url
from model_dependabot.sources.hf import dataset_info_url, model_info_url
from model_dependabot.store import Store

NOW = datetime(2026, 10, 25, tzinfo=UTC)
SHA_A = "a" * 40
SHA_B = "b" * 40
REPO = "owner/model"
PURL_A = f"pkg:huggingface/owner/model@{SHA_A}"
PURL_B = f"pkg:huggingface/owner/model@{SHA_B}"
BASE_A = {
    "kind": "base_model",
    "identifier": PURL_A,
    "pinned": True,
    "name": REPO,
    "version": SHA_A,
}
BASE_B = BASE_A | {"identifier": PURL_B, "version": SHA_B}
BASE_GAP = {"kind": "base_model", "name": REPO, "pinned": False, "gap_reason": "no revision"}
DATA_REPO = "owner/data"
HUB_A = f"hf-dataset:{DATA_REPO}@{SHA_A}"
HUB_B = f"hf-dataset:{DATA_REPO}@{SHA_B}"
HUB_DATASET_A = {
    "kind": "dataset",
    "identifier": HUB_A,
    "pinned": True,
    "hub_repo": DATA_REPO,
    "hub_revision": SHA_A,
}
HUB_DATASET_B = HUB_DATASET_A | {"identifier": HUB_B, "hub_revision": SHA_B}
HUB_DATASET_GAP = {
    "kind": "dataset",
    "pinned": False,
    "hub_repo": DATA_REPO,
    "gap_reason": "no revision",
}
DOI = "10.1234/test"
RETRACTION = {"type": "retraction", "source": "publisher", "DOI": "10.1234/notice"}


class Answers:
    """A fetcher serving each URL's body from memory; an exception value is raised instead."""

    def __init__(self, values: dict[str, Any]) -> None:
        self.values = values

    def get(self, url: str, **kwargs: Any) -> Response:
        value = self.values[url]
        if isinstance(value, Exception):
            raise value
        body = value if isinstance(value, bytes) else json.dumps(value).encode()
        return Response(200, body, url, NOW)


@pytest.fixture
def root(tmp_path: Path) -> Path:
    return tmp_path


def fresh(root: Path, name: str, *entries: dict[str, Any]) -> Store:
    store = Store(root / name / "md.db", now=lambda: NOW)
    store.add_model("m")
    store.add_version("m", {}, "0" * 64, list(entries))
    return store


def opened(store: Store, kind: str, cause: dict[str, Any], key: str | None = None) -> int:
    return store.insert_alert(
        model_id="m",
        kind=kind,
        cause_key=key or f"{kind}:{cause['identifier']}",
        cause=cause,
        severity="HIGH",
        severity_origin="policy",
        opened_in_version=1,
        evidence_ids=[],
    )


def state(store: Store, alert_id: int) -> str:
    alert = store.get_alert(alert_id)
    assert alert is not None
    return alert["state"]


# --- F3 / A5: an incomplete inventory entry is not removal of the cause -------------------------


def test_base_model_gap_keeps_disabled_alert_open(root: Path) -> None:
    with fresh(root, "gap", BASE_A) as store:
        cause = {"identifier": PURL_A, "base_model": PURL_A, "repo": REPO}
        aid = opened(store, "base_model_disabled", cause)
        store.add_version("m", {}, "0" * 64, [BASE_GAP])
        result = reevaluate_version(store, "m", 2)
        assert state(store, aid) == "open"
        assert aid not in result["fixed"]


def test_hub_dataset_gap_keeps_removed_alert_open(root: Path) -> None:
    with fresh(root, "hub-gap", HUB_DATASET_A) as store:
        cause = {"identifier": HUB_A, "dataset": HUB_A, "host": "huggingface", "disabled": True}
        aid = opened(store, "dataset_removed", cause)
        store.add_version("m", {}, "0" * 64, [HUB_DATASET_GAP])
        reevaluate_version(store, "m", 2)
        assert state(store, aid) == "open"


def test_hub_dataset_gap_keeps_paper_retraction_open(root: Path) -> None:
    paper = "10.1234/paper"
    with fresh(root, "hub-paper-gap", HUB_DATASET_A | {"paper_dois": [paper]}) as store:
        cause = {"identifier": HUB_A, "dataset": HUB_A, "paper_doi": paper}
        aid = opened(store, "paper_retracted", cause, f"paper_retracted:{HUB_A}:{paper}")
        store.add_version("m", {}, "0" * 64, [HUB_DATASET_GAP | {"paper_dois": [paper]}])
        reevaluate_version(store, "m", 2)
        assert state(store, aid) == "open"


def test_base_model_gap_keeps_licence_alert_open(root: Path) -> None:
    with fresh(root, "licence-gap", BASE_A) as store:
        cause = {"identifier": PURL_A, "item": PURL_A, "source": "hf-hub"}
        aid = opened(store, "licence_changed", cause)
        store.add_version("m", {}, "0" * 64, [BASE_GAP])
        reevaluate_version(store, "m", 2)
        assert state(store, aid) == "open"


# --- F4 / A4: repository-wide causes follow the repository, not the revision --------------------


def test_new_revision_of_disabled_base_model_carries_alert(root: Path) -> None:
    with fresh(root, "revision", BASE_A) as store:
        cause = {"identifier": PURL_A, "base_model": PURL_A, "repo": REPO}
        aid = opened(store, "base_model_disabled", cause)
        store.add_version("m", {}, "0" * 64, [BASE_B])
        result = reevaluate_version(store, "m", 2)
        alert = store.get_alert(aid)
        assert alert is not None and alert["state"] == "open"
        assert aid in result["carried_forward"]
        assert alert["current_version"] == 2
        assert alert["cause"]["identifier"] == PURL_B


def test_new_revision_of_unavailable_base_model_carries_alert(root: Path) -> None:
    with fresh(root, "unavailable", BASE_A) as store:
        cause = {"identifier": PURL_A, "base_model": PURL_A, "repo": REPO}
        aid = opened(store, "base_model_unavailable", cause)
        store.add_version("m", {}, "0" * 64, [BASE_B])
        reevaluate_version(store, "m", 2)
        assert state(store, aid) == "open"


def test_new_revision_of_disabled_hub_dataset_carries_alert(root: Path) -> None:
    with fresh(root, "hub-revision", HUB_DATASET_A) as store:
        cause = {"identifier": HUB_A, "dataset": HUB_A, "host": "huggingface", "disabled": True}
        aid = opened(store, "dataset_removed", cause)
        store.add_version("m", {}, "0" * 64, [HUB_DATASET_B])
        reevaluate_version(store, "m", 2)
        alert = store.get_alert(aid)
        assert alert is not None and alert["state"] == "open"
        assert alert["cause"]["identifier"] == HUB_B


def test_other_base_model_fixes_disabled_alert(root: Path) -> None:
    """Depending on a different repository is positive evidence the cause is gone."""
    with fresh(root, "other", BASE_A) as store:
        cause = {"identifier": PURL_A, "base_model": PURL_A, "repo": REPO}
        aid = opened(store, "base_model_disabled", cause)
        other = BASE_B | {
            "name": "owner/other",
            "identifier": f"pkg:huggingface/owner/other@{SHA_B}",
        }
        store.add_version("m", {}, "0" * 64, [other])
        reevaluate_version(store, "m", 2)
        assert state(store, aid) == "fixed"


def test_disabled_base_model_alert_follows_new_revision_through_a_check(root: Path) -> None:
    """After a re-pin, the hub still reports the repository disabled: one alert, still open,
    then cleared when the hub reports it enabled again."""
    normal = fixture_json("hf_upstream/model-normal")
    url = model_info_url(REPO)
    with fresh(root, "check", BASE_A) as store:
        run_check(store, Answers({url: normal | {"disabled": True}}), ["m"], ["hf-hub"])
        (alert,) = store.alerts_for("m", ["open"])
        store.add_version("m", {}, "0" * 64, [BASE_B])
        reevaluate_version(store, "m", 2)
        run_check(store, Answers({url: normal | {"disabled": True}}), ["m"], ["hf-hub"])
        assert [a["alert_id"] for a in store.alerts_for("m", ["open"])] == [alert["alert_id"]]
        run_check(store, Answers({url: normal | {"disabled": False}}), ["m"], ["hf-hub"])
        assert state(store, alert["alert_id"]) == "cleared"


def test_disabled_hub_dataset_alert_follows_new_revision_through_a_check(root: Path) -> None:
    normal = fixture_json("hf_upstream/dataset-disabled")
    url = dataset_info_url(DATA_REPO)
    with fresh(root, "hub-check", HUB_DATASET_A) as store:
        run_check(store, Answers({url: normal | {"disabled": True}}), ["m"], ["hf-hub"])
        (alert,) = store.alerts_for("m", ["open"])
        store.add_version("m", {}, "0" * 64, [HUB_DATASET_B])
        reevaluate_version(store, "m", 2)
        run_check(store, Answers({url: normal | {"disabled": True}}), ["m"], ["hf-hub"])
        assert [a["alert_id"] for a in store.alerts_for("m", ["open"])] == [alert["alert_id"]]


# --- F1 / A1: an unreadable Crossref answer is a failed read ------------------------------------


def _retracted(root: Path, name: str) -> tuple[Store, int]:
    store = fresh(root, name, {"kind": "dataset", "identifier": DOI, "pinned": True})
    store.set_routing(DOI, agency="Crossref")
    answer = {"message": {"DOI": DOI, "updated-by": [RETRACTION]}}
    run_check(store, Answers({works_url(DOI): answer}), ["m"], ["crossref"])
    (alert,) = store.alerts_for("m", ["open"])
    return store, alert["alert_id"]


@pytest.mark.parametrize(
    "body",
    [
        pytest.param({"message": []}, id="message-not-object"),
        pytest.param({"message": "ok"}, id="message-string"),
        pytest.param(
            {"message": {"DOI": DOI, "updated-by": {"type": "retraction"}}}, id="not-list"
        ),
        pytest.param({"message": {"DOI": DOI, "updated-by": "retraction"}}, id="string-list"),
        pytest.param({"message": {"DOI": DOI, "updated-by": [["retraction"]]}}, id="entry-not-obj"),
        pytest.param({"message": {"DOI": DOI, "updated-by": [{"source": "x"}]}}, id="no-type"),
        pytest.param({"message": {"DOI": DOI, "updated-by": [{"type": 7}]}}, id="type-not-text"),
        pytest.param({"message": {"DOI": "10.9999/other", "updated-by": []}}, id="other-doi"),
        pytest.param({"message-type": "work-list", "message": {"DOI": DOI}}, id="other-type"),
        pytest.param({"status": "failed", "message": {"DOI": DOI}}, id="status-failed"),
    ],
)
def test_malformed_crossref_answer_fails_and_keeps_retraction(root: Path, body: Any) -> None:
    store, aid = _retracted(root, "malformed")
    with store:
        outcome = run_check(store, Answers({works_url(DOI): body}), ["m"], ["crossref"])
        assert outcome.sources["crossref"].startswith("failed")
        assert state(store, aid) == "open"


# --- A2: a retraction gone from a well-formed answer is cleared, not withdrawn -----------------


def test_retraction_absent_from_wellformed_answer_is_cleared(root: Path) -> None:
    store, aid = _retracted(root, "absent")
    with store:
        answer = {"status": "ok", "message-type": "work", "message": {"DOI": DOI}}
        outcome = run_check(store, Answers({works_url(DOI): answer}), ["m"], ["crossref"])
        assert outcome.sources["crossref"] == "ok"
        assert state(store, aid) == "cleared"


def test_failed_crossref_read_keeps_retraction(root: Path) -> None:
    store, aid = _retracted(root, "timeout")
    with store:
        failure = SourceFailedError("crossref", "timeout")
        outcome = run_check(store, Answers({works_url(DOI): failure}), ["m"], ["crossref"])
        assert outcome.sources["crossref"] == "failed: timeout"
        assert state(store, aid) == "open"


# --- F2 / A3: only the source that reported a licence change can clear it ----------------------

CHANGED = {
    "data": {
        "attributes": {
            "url": "https://figshare.com/articles/dataset/test/123",
            "rightsList": [{"rightsIdentifier": "Apache-2.0"}],
        }
    }
}
RESTORED_ELSEWHERE = {"license": {"name": "MIT"}}
LICENSED = {"kind": "dataset", "identifier": DOI, "pinned": True}
LICENSED |= {"recorded_licence": "MIT", "licence_form": "spdx"}


@pytest.fixture
def licence_alert(root: Path) -> Iterator[tuple[Store, int]]:
    with fresh(root, "licence", LICENSED) as store:
        store.set_routing(DOI, agency="DataCite", repository="figshare", repository_id="123")
        run_check(store, Answers({doi_url(DOI): CHANGED}), ["m"], ["datacite"])
        (alert,) = store.alerts_for("m", ["open"])
        assert alert["cause"]["source"] == "datacite"
        yield store, alert["alert_id"]


def test_licence_alert_stays_open_when_originating_source_fails(
    licence_alert: tuple[Store, int],
) -> None:
    store, aid = licence_alert
    answers = Answers(
        {
            doi_url(DOI): SourceFailedError("datacite", "timeout"),
            article_url("123"): RESTORED_ELSEWHERE,
        }
    )
    outcome = run_check(store, answers, ["m"], ["datacite", "figshare"])
    assert outcome.sources == {"datacite": "failed: timeout", "figshare": "ok"}
    assert state(store, aid) == "open"


def test_licence_alert_stays_open_when_originating_source_not_asked(
    licence_alert: tuple[Store, int],
) -> None:
    store, aid = licence_alert
    run_check(store, Answers({article_url("123"): RESTORED_ELSEWHERE}), ["m"], ["figshare"])
    assert state(store, aid) == "open"


def test_licence_alert_cleared_by_originating_source(licence_alert: tuple[Store, int]) -> None:
    store, aid = licence_alert
    restored = json.loads(json.dumps(CHANGED))
    restored["data"]["attributes"]["rightsList"] = [{"rightsIdentifier": "MIT"}]
    run_check(store, Answers({doi_url(DOI): restored}), ["m"], ["datacite"])
    assert state(store, aid) == "cleared"


def test_licence_alert_needs_every_reporting_source_to_clear(
    licence_alert: tuple[Store, int],
) -> None:
    """DataCite and Figshare both report the change; DataCite alone returning is not enough."""
    store, aid = licence_alert
    changed_elsewhere = {"license": {"name": "Apache-2.0"}}
    answers = Answers({doi_url(DOI): CHANGED, article_url("123"): changed_elsewhere})
    run_check(store, answers, ["m"], ["datacite", "figshare"])
    restored = json.loads(json.dumps(CHANGED))
    restored["data"]["attributes"]["rightsList"] = [{"rightsIdentifier": "MIT"}]
    run_check(store, Answers({doi_url(DOI): restored}), ["m"], ["datacite"])
    assert state(store, aid) == "open"
    run_check(store, Answers({article_url("123"): RESTORED_ELSEWHERE}), ["m"], ["figshare"])
    assert state(store, aid) == "cleared"


# --- A4 migration: open repository-wide alerts written with a revision key are rekeyed ----------


def test_opening_a_store_rekeys_repository_alerts(root: Path) -> None:
    path = root / "old" / "md.db"
    zenodo = "10.5281/zenodo.1"
    with fresh(root, "old", BASE_A, HUB_DATASET_A) as store:
        base_cause = {"identifier": PURL_A, "base_model": PURL_A, "repo": REPO}
        disabled = opened(store, "base_model_disabled", base_cause)
        unavailable = opened(store, "base_model_unavailable", base_cause)
        hub_cause = {"identifier": HUB_A, "dataset": HUB_A, "host": "huggingface"}
        removed = opened(store, "dataset_removed", hub_cause)
        doi_removed = opened(store, "dataset_removed", {"identifier": zenodo, "host": "zenodo"})
        closed = opened(store, "base_model_disabled", base_cause | {"identifier": PURL_B})
        store.close_alert(closed, state="cleared")
    with Store(path, now=lambda: NOW) as store:
        keys = {aid: store.get_alert(aid)["cause_key"] for aid in (disabled, unavailable)}
        keys |= {aid: store.get_alert(aid)["cause_key"] for aid in (removed, doi_removed, closed)}
    assert keys == {
        disabled: "base_model_disabled:pkg:huggingface/owner/model",
        unavailable: "base_model_unavailable:pkg:huggingface/owner/model",
        removed: f"dataset_removed:hf-dataset:{DATA_REPO}",
        doi_removed: f"dataset_removed:{zenodo}",
        closed: f"base_model_disabled:{PURL_B}",
    }
    with Store(path, now=lambda: NOW) as store:  # a second open changes nothing
        assert store.get_alert(disabled)["cause_key"] == keys[disabled]


def test_rekeying_leaves_an_alert_whose_new_key_is_taken(root: Path) -> None:
    path = root / "taken" / "md.db"
    with fresh(root, "taken", BASE_A) as store:
        cause = {"identifier": PURL_A, "base_model": PURL_A, "repo": REPO}
        current = opened(
            store, "base_model_disabled", cause, "base_model_disabled:pkg:huggingface/owner/model"
        )
        old = opened(store, "base_model_disabled", cause)
    with Store(path, now=lambda: NOW) as store:
        assert store.get_alert(current)["cause_key"].endswith("/owner/model")
        assert store.get_alert(old)["cause_key"] == f"base_model_disabled:{PURL_A}"
        assert store.get_alert(old)["state"] == "open"


def test_rekeyed_alert_is_carried_and_cleared_by_the_hub(root: Path) -> None:
    normal = fixture_json("hf_upstream/model-normal")
    url = model_info_url(REPO)
    path = root / "carried" / "md.db"
    with fresh(root, "carried", BASE_A) as store:
        cause = {"identifier": PURL_A, "base_model": PURL_A, "repo": REPO}
        aid = opened(store, "base_model_disabled", cause)
    with Store(path, now=lambda: NOW) as store:
        run_check(store, Answers({url: normal | {"disabled": True}}), ["m"], ["hf-hub"])
        assert [a["alert_id"] for a in store.alerts_for("m", ["open"])] == [aid]
        run_check(store, Answers({url: normal | {"disabled": False}}), ["m"], ["hf-hub"])
        assert state(store, aid) == "cleared"

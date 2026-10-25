"""The base-model alert kinds (T043, T044; FR-011, FR-012, FR-016, constitution 1.0.2).

Each hub answer is a state derived in the test from the recordings under
``tests/fixtures/hf_upstream``: the reachable answer for ``openai-community/gpt2``
(``model-normal``), a refusal (the recorded 401 body of ``model-missing`` served at gpt2's URL, or
the same body with 403 or 404), a disabled answer (``model-normal`` with ``disabled: true``, the
shape recorded in ``model-disabled``) and a failed request (``model-normal`` replayed as a timeout).
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from conftest import fixture_json
from model_dependabot.lifecycle import UNAVAILABLE_STATEMENT, run_check
from model_dependabot.sources import hf
from model_dependabot.sources.fetcher import RecordedFetcher
from model_dependabot.store import Store

DAY0 = datetime(2026, 10, 24, 6, 0, tzinfo=UTC)
GPT2 = "openai-community/gpt2"
GPT2_SHA = "607a30d783dfa663caf39e06633721c8d4cfcd7e"
REPO_PURL = "pkg:huggingface/openai-community/gpt2"
PURL = f"{REPO_PURL}@{GPT2_SHA}"


class Clock:
    def __init__(self) -> None:
        self.now = DAY0

    def __call__(self) -> datetime:
        return self.now


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def store(tmp_path: Path, clock: Clock) -> Iterator[Store]:
    with Store(tmp_path / "md.db", now=clock) as opened:
        opened.add_model("m")
        entry = {"kind": "base_model", "identifier": PURL, "pinned": True, "name": GPT2}
        opened.add_version("m", {}, "0" * 64, [entry | {"version": GPT2_SHA}])
        yield opened


@pytest.fixture
def answers(derive_upstream: Callable[..., Path]) -> dict[str, Path]:
    body = fixture_json("hf_upstream/model-missing")
    url = hf.model_info_url(GPT2)

    def refusal(status: int) -> Path:
        return derive_upstream(extra={"r": {"url": url, "status": status, "body": body}})

    return {
        "reachable": derive_upstream(),
        "refused": refusal(401),
        "refused-403": refusal(403),
        "refused-404": refusal(404),
        "disabled": derive_upstream(
            changes={"hf_upstream/model-normal": lambda b: b | {"disabled": True}}
        ),
        "failed": derive_upstream(errors={"hf_upstream/model-normal": "timed out"}),
    }


def check(
    store: Store,
    clock: Clock,
    answers: dict[str, Path],
    answer: str,
    at: timedelta,
    trigger: str = "scheduled",
) -> Any:
    clock.now = DAY0 + at
    fetcher = RecordedFetcher(answers[answer])
    return run_check(store, fetcher, ["m"], ("hf-hub",), trigger=trigger)


def alerts(store: Store, kind: str, states: tuple[str, ...] = ("open",)) -> list[dict[str, Any]]:
    return [a for a in store.alerts_for("m", list(states)) if a["kind"] == kind]


def refused_events(store: Store) -> list[dict[str, Any]]:
    return [e for e in store.watch_events("m") if e["kind"] == "base_model_refused"]


H = timedelta(hours=1)
SHORT = timedelta(hours=24) - timedelta(seconds=5)


def test_disabled_opens_a_moderate_alert_at_once_with_the_hub_answer(
    store: Store, clock: Clock, answers: dict[str, Path]
) -> None:
    check(store, clock, answers, "disabled", 0 * H, trigger="on_demand")
    [alert] = alerts(store, "base_model_disabled")
    [observation] = store.observations(PURL, "hf-hub")
    # Keyed by the repository, not the revision (identity and clearance table).
    assert alert["cause_key"] == f"base_model_disabled:{REPO_PURL}"
    assert (alert["severity"], alert["severity_origin"]) == ("MODERATE", "policy")
    assert alert["cause"]["disabled"] is True
    assert [e["evidence_id"] for e in store.alert_evidence(alert["alert_id"])] == [
        observation["evidence_ref"]
    ]
    check(store, clock, answers, "disabled", 24 * H)
    assert len(alerts(store, "base_model_disabled")) == 1


def test_one_refusal_is_a_watch_event_and_no_alert(
    store: Store, clock: Clock, answers: dict[str, Path]
) -> None:
    check(store, clock, answers, "refused", 0 * H)
    assert alerts(store, "base_model_unavailable") == []
    [event] = refused_events(store)
    assert event["detail"]["http_status"] == 401


@pytest.mark.parametrize("answer", ["refused", "refused-403", "refused-404"])
def test_two_scheduled_refusals_24_hours_apart_open_a_low_alert(
    answer: str, store: Store, clock: Clock, answers: dict[str, Path]
) -> None:
    check(store, clock, answers, answer, 0 * H)
    check(store, clock, answers, answer, 24 * H)
    [alert] = alerts(store, "base_model_unavailable")
    refusals = store.observations(PURL, "hf-hub")
    assert alert["cause_key"] == f"base_model_unavailable:{REPO_PURL}"
    assert (alert["severity"], alert["severity_origin"]) == ("LOW", "policy")
    assert alert["cause"]["statement"] == "no longer publicly available (deleted or made private)"
    assert alert["cause"]["statement"] == UNAVAILABLE_STATEMENT
    assert [r["observed_at"] for r in alert["cause"]["refusals"]] == [
        "2026-10-24T06:00:00Z",
        "2026-10-25T06:00:00Z",
    ]
    assert sorted(e["evidence_id"] for e in store.alert_evidence(alert["alert_id"])) == sorted(
        r["evidence_ref"] for r in refusals
    )


def test_two_refusals_23_hours_apart_open_nothing(
    store: Store, clock: Clock, answers: dict[str, Path]
) -> None:
    check(store, clock, answers, "refused", 0 * H)
    check(store, clock, answers, "refused", 23 * H)
    assert alerts(store, "base_model_unavailable") == []
    assert len(refused_events(store)) == 1


def test_an_on_demand_refusal_does_not_count(
    store: Store, clock: Clock, answers: dict[str, Path]
) -> None:
    check(store, clock, answers, "refused", 0 * H)
    check(store, clock, answers, "refused", 30 * H, trigger="on_demand")
    assert alerts(store, "base_model_unavailable") == []


def test_a_failed_request_is_ignored(store: Store, clock: Clock, answers: dict[str, Path]) -> None:
    check(store, clock, answers, "refused", 0 * H)
    outcome = check(store, clock, answers, "failed", 12 * H)
    assert outcome.sources["hf-hub"].startswith("failed")
    check(store, clock, answers, "refused", 24 * H)
    assert len(alerts(store, "base_model_unavailable")) == 1


def test_reachable_again_clears_the_alert_with_that_observation_as_evidence(
    store: Store, clock: Clock, answers: dict[str, Path]
) -> None:
    check(store, clock, answers, "refused", 0 * H)
    check(store, clock, answers, "refused", 24 * H)
    check(store, clock, answers, "reachable", 48 * H, trigger="on_demand")
    assert alerts(store, "base_model_unavailable") == []
    [closed] = alerts(store, "base_model_unavailable", ("cleared",))
    reachable = store.observations(PURL, "hf-hub")[-1]
    assert reachable["outcome"] == "reachable"
    assert reachable["evidence_ref"] in [
        e["evidence_id"] for e in store.alert_evidence(closed["alert_id"])
    ]


def test_a_later_qualifying_run_after_cleared_opens_a_new_alert(
    store: Store, clock: Clock, answers: dict[str, Path]
) -> None:
    for answer, hours in (("refused", 0), ("refused", 24), ("reachable", 48)):
        check(store, clock, answers, answer, hours * H)
    check(store, clock, answers, "refused", 72 * H)
    assert alerts(store, "base_model_unavailable") == []
    check(store, clock, answers, "refused", 96 * H)
    [reopened] = alerts(store, "base_model_unavailable")
    [cleared] = alerts(store, "base_model_unavailable", ("cleared",))
    assert reopened["alert_id"] != cleared["alert_id"]
    assert [r["observed_at"] for r in reopened["cause"]["refusals"]] == [
        "2026-10-27T06:00:00Z",
        "2026-10-28T06:00:00Z",
    ]


def test_a_further_refusal_carries_the_open_alert_forward(
    store: Store, clock: Clock, answers: dict[str, Path]
) -> None:
    for hours in (0, 24, 48):
        check(store, clock, answers, "refused", hours * H)
    [alert] = alerts(store, "base_model_unavailable")
    assert len(alert["cause"]["refusals"]) == 3
    assert len(store.alert_evidence(alert["alert_id"])) == 3


def test_disabled_false_later_clears_the_disabled_alert_with_that_observation_as_evidence(
    store: Store, clock: Clock, answers: dict[str, Path]
) -> None:
    # Orchestrator disposition B4 (constitution 1.0.2): the source no longer shows the cause.
    check(store, clock, answers, "disabled", 0 * H)
    check(store, clock, answers, "reachable", 1 * H, trigger="on_demand")
    assert alerts(store, "base_model_disabled") == []
    [closed] = alerts(store, "base_model_disabled", ("cleared",))
    latest = store.observations(PURL, "hf-hub")[-1]
    assert latest["disabled"] in (0, False)
    assert latest["evidence_ref"] in [
        e["evidence_id"] for e in store.alert_evidence(closed["alert_id"])
    ]
    check(store, clock, answers, "disabled", 2 * H)
    assert len(alerts(store, "base_model_disabled")) == 1


def test_a_refusal_or_failure_after_disabled_does_not_clear_it(
    store: Store, clock: Clock, answers: dict[str, Path]
) -> None:
    check(store, clock, answers, "disabled", 0 * H)
    check(store, clock, answers, "refused", 1 * H)
    check(store, clock, answers, "failed", 2 * H)
    assert len(alerts(store, "base_model_disabled")) == 1

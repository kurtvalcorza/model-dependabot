"""Licence comparison and the licence alert and watch-event kinds (T037; FR-009, FR-010, FR-016).

Each declared licence is a state derived in the test from the recorded hub answer for
``openai-community/gpt2`` (``hf_upstream/model-normal``, ``cardData.license: "mit"``), the recorded
Figshare article (``figshare/cc-by-4.0``, ``license.name: "CC BY 4.0"``) or the recorded hub
dataset (``hf_upstream/dataset-disabled``, ``cardData.license: "apache-2.0"``).
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from model_dependabot.lifecycle import reevaluate_version, run_check
from model_dependabot.sources.fetcher import RecordedFetcher
from model_dependabot.store import Store

MOMENT = datetime(2026, 10, 24, 6, 0, tzinfo=UTC)
GPT2 = "openai-community/gpt2"
GPT2_SHA = "607a30d783dfa663caf39e06633721c8d4cfcd7e"
PURL = f"pkg:huggingface/openai-community/gpt2@{GPT2_SHA}"
FIGSHARE = "10.6084/m9.figshare.34763127.v1"
FIGSHARE_ID = "34763127"
KEY = "licence_changed:pkg:huggingface/openai-community/gpt2"  # keyed by repository (003)


@pytest.fixture
def store(tmp_path: Path) -> Store:
    with Store(tmp_path / "md.db", now=lambda: MOMENT) as opened:
        yield opened


def base_model(recorded: str | None = None, form: str | None = None) -> dict[str, Any]:
    return {
        "kind": "base_model",
        "identifier": PURL,
        "pinned": True,
        "name": GPT2,
        "version": GPT2_SHA,
        "recorded_licence": recorded,
        "licence_form": form,
    }


def register(store: Store, entries: list[dict[str, Any]], model_id: str = "m") -> int:
    if store.get_model(model_id) is None:
        store.add_model(model_id)
    return store.add_version(model_id, {}, "0" * 64, entries)


def card(licence: str | None) -> Callable[[dict[str, Any]], dict[str, Any]]:
    def change(body: dict[str, Any]) -> dict[str, Any]:
        if licence is None:
            body["cardData"].pop("license", None)
        else:
            body["cardData"]["license"] = licence
        return body

    return change


def check_with(
    store: Store, derive: Callable[..., Path], licence: str | None, model_id: str = "m"
) -> Any:
    root = derive(changes={"hf_upstream/model-normal": card(licence)})
    return run_check(store, RecordedFetcher(root), [model_id], ("hf-hub",))


def licence_alerts(store: Store, states: tuple[str, ...] = ("open",)) -> list[dict[str, Any]]:
    return [a for a in store.alerts_for("m", list(states)) if a["kind"] == "licence_changed"]


def licence_events(store: Store) -> dict[str, dict[str, Any]]:
    events = store.watch_events("m")
    return {e["kind"]: e for e in events if e["kind"].startswith("licence_")}


def test_a_real_change_opens_one_high_policy_alert_showing_both_licences(
    store: Store, derive_upstream: Callable[..., Path]
) -> None:
    register(store, [base_model("Apache-2.0", "spdx")])
    check_with(store, derive_upstream, "cc-by-nc-4.0")
    (alert,) = licence_alerts(store)
    assert alert["cause_key"] == KEY
    assert (alert["severity"], alert["severity_origin"]) == ("HIGH", "policy")
    cause = alert["cause"]
    assert (cause["identifier"], cause["recorded_licence"]) == (PURL, "Apache-2.0")
    assert (cause["recorded_from"], cause["source"]) == ("inventory", "hf-hub")
    assert (cause["declared_licence"], cause["declared_normalised"]) == (
        "cc-by-nc-4.0",
        "CC-BY-NC-4.0",
    )
    evidence = store.alert_evidence(alert["alert_id"])
    assert [e["source"] for e in evidence] == ["hf-hub"]


def test_a_spelling_or_case_difference_raises_nothing(
    store: Store, derive_upstream: Callable[..., Path]
) -> None:
    register(store, [base_model("Apache-2.0", "spdx")])
    check_with(store, derive_upstream, "apache-2.0")
    check_with(store, derive_upstream, "Apache-2.0")
    assert licence_alerts(store, ("open", "cleared")) == []
    assert licence_events(store) == {}


def test_a_figshare_alias_against_the_recorded_identifier_raises_nothing(
    store: Store, derive_upstream: Callable[..., Path]
) -> None:
    dataset = {
        "kind": "dataset",
        "identifier": FIGSHARE,
        "pinned": True,
        "recorded_licence": "CC-BY-4.0",
        "licence_form": "spdx",
    }
    register(store, [dataset])
    store.set_routing(FIGSHARE, agency="DataCite", repository="figshare", repository_id=FIGSHARE_ID)
    outcome = run_check(store, RecordedFetcher(derive_upstream()), ["m"], ("figshare",))
    assert outcome.sources == {"figshare": "ok"}
    [observation] = store.observations(FIGSHARE, "figshare")
    assert (observation["declared_licence"], observation["licence_form"]) == ("CC BY 4.0", "spdx")
    assert licence_alerts(store, ("open", "cleared")) == []
    assert licence_events(store) == {}


def test_a_then_b_then_c_keeps_one_alert_with_c_declared_and_both_observations(
    store: Store, derive_upstream: Callable[..., Path]
) -> None:
    register(store, [base_model("Apache-2.0", "spdx")])
    check_with(store, derive_upstream, "cc-by-nc-4.0")
    outcome = check_with(store, derive_upstream, "mit")
    (alert,) = licence_alerts(store, ("open", "cleared"))
    assert alert["state"] == "open"
    assert (alert["cause"]["declared_licence"], alert["cause"]["declared_normalised"]) == (
        "mit",
        "MIT",
    )
    assert alert["cause"]["recorded_licence"] == "Apache-2.0"
    assert len(store.alert_evidence(alert["alert_id"])) == 2
    assert outcome.models[0]["opened"] == []
    assert outcome.models[0]["carried_forward"] == [alert["alert_id"]]


def test_a_then_b_then_a_closes_the_alert_as_cleared_with_the_a_observation(
    store: Store, derive_upstream: Callable[..., Path]
) -> None:
    register(store, [base_model("Apache-2.0", "spdx")])
    check_with(store, derive_upstream, "cc-by-nc-4.0")
    outcome = check_with(store, derive_upstream, "apache-2.0")
    (alert,) = licence_alerts(store, ("open", "cleared"))
    assert alert["state"] == "cleared"
    assert outcome.models[0]["closed"] == [alert["alert_id"]]
    latest = store.observations(PURL, "hf-hub")[-1]
    assert latest["declared_licence"] == "apache-2.0"
    held = [e["evidence_id"] for e in store.alert_evidence(alert["alert_id"])]
    assert latest["evidence_ref"] in held
    # 001's re-open rule: the cause found again gives a new open alert.
    check_with(store, derive_upstream, "cc-by-nc-4.0")
    assert [a["state"] for a in licence_alerts(store, ("open", "cleared"))] == ["cleared", "open"]


def test_with_no_recorded_licence_the_first_observation_is_the_baseline(
    store: Store, derive_upstream: Callable[..., Path]
) -> None:
    register(store, [base_model()])
    first = check_with(store, derive_upstream, "apache-2.0")
    assert first.models[0]["opened"] == []
    assert licence_events(store) == {}
    check_with(store, derive_upstream, "Apache-2.0")
    assert licence_alerts(store) == []
    check_with(store, derive_upstream, "cc-by-nc-4.0")
    (alert,) = licence_alerts(store)
    assert (alert["cause"]["recorded_licence"], alert["cause"]["recorded_from"]) == (
        "Apache-2.0",
        "baseline",
    )


def test_an_unrecognised_declared_licence_records_a_watch_event_not_an_alert(
    store: Store, derive_upstream: Callable[..., Path]
) -> None:
    register(store, [base_model("MIT", "spdx")])
    check_with(store, derive_upstream, "llama3.1")
    assert licence_alerts(store) == []
    event = licence_events(store)["licence_unrecognised"]
    assert event["entry_identifier"] == PURL
    assert (event["detail"]["declared_licence"], event["detail"]["recorded_licence"]) == (
        "llama3.1",
        "MIT",
    )
    assert [e["source"] for e in event["evidence"]] == ["hf-hub"]


def test_an_unrecognised_recorded_licence_never_alerts(
    store: Store, derive_upstream: Callable[..., Path]
) -> None:
    register(store, [base_model("llama3.1", "unrecognised")])
    check_with(store, derive_upstream, "mit")
    check_with(store, derive_upstream, "llama3.1")
    assert licence_alerts(store, ("open", "cleared")) == []


def test_a_source_that_no_longer_declares_the_recorded_licence_records_licence_missing(
    store: Store, derive_upstream: Callable[..., Path]
) -> None:
    register(store, [base_model("MIT", "spdx")])
    check_with(store, derive_upstream, None)
    assert licence_alerts(store) == []
    event = licence_events(store)["licence_missing"]
    assert (event["entry_identifier"], event["detail"]["recorded_licence"]) == (PURL, "MIT")


def test_a_failed_source_changes_nothing(
    store: Store, derive_upstream: Callable[..., Path]
) -> None:
    register(store, [base_model("Apache-2.0", "spdx")])
    check_with(store, derive_upstream, "cc-by-nc-4.0")
    root = derive_upstream(errors={"hf_upstream/model-normal": "timed out"})
    outcome = run_check(store, RecordedFetcher(root), ["m"], ("hf-hub",))
    assert outcome.sources["hf-hub"].startswith("failed")
    (alert,) = licence_alerts(store)
    assert alert["state"] == "open"


def test_a_new_version_without_the_item_fixes_the_alert(
    store: Store, derive_upstream: Callable[..., Path]
) -> None:
    register(store, [base_model("Apache-2.0", "spdx")])
    check_with(store, derive_upstream, "cc-by-nc-4.0")
    (alert,) = licence_alerts(store)
    version = register(store, [])
    assert reevaluate_version(store, "m", version)["fixed"] == [alert["alert_id"]]

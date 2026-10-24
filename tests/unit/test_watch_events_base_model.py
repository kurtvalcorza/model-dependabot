"""Base-model watch events (T049; FR-013, research U7, data-model.md Watch event).

Every hub answer is derived in the test from the recorded ``hf_upstream/model-normal``
(``openai-community/gpt2``, ``gated: false``, ``cardData: {language, tags, license}``): a newer
``sha``, a ``cardData.new_version`` pointer, ``gated: "manual"`` (the value recorded in
``model-gated``) and a changed card. None of them is ever an alert.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from model_dependabot.lifecycle import run_check
from model_dependabot.sources import hf
from model_dependabot.sources.fetcher import RecordedFetcher
from model_dependabot.store import Store

MOMENT = datetime(2026, 10, 24, 6, 0, tzinfo=UTC)
GPT2 = "openai-community/gpt2"
GPT2_SHA = "607a30d783dfa663caf39e06633721c8d4cfcd7e"
NEWER_SHA = "0" * 40
PURL = f"pkg:huggingface/openai-community/gpt2@{GPT2_SHA}"
NAME = "hf_upstream/model-normal"
Change = Callable[[dict[str, Any]], dict[str, Any]]


@pytest.fixture
def store(tmp_path: Path) -> Iterator[Store]:
    with Store(tmp_path / "md.db", now=lambda: MOMENT) as opened:
        opened.add_model("m")
        entry = {"kind": "base_model", "identifier": PURL, "pinned": True, "name": GPT2}
        opened.add_version("m", {}, "0" * 64, [entry | {"version": GPT2_SHA}])
        yield opened


def check(store: Store, derive: Callable[..., Path], *changes: Change) -> Any:
    def change(body: dict[str, Any]) -> dict[str, Any]:
        for step in changes:
            body = step(body)
        return body

    root = derive(changes={NAME: change})
    return run_check(store, RecordedFetcher(root), ["m"], ("hf-hub",))


def sha(value: str) -> Change:
    return lambda body: body | {"sha": value}


def pointer(value: str) -> Change:
    def change(body: dict[str, Any]) -> dict[str, Any]:
        body["cardData"]["new_version"] = value
        return body

    return change


def gated(value: object) -> Change:
    return lambda body: body | {"gated": value}


def card(**fields: Any) -> Change:
    def change(body: dict[str, Any]) -> dict[str, Any]:
        body["cardData"] |= fields
        return body

    return change


def events(store: Store, kind: str) -> list[dict[str, Any]]:
    return [e for e in store.watch_events("m") if e["kind"] == kind]


def no_alerts(store: Store) -> None:
    assert store.alerts_for("m") == []


def test_the_recorded_answer_records_no_watch_event(
    store: Store, derive_upstream: Callable[..., Path]
) -> None:
    check(store, derive_upstream)
    check(store, derive_upstream)
    assert store.watch_events("m") == []
    no_alerts(store)


def test_a_newer_revision_shows_pinned_and_newest_once(
    store: Store, derive_upstream: Callable[..., Path]
) -> None:
    check(store, derive_upstream, sha(NEWER_SHA))
    check(store, derive_upstream, sha(NEWER_SHA))
    [event] = events(store, "base_model_new_revision")
    assert (event["detail"]["pinned"], event["detail"]["newest"]) == (GPT2_SHA, NEWER_SHA)
    assert len(event["evidence"]) == 1
    no_alerts(store)


def test_a_second_newer_revision_is_recorded_as_a_change(
    store: Store, derive_upstream: Callable[..., Path]
) -> None:
    check(store, derive_upstream, sha(NEWER_SHA))
    check(store, derive_upstream, sha("1" * 40))
    [event] = events(store, "base_model_new_revision")
    assert event["detail"]["newest"] == "1" * 40
    assert len(event["evidence"]) == 2


def test_a_new_version_pointer_appears_then_changes(
    store: Store, derive_upstream: Callable[..., Path]
) -> None:
    check(store, derive_upstream)
    check(store, derive_upstream, pointer("openai-community/gpt2-medium"))
    check(store, derive_upstream, pointer("openai-community/gpt2-medium"))
    [event] = events(store, "base_model_new_version_pointer")
    assert event["detail"]["new_version"] == "openai-community/gpt2-medium"
    assert len(event["evidence"]) == 1
    check(store, derive_upstream, pointer("openai-community/gpt2-large"))
    [event] = events(store, "base_model_new_version_pointer")
    assert event["detail"]["new_version"] == "openai-community/gpt2-large"
    assert len(event["evidence"]) == 2
    assert events(store, "card_changed") == []
    no_alerts(store)


@pytest.mark.parametrize("value", ["manual", "auto"])
def test_a_gating_change_is_recorded_once(
    value: str, store: Store, derive_upstream: Callable[..., Path]
) -> None:
    check(store, derive_upstream)
    check(store, derive_upstream, gated(value))
    check(store, derive_upstream, gated(value))
    [event] = events(store, "gating_changed")
    assert (event["detail"]["from"], event["detail"]["to"]) == ("false", value)
    assert len(event["evidence"]) == 1
    no_alerts(store)


def test_gating_seen_first_is_the_baseline(
    store: Store, derive_upstream: Callable[..., Path]
) -> None:
    check(store, derive_upstream, gated("manual"))
    assert events(store, "gating_changed") == []


def test_a_card_change_other_than_the_licence_is_recorded_once(
    store: Store, derive_upstream: Callable[..., Path]
) -> None:
    check(store, derive_upstream)
    check(store, derive_upstream, card(language="de"))
    check(store, derive_upstream, card(language="de"))
    [event] = events(store, "card_changed")
    before = hf.card_hash({"language": "en", "tags": ["exbert"]})
    after = hf.card_hash({"language": "de", "tags": ["exbert"]})
    assert (event["detail"]["previous_card_hash"], event["detail"]["card_hash"]) == (before, after)
    assert len(event["evidence"]) == 1
    no_alerts(store)


@pytest.mark.parametrize(
    "fields",
    [{"license_name": "x"}, {"license_link": "https://example.org/l"}, {"new_version": "a/b"}],
)
def test_licence_fields_and_the_pointer_are_not_card_changes(
    fields: dict[str, str], store: Store, derive_upstream: Callable[..., Path]
) -> None:
    check(store, derive_upstream)
    check(store, derive_upstream, card(**fields))
    assert events(store, "card_changed") == []

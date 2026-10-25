"""A renamed base model: the hub redirects the pinned name (held-out scoring HO-097).

The hub answers a renamed repository's model info with a 307 to the new name (the shape recorded
for a dataset in ``hf_upstream/dataset-moved``). Each state is derived in the test from the
recordings under ``tests/fixtures/hf_upstream``: the 307 is served at gpt2's URL with the new name
in ``redirected_to``; the new name answers with ``model-normal`` renamed to it, with
``disabled: true`` (the shape recorded in ``model-disabled``), with the recorded 401 body of
``model-missing``, with HTTP 500 or with an answer naming yet another repository.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from conftest import fixture_json
from model_dependabot.lifecycle import run_check
from model_dependabot.sources import hf
from model_dependabot.sources.fetcher import RecordedFetcher
from model_dependabot.store import Store

DAY0 = datetime(2026, 10, 24, 6, 0, tzinfo=UTC)
GPT2 = "openai-community/gpt2"
RENAMED = "openai-community/gpt2-renamed"
GPT2_SHA = "607a30d783dfa663caf39e06633721c8d4cfcd7e"
REPO_PURL = "pkg:huggingface/openai-community/gpt2"
PURL = f"{REPO_PURL}@{GPT2_SHA}"
H = timedelta(hours=1)


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


def _renamed(**fields: Any) -> dict[str, Any]:
    return fixture_json("hf_upstream/model-normal") | {"id": RENAMED} | fields


@pytest.fixture
def answers(derive_upstream: Callable[..., Path]) -> dict[str, Path]:
    moved = {
        "url": hf.model_info_url(GPT2),
        "status": 307,
        "body": "Temporary Redirect. Redirecting to " + hf.model_info_url(RENAMED),
        "redirected_to": hf.model_info_url(RENAMED),
    }
    target = hf.model_info_url(RENAMED)

    def to(status: int, body: Any) -> Path:
        return derive_upstream(
            extra={"moved": moved, "t": {"url": target, "status": status, "body": body}}
        )

    return {
        "disabled": derive_upstream(
            changes={"hf_upstream/model-normal": lambda b: b | {"disabled": True}}
        ),
        "moved-disabled": to(200, _renamed(disabled=True)),
        "moved-enabled": to(200, _renamed(disabled=False)),
        "moved-refused": to(401, fixture_json("hf_upstream/model-missing")),
        "moved-failed": to(500, {"error": "Internal Error"}),
        "moved-elsewhere": to(200, _renamed(id="someone-else/gpt2")),
        "refused": derive_upstream(
            extra={
                "r": {
                    "url": hf.model_info_url(GPT2),
                    "status": 401,
                    "body": fixture_json("hf_upstream/model-missing"),
                }
            }
        ),
    }


def check(store: Store, clock: Clock, answers: dict[str, Path], answer: str, at: timedelta) -> Any:
    clock.now = DAY0 + at
    fetcher = RecordedFetcher(answers[answer])
    return run_check(store, fetcher, ["m"], ("hf-hub",), trigger="scheduled")


def alerts(store: Store, kind: str, states: tuple[str, ...] = ("open",)) -> list[dict[str, Any]]:
    return [a for a in store.alerts_for("m", list(states)) if a["kind"] == kind]


def events(store: Store, kind: str) -> list[dict[str, Any]]:
    return [e for e in store.watch_events("m") if e["kind"] == kind]


def test_a_rename_to_a_disabled_repository_opens_base_model_disabled_on_the_pinned_name(
    store: Store, clock: Clock, answers: dict[str, Path]
) -> None:
    outcome = check(store, clock, answers, "moved-disabled", 0 * H)
    assert outcome.sources == {"hf-hub": "ok"}
    [moved] = events(store, "base_model_moved")
    assert (moved["detail"]["from"], moved["detail"]["to"]) == (GPT2, RENAMED)
    assert moved["detail"]["target_disabled"] is True
    [alert] = alerts(store, "base_model_disabled")
    # Keyed by the pinned repository, so a re-pin to the new name follows the carry-forward rules.
    assert alert["cause_key"] == f"base_model_disabled:{REPO_PURL}"
    assert (alert["cause"]["repo"], alert["cause"]["moved_to"]) == (GPT2, RENAMED)
    assert (alert["severity"], alert["severity_origin"]) == ("MODERATE", "policy")
    urls = {e["url"] for e in store.alert_evidence(alert["alert_id"])}
    assert urls == {hf.model_info_url(GPT2), hf.model_info_url(RENAMED)}


def test_a_rename_to_an_enabled_repository_is_a_watch_event_only(
    store: Store, clock: Clock, answers: dict[str, Path]
) -> None:
    check(store, clock, answers, "moved-enabled", 0 * H)
    [moved] = events(store, "base_model_moved")
    assert moved["detail"]["to"] == RENAMED
    assert moved["detail"]["target_disabled"] is False
    assert store.alerts_for("m", ["open"]) == []


def test_refusals_of_the_new_name_24_hours_apart_open_base_model_unavailable(
    store: Store, clock: Clock, answers: dict[str, Path]
) -> None:
    check(store, clock, answers, "moved-refused", 0 * H)
    assert alerts(store, "base_model_unavailable") == []
    check(store, clock, answers, "moved-refused", 24 * H)
    [alert] = alerts(store, "base_model_unavailable")
    assert alert["cause_key"] == f"base_model_unavailable:{REPO_PURL}"
    assert len(alert["cause"]["refusals"]) == 2
    assert all(r["redirected_to"] == hf.model_info_url(RENAMED) for r in alert["cause"]["refusals"])
    urls = {e["url"] for e in store.alert_evidence(alert["alert_id"])}
    assert hf.model_info_url(RENAMED) in urls


def test_a_refusal_then_a_rename_to_a_refused_name_keeps_the_refusal_run(
    store: Store, clock: Clock, answers: dict[str, Path]
) -> None:
    check(store, clock, answers, "refused", 0 * H)
    check(store, clock, answers, "moved-refused", 24 * H)
    assert len(alerts(store, "base_model_unavailable")) == 1


@pytest.mark.parametrize("answer", ["moved-failed", "moved-elsewhere"])
def test_a_redirect_alone_never_clears_or_ends_anything(
    store: Store, clock: Clock, answers: dict[str, Path], answer: str
) -> None:
    check(store, clock, answers, "disabled", 0 * H)
    check(store, clock, answers, "refused", 1 * H)
    check(store, clock, answers, answer, 2 * H)
    assert len(alerts(store, "base_model_disabled")) == 1
    [moved] = events(store, "base_model_moved")
    assert moved["detail"]["to"] == RENAMED
    assert moved["detail"]["target_error"]
    # The unreadable target wrote no observation, so the refusal run goes on.
    check(store, clock, answers, "refused", 25 * H)
    assert len(alerts(store, "base_model_unavailable")) == 1


def test_a_rename_to_an_enabled_repository_clears_an_open_disabled_alert(
    store: Store, clock: Clock, answers: dict[str, Path]
) -> None:
    check(store, clock, answers, "disabled", 0 * H)
    check(store, clock, answers, "moved-enabled", 1 * H)
    assert alerts(store, "base_model_disabled") == []
    [closed] = alerts(store, "base_model_disabled", ("cleared",))
    urls = {e["url"] for e in store.alert_evidence(closed["alert_id"])}
    assert hf.model_info_url(RENAMED) in urls


def test_a_database_from_before_base_model_moved_is_widened_when_opened(tmp_path: Path) -> None:
    path = tmp_path / "old.db"
    with Store(path, now=lambda: DAY0) as opened:
        opened.add_model("m")
        version = opened.add_version("m", {}, "0" * 64, [])
        kept = opened.record_watch_event(
            model_id="m",
            version=version,
            entry_identifier="x",
            kind="card_changed",
            detail={},
            evidence_ids=[],
        )
        # The watch_events table as written before the kind existed.
        old = (
            opened.conn.execute("SELECT sql FROM sqlite_master WHERE name = 'watch_events'")
            .fetchone()["sql"]
            .replace("'base_model_moved', ", "")
        )
        opened.conn.execute("PRAGMA foreign_keys = OFF")
        opened.conn.execute("PRAGMA legacy_alter_table = ON")
        with opened.conn:
            opened.conn.execute("ALTER TABLE watch_events RENAME TO watch_events_old")
            opened.conn.execute(old)
            opened.conn.execute("INSERT INTO watch_events SELECT * FROM watch_events_old")
            opened.conn.execute("DROP TABLE watch_events_old")
    with Store(path, now=lambda: DAY0) as reopened:
        added = reopened.record_watch_event(
            model_id="m",
            version=version,
            entry_identifier="x",
            kind="base_model_moved",
            detail={},
            evidence_ids=[],
        )
        assert {e["watch_event_id"] for e in reopened.watch_events("m")} == {kept, added}

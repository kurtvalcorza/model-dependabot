"""Base model availability end to end, offline (T045; quickstart.md section 4, SC-003).

``register`` records gpt2 as the base model; ``check --all --scheduled`` and on-demand ``check``
runs then replay hub answers derived from ``tests/fixtures/hf_upstream``: the reachable
``model-normal``, a refusal (the recorded 401 body of ``model-missing`` served at gpt2's URL), a
disabled answer (``model-normal`` with ``disabled: true``, the shape of ``model-disabled``) and a
timeout. The store's clock is set for each run, so the runs land at the stated times.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from conftest import fixture_json
from model_dependabot.cli import EXIT_OK, EXIT_SOURCE_FAILED, main, make_handlers
from model_dependabot.sources import hf
from model_dependabot.sources.fetcher import RecordedFetcher

GPT2 = "openai-community/gpt2"
GPT2_SHA = "607a30d783dfa663caf39e06633721c8d4cfcd7e"
PURL = f"pkg:huggingface/openai-community/gpt2@{GPT2_SHA}"
DAY0 = datetime(2026, 10, 24, 6, 0, tzinfo=UTC)
H = timedelta(hours=1)
SHORT = timedelta(hours=24) - timedelta(seconds=5)
STATEMENT = "no longer publicly available (deleted or made private)"


@pytest.fixture
def answers(derive_upstream: Callable[..., Path]) -> dict[str, RecordedFetcher]:
    body = fixture_json("hf_upstream/model-missing")
    extra = {"r": {"url": hf.model_info_url(GPT2), "status": 401, "body": body}}
    roots = {
        "reachable": derive_upstream(),
        "refused": derive_upstream(extra=extra),
        "disabled": derive_upstream(
            changes={"hf_upstream/model-normal": lambda b: b | {"disabled": True}}
        ),
        "failed": derive_upstream(errors={"hf_upstream/model-normal": "timed out"}),
    }
    return {name: RecordedFetcher(root) for name, root in roots.items()}


@pytest.fixture
def run(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], answers: dict[str, RecordedFetcher]
) -> Callable[..., tuple[int, Any]]:
    db = tmp_path / "db" / "md.db"
    manifest = tmp_path / "m" / "model.toml"
    manifest.parent.mkdir()
    lines = ["[model]", 'id = "based"', 'name = "Based"', 'owner = "Owner"', ""]
    lines += ["[base_model]", f'hub = "hf:{GPT2}"', f'revision = "{GPT2_SHA}"']
    manifest.write_text("\n".join(lines) + "\n", encoding="utf-8")
    clock = {"now": DAY0}

    def invoke(*argv: str, answer: str = "reachable", at: timedelta = 0 * H) -> tuple[int, Any]:
        clock["now"] = DAY0 + at
        handlers = make_handlers(fetcher=answers[answer], now=lambda: clock["now"])
        code = main([*argv, "--db", str(db), "--json"], handlers=handlers)
        out = capsys.readouterr().out
        return code, json.loads(out) if out.strip() else None

    code, _ = invoke("register", str(manifest), at=-1 * H)
    assert code == EXIT_OK
    return invoke


def scheduled(run: Callable[..., tuple[int, Any]], answer: str, at: timedelta) -> int:
    code, payload = run("check", "--all", "--scheduled", "--source", "hf-hub", answer=answer, at=at)
    assert payload["trigger"] == "scheduled"
    return code


def on_demand(run: Callable[..., tuple[int, Any]], answer: str, at: timedelta) -> int:
    code, payload = run("check", "based", "--source", "hf-hub", answer=answer, at=at)
    assert payload["trigger"] == "on_demand"
    return code


def listed(run: Callable[..., tuple[int, Any]]) -> tuple[list[dict[str, Any]], set[str]]:
    _, payload = run("alerts", "based")
    kinds = {e["kind"] for e in payload["watch_events"]}
    return [a for a in payload["alerts"] if a["kind"].startswith("base_model_")], kinds


def test_one_refusal_then_reachable_is_a_watch_event_only(
    run: Callable[..., tuple[int, Any]],
) -> None:
    assert scheduled(run, "refused", 0 * H) == EXIT_OK
    assert scheduled(run, "reachable", 24 * H) == EXIT_OK
    alerts, kinds = listed(run)
    assert alerts == []
    assert "base_model_refused" in kinds


def test_refusals_24_hours_apart_open_one_low_alert_with_both_refusals(
    run: Callable[..., tuple[int, Any]],
) -> None:
    scheduled(run, "refused", 0 * H)
    scheduled(run, "refused", 24 * H)
    [alert] = listed(run)[0]
    assert (alert["kind"], alert["severity"]) == ("base_model_unavailable", "LOW")
    assert alert["cause"]["statement"] == STATEMENT
    assert len(alert["cause"]["refusals"]) == 2
    assert len(alert["evidence"]) == 2


def test_daily_runs_a_few_seconds_short_alert_on_the_third_run(
    run: Callable[..., tuple[int, Any]],
) -> None:
    scheduled(run, "refused", 0 * H)
    scheduled(run, "refused", SHORT)
    assert listed(run)[0] == []
    scheduled(run, "refused", 2 * SHORT)
    [alert] = listed(run)[0]
    assert alert["kind"] == "base_model_unavailable"
    assert len(alert["cause"]["refusals"]) == 3


def test_on_demand_runs_and_a_timeout_between_change_nothing(
    run: Callable[..., tuple[int, Any]],
) -> None:
    scheduled(run, "refused", 0 * H)
    assert on_demand(run, "refused", 6 * H) == EXIT_OK
    assert scheduled(run, "failed", 12 * H) == EXIT_SOURCE_FAILED
    scheduled(run, "refused", 24 * H)
    [alert] = listed(run)[0]
    assert len(alert["cause"]["refusals"]) == 2


def test_an_on_demand_reachable_answer_ends_the_run(
    run: Callable[..., tuple[int, Any]],
) -> None:
    scheduled(run, "refused", 0 * H)
    on_demand(run, "reachable", 6 * H)
    scheduled(run, "refused", 24 * H)
    assert listed(run)[0] == []


def test_reachable_again_closes_the_alert_as_cleared(
    run: Callable[..., tuple[int, Any]],
) -> None:
    scheduled(run, "refused", 0 * H)
    scheduled(run, "refused", 24 * H)
    scheduled(run, "reachable", 48 * H)
    assert listed(run)[0] == []
    _, history = run("history", "based")
    [closed] = [h for h in history["history"] if h["kind"] == "base_model_unavailable"]
    assert closed["outcome"] == "cleared"


def test_disabled_opens_one_moderate_alert_at_once(run: Callable[..., tuple[int, Any]]) -> None:
    assert on_demand(run, "disabled", 0 * H) == EXIT_OK
    [alert] = listed(run)[0]
    assert (alert["kind"], alert["severity"], alert["severity_origin"]) == (
        "base_model_disabled",
        "MODERATE",
        "policy",
    )
    assert [e["source"] for e in alert["evidence"]] == ["hf-hub"]

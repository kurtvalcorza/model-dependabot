"""An imported code-free claim cannot hide a code-capable weight file (T015, US1, quickstart §2).

The forged inventory's only code-free entry is a pickle named ``model.safetensors`` on the hub at
a pinned commit (derived recordings, ``derive_format_check``); the honest inventory's
``model.safetensors`` is gpt2's real one beside gpt2's pickle. Both are checked with recorded
answers only.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from conftest import (
    FORGED_COMMIT,
    FORGED_REPO,
    GPT2_COMMIT,
    GPT2_PICKLE,
    GPT2_REPO,
    GPT2_SAFETENSORS,
    resolve,
)
from model_dependabot.cli import EXIT_OK, EXIT_SOURCE_FAILED, main, make_handlers
from model_dependabot.sources.fetcher import RecordedFetcher
from model_dependabot.store import Store

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
FORGED = FIXTURES / "boms" / "forged-code-free.json"
HONEST = FIXTURES / "boms" / "confirmed-code-free.json"
RECORDED = FIXTURES / "format_check"
RULE = "imported code-free claims count only once confirmed"

Cli = Callable[..., tuple[int, Any]]


@pytest.fixture
def cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> Cli:
    db = tmp_path / "md.db"

    def invoke(*argv: str, recordings: Path | None = None) -> tuple[int, Any]:
        handlers = make_handlers(fetcher=RecordedFetcher(recordings or tmp_path / "none"))
        code = main([*argv, "--db", str(db), "--json"], handlers=handlers)
        out = capsys.readouterr().out
        return code, json.loads(out) if out.strip() else None

    invoke.db = db  # type: ignore[attr-defined]
    return invoke


def _strict(cli: Cli, bom: Path, model_id: str) -> None:
    code, payload = cli("import", str(bom), "--model-id", model_id)
    assert code == EXIT_OK, payload
    assert cli("policy", model_id, "--format", "strict", "--by", "owner")[0] == EXIT_OK


def _check(cli: Cli, model_id: str, recordings: Path) -> tuple[int, Any]:
    return cli("check", model_id, "--source", "format-check", recordings=recordings)


def _policy_alerts(cli: Cli, model_id: str, state: str = "open") -> list[dict[str, Any]]:
    _, listed = cli("alerts", model_id, "--state", state)
    return [alert for alert in listed["alerts"] if alert["kind"] == "format_policy"]


def test_a_forged_code_free_claim_raises_the_policy_alert(
    cli: Cli, derive_format_check: Callable
) -> None:
    _strict(cli, FORGED, "forged")
    code, checked = _check(cli, "forged", derive_format_check())
    assert code == EXIT_OK, checked
    assert checked["sources"] == {"format-check": "ok"}
    [model] = checked["models"]
    assert [(c["outcome"], c["measured_format"]) for c in model["claim_checks"]] == [
        ("confirmed", None),
        ("contradicted", "pickle"),
    ]

    _, listed = cli("alerts", "forged")
    kinds = {event["kind"] for event in listed["watch_events"]}
    assert "format_claim_contradicted" in kinds
    [alert] = _policy_alerts(cli, "forged")
    cause = alert["cause"]
    assert cause["identifier"] == f"sha256:{GPT2_PICKLE}"
    assert cause["format"] == "pickle"  # the bytes win
    assert cause["rule"] == RULE
    assert cause["unconfirmed_claims"] == [
        {
            "identifier": f"sha256:{GPT2_PICKLE}",
            "location": resolve(FORGED_REPO, FORGED_COMMIT, "model.safetensors"),
            "outcome": "contradicted",
            "origin": "import",
        }
    ]
    sources = {evidence["source"] for evidence in alert["evidence"]}
    assert {"format-policy", "format-check"} <= sources


def test_an_honest_code_free_claim_is_confirmed_and_raises_nothing(cli: Cli) -> None:
    _strict(cli, HONEST, "honest")
    code, checked = _check(cli, "honest", RECORDED)
    assert code == EXIT_OK, checked
    with Store(cli.db) as store:
        latest = store.latest_claim_check("honest", 1, f"sha256:{GPT2_SAFETENSORS}")
    assert latest is not None and latest["outcome"] == "confirmed"
    assert _policy_alerts(cli, "honest") == []


def test_a_failed_check_leaves_the_alert_open_and_a_later_confirmation_clears_it(
    cli: Cli, derive_format_check: Callable
) -> None:
    _strict(cli, HONEST, "honest")
    hop = resolve(GPT2_REPO, GPT2_COMMIT, "model.safetensors")
    failing = derive_format_check({"busy": {"url": hop, "status": 503, "body": "busy"}})
    code, checked = _check(cli, "honest", failing)
    assert code == EXIT_SOURCE_FAILED
    assert checked["sources"]["format-check"].startswith("failed:")
    [alert] = _policy_alerts(cli, "honest")
    assert alert["cause"]["identifier"] == f"sha256:{GPT2_PICKLE}"
    assert alert["cause"]["rule"] == RULE
    assert alert["cause"]["unconfirmed_claims"] == [
        {
            "identifier": f"sha256:{GPT2_SAFETENSORS}",
            "location": resolve(GPT2_REPO, GPT2_COMMIT, "model.safetensors"),
            "outcome": "unverified",
            "origin": "import",
        }
    ]

    code, _ = _check(cli, "honest", RECORDED)
    assert code == EXIT_OK
    assert _policy_alerts(cli, "honest") == []
    [closed] = _policy_alerts(cli, "honest", "closed")
    assert closed["state"] == "cleared"
    confirming = [e for e in closed["evidence"] if e["source"] == "format-check"]
    assert confirming and confirming[-1]["matched_identifier"] == f"sha256:{GPT2_SAFETENSORS}"
    assert confirming[-1]["detail"]["outcome"] == "confirmed"


def test_the_text_views_say_whether_the_claim_is_verified(
    cli: Cli, capsys: pytest.CaptureFixture[str], tmp_path: Path, derive_format_check: Callable
) -> None:
    """US1 acceptance scenario 2: the text views name the claim, its origin and the rule."""
    _strict(cli, FORGED, "forged")
    handlers = make_handlers(fetcher=RecordedFetcher(tmp_path / "none"))

    def text(*argv: str) -> str:
        assert main([*argv, "--db", str(cli.db)], handlers=handlers) == EXIT_OK
        return capsys.readouterr().out

    assert "code-free claimed, unverified (origin import)" in text("inventory", "show", "forged")
    _check(cli, "forged", derive_format_check())
    assert "code-free claim contradicted (origin import)" in text("inventory", "show", "forged")
    listed = text("alerts", "forged")
    assert RULE in listed
    _, payload = cli("alerts", "forged")
    alert_id = payload["alerts"][0]["alert_id"]
    shown = text("alert", "show", str(alert_id))
    assert RULE in shown and "contradicted" in shown

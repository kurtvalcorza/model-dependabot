"""``format-check`` in the ``check`` contract (T018, contracts/cli.md, FR-002b, FR-024)."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from conftest import GPT2_COMMIT, GPT2_REPO, GPT2_SAFETENSORS, resolve
from model_dependabot.cli import CHECK_SOURCES, EXIT_OK, EXIT_SOURCE_FAILED, main, make_handlers
from model_dependabot.sources.fetcher import RecordedFetcher

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
HONEST = FIXTURES / "boms" / "confirmed-code-free.json"
SUMMARY_KEYS = {"model_id", "version", "opened", "carried_forward", "closed", "watch_events"}
Invoke = Callable[..., tuple[int, Any]]


@pytest.fixture
def cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> Invoke:
    db = tmp_path / "db" / "md.db"

    def invoke(*argv: str, recordings: Path = FIXTURES / "format_check") -> tuple[int, Any]:
        handlers = make_handlers(fetcher=RecordedFetcher(recordings))
        code = main([*argv, "--db", str(db), "--json"], handlers=handlers)
        out = capsys.readouterr().out
        return code, json.loads(out) if out.strip() else None

    assert invoke("import", str(HONEST), "--model-id", "m")[0] == EXIT_OK
    return invoke


def test_format_check_is_a_default_source() -> None:
    assert "format-check" in CHECK_SOURCES


def test_check_with_only_format_check_reports_it_and_the_claim_checks(cli: Invoke) -> None:
    code, payload = cli("check", "m", "--source", "format-check")
    assert code == EXIT_OK
    assert payload["sources"] == {"format-check": "ok"}
    [model] = payload["models"]
    assert set(model) >= SUMMARY_KEYS  # every existing field is still there
    assert model["claim_checks"] == [
        {
            "identifier": f"sha256:{GPT2_SAFETENSORS}",
            "outcome": "confirmed",
            "measured_format": None,
            "reason": None,
        },
        {
            "identifier": f"sha256:{GPT2_SAFETENSORS}",
            "outcome": "confirmed",
            "measured_format": "safetensors",
            "reason": None,
        },
        {
            "identifier": "sha256:7c5d3f4b8b76583b422fcb9189ad6c89d5d97a094541ce8932dce3ecabde1421",
            "outcome": "confirmed",
            "measured_format": None,
            "reason": None,
        },
    ]


def test_another_source_alone_does_not_run_format_check(cli: Invoke) -> None:
    code, payload = cli("check", "m", "--source", "osv")
    assert code == EXIT_OK
    assert "format-check" not in payload["sources"]
    assert "claim_checks" not in payload["models"][0]


def test_a_failed_format_check_is_reported_and_exits_2(
    cli: Invoke, derive_format_check: Callable
) -> None:
    hop = resolve(GPT2_REPO, GPT2_COMMIT, "model.safetensors")
    failing = derive_format_check({"busy": {"url": hop, "status": 503, "body": "busy"}})
    code, payload = cli("check", "m", "--source", "format-check", recordings=failing)
    assert code == EXIT_SOURCE_FAILED
    assert payload["sources"]["format-check"].startswith("failed: ")
    assert payload["models"][0]["claim_checks"] == []


def test_a_second_run_reads_nothing_and_reports_no_claim_checks(
    cli: Invoke, tmp_path: Path
) -> None:
    assert cli("check", "m", "--source", "format-check")[0] == EXIT_OK
    empty = tmp_path / "empty"
    empty.mkdir()
    code, payload = cli("check", "m", "--source", "format-check", recordings=empty)
    assert code == EXIT_OK
    assert payload["sources"] == {"format-check": "ok"}
    assert payload["models"][0]["claim_checks"] == []

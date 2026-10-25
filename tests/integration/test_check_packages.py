"""Register, check and list package alerts end to end, offline (T029; SC-002, SC-003, SC-007)."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from model_dependabot.cli import (
    EXIT_INVALID_INPUT,
    EXIT_OK,
    EXIT_SOURCE_FAILED,
    main,
    make_handlers,
)
from model_dependabot.sources.fetcher import RecordedFetcher

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
OSV = FIXTURES / "osv"
VULNERABLE = FIXTURES / "manifests" / "vulnerable.toml"
FIXED = FIXTURES / "manifests" / "fixed.toml"
MODEL = "pillow-model"


@pytest.fixture
def cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> Callable[..., tuple[int, Any]]:
    db = tmp_path / "md.db"

    def invoke(*argv: str, osv: Path = OSV) -> tuple[int, Any]:
        handlers = make_handlers(fetcher=RecordedFetcher(osv))
        code = main([*argv, "--db", str(db), "--json"], handlers=handlers)
        out = capsys.readouterr().out
        return code, json.loads(out) if out.strip() else None

    return invoke


def test_register_check_and_list_alerts(cli: Callable[..., tuple[int, Any]]) -> None:
    assert cli("register", str(VULNERABLE))[0] == EXIT_OK
    code, checked = cli("check", MODEL, "--source", "osv")
    assert code == EXIT_OK
    assert checked["sources"] == {"osv": "ok"}

    code, listed = cli("alerts", MODEL)
    assert code == EXIT_OK
    assert listed["model_id"] == MODEL
    assert listed["current_version"] == 1
    alerts = listed["alerts"]
    assert [alert["cause"]["advisory_id"] for alert in alerts] == [
        "GHSA-cp9v-662q-vvx9",
        "GHSA-24rc-8hj2-v98c",
    ]  # by severity: HIGH, then MODERATE
    first = alerts[0]
    assert first["kind"] == "package_advisory"
    assert first["state"] == "open"
    assert (first["severity"], first["severity_origin"]) == ("HIGH", "database_specific")
    assert first["cause"]["aliases"] == ["CVE-2026-112405"]
    assert (first["cause"]["package"], first["cause"]["version"]) == ("pillow", "12.3.0")
    assert first["cause"]["fixed"] == ["13.0.0"]
    assert first["opened_in_version"] == 1
    for alert in alerts:  # SC-003: source, retrieval time and the exact identifier matched
        [evidence] = alert["evidence"]
        assert evidence["source"] == "osv.dev"
        assert evidence["retrieved_at"].endswith("Z")
        assert evidence["matched_identifier"] == "pkg:pypi/pillow@12.3.0"
        assert evidence["detail"]["local_match"] is True
        assert len(evidence["body_sha256"]) == 64
    assert listed["watch_events"] == []
    assert listed["last_check"]["sources"] == {"osv": "ok"}

    code, shown = cli("alert", "show", str(first["alert_id"]))
    assert code == EXIT_OK
    assert shown["alert_id"] == first["alert_id"]
    assert shown["evidence"] == first["evidence"]


def test_an_unaffected_version_raises_nothing(cli: Callable[..., tuple[int, Any]]) -> None:
    assert cli("register", str(FIXED))[0] == EXIT_OK
    assert cli("check", MODEL)[0] == EXIT_OK
    code, listed = cli("alerts", MODEL, "--state", "all")
    assert code == EXIT_OK
    assert listed["alerts"] == []


def test_check_all_checks_every_model(cli: Callable[..., tuple[int, Any]]) -> None:
    assert cli("register", str(VULNERABLE))[0] == EXIT_OK
    code, checked = cli("check", "--all", "--source", "osv")
    assert code == EXIT_OK
    assert [model["model_id"] for model in checked["models"]] == [MODEL]


def test_a_failed_source_exits_2_and_changes_nothing(
    cli: Callable[..., tuple[int, Any]], derive_osv: Callable[..., Path]
) -> None:
    assert cli("register", str(VULNERABLE))[0] == EXIT_OK
    assert cli("check", MODEL)[0] == EXIT_OK
    _, before = cli("alerts", MODEL, "--state", "all")

    failing = derive_osv(errors={"querybatch-vulnerable": "timed out"})
    code, checked = cli("check", MODEL, osv=failing)
    assert code == EXIT_SOURCE_FAILED
    assert checked["sources"]["osv"].startswith("failed")

    _, after = cli("alerts", MODEL, "--state", "all")
    assert after["alerts"] == before["alerts"]
    assert after["watch_events"] == before["watch_events"]
    assert after["last_check"]["sources"]["osv"].startswith("failed")


def test_unknown_model_or_alert_is_invalid_input(cli: Callable[..., tuple[int, Any]]) -> None:
    assert cli("check", "no-such-model")[0] == EXIT_INVALID_INPUT
    assert cli("alerts", "no-such-model")[0] == EXIT_INVALID_INPUT
    assert cli("alert", "show", "999")[0] == EXIT_INVALID_INPUT

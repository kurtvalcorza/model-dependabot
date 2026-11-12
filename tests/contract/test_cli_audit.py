"""The ``inventory audit`` JSON contract and exit codes (T029, contracts/cli.md)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from model_dependabot.cli import EXIT_INVALID_INPUT, EXIT_OK, main, make_handlers
from model_dependabot.sources.fetcher import RecordedFetcher

NOW = datetime(2026, 11, 13, 9, 0, tzinfo=UTC)
SUMMARY = {
    "checked",
    "alerts_open",
    "watch_events",
    "entries",
    "verified",
    "declared_but_unverified",
    "conflicting",
    "unavailable",
    "gaps",
    "uncheckable",
    "sources_failed",
    "sources_stale",
    "sources_not_checked",
}
TOP = {
    "model_id",
    "version",
    "produced_at",
    "stale_after_hours",
    "statement",
    "summary",
    "findings",
    "assurance",
    "coverage",
}


@pytest.fixture
def audit(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    db = tmp_path / "md.db"
    manifest = tmp_path / "model.toml"
    manifest.write_text('[model]\nid = "m"\n\n[base_model]\nhub = "hf:o/base"\n', "utf-8")
    handlers = make_handlers(fetcher=RecordedFetcher(tmp_path / "none"), now=lambda: NOW)
    assert main(["register", str(manifest), "--db", str(db)], handlers=handlers) == EXIT_OK
    capsys.readouterr()

    def invoke(*argv: str) -> tuple[int, Any]:
        code = main(["inventory", "audit", *argv, "--db", str(db), "--json"], handlers=handlers)
        out = capsys.readouterr().out
        return code, json.loads(out) if out.strip() else None

    return invoke


def test_the_json_has_every_field_of_the_contract(audit) -> None:
    code, report = audit("m")
    assert code == EXIT_OK
    assert set(report) == TOP
    assert set(report["summary"]) == SUMMARY
    assert set(report["findings"]) == {"state", "alerts", "watch_events"}
    assert set(report["assurance"]) == {"entries", "undeclared_kinds"}
    assert set(report["coverage"]) == {"sources", "uncheckable"}
    assert report["produced_at"] == "2026-11-13T09:00:00Z"
    assert report["stale_after_hours"] == 24
    [entry] = report["assurance"]["entries"]
    assert set(entry) == {"kind", "identifier", "location", "status", "gap_reason", "claims"}
    [uncheckable] = report["coverage"]["uncheckable"]
    assert set(uncheckable) == {"kind", "identifier", "location", "reason"}


def test_weak_assurance_still_exits_0(audit) -> None:
    code, report = audit("m")
    assert code == EXIT_OK
    assert report["summary"]["gaps"] == 1 and report["summary"]["checked"] is False


@pytest.mark.parametrize(
    "argv", [("nobody",), ("m", "--version", "2"), ("m", "--stale-after", "0")]
)
def test_bad_input_exits_1(audit, argv: tuple[str, ...]) -> None:
    assert audit(*argv)[0] == EXIT_INVALID_INPUT


def test_stale_after_changes_only_staleness(audit) -> None:
    _, default = audit("m")
    _, longer = audit("m", "--stale-after", "72")
    assert longer["stale_after_hours"] == 72

    def without_staleness(report: dict[str, Any]) -> dict[str, Any]:
        copy = json.loads(json.dumps(report))
        copy.pop("stale_after_hours")
        copy["summary"].pop("sources_stale")
        for source in copy["coverage"]["sources"]:
            source.pop("stale")
        return copy

    assert without_staleness(default) == without_staleness(longer)

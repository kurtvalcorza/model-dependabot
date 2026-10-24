"""Auto-close on registration, end to end and offline (T045; quickstart.md section 5, SC-004).

Version 2 pins pillow at its fixed version; the alerts show ``fixed`` straight after ``register``,
with no check run and no source request.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from model_dependabot.cli import EXIT_OK, main, make_handlers
from model_dependabot.sources.fetcher import RecordedFetcher

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
VULNERABLE = FIXTURES / "manifests" / "vulnerable.toml"
FIXED = FIXTURES / "manifests" / "fixed.toml"
MODEL = "pillow-model"


def test_registering_a_fixing_version_closes_the_alerts_as_fixed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    db = tmp_path / "md.db"
    fetcher = RecordedFetcher(FIXTURES / "osv")
    handlers = make_handlers(fetcher=fetcher)

    def cli(*argv: str) -> tuple[int, Any]:
        code = main([*argv, "--db", str(db), "--json"], handlers=handlers)
        out = capsys.readouterr().out
        return code, json.loads(out) if out.strip() else None

    assert cli("register", str(VULNERABLE))[0] == EXIT_OK
    assert cli("check", MODEL, "--source", "osv")[0] == EXIT_OK
    _, before = cli("alerts", MODEL)
    assert [alert["state"] for alert in before["alerts"]] == ["open", "open"]
    seen = len(fetcher.requests)

    code, registered = cli("register", str(FIXED), "--model-id", MODEL)
    assert code == EXIT_OK
    assert registered["version"] == 2
    assert sorted(registered["alerts"]["fixed"]) == sorted(a["alert_id"] for a in before["alerts"])
    assert registered["alerts"]["carried_forward"] == []
    assert len(fetcher.requests) == seen  # no source is consulted (FR-014)

    code, listed = cli("alerts", MODEL, "--state", "all")
    assert code == EXIT_OK
    assert listed["current_version"] == 2
    assert listed["last_check"]["run_id"] == 1  # no check was needed (SC-004)
    for alert in listed["alerts"]:
        assert alert["state"] == "fixed"
        assert alert["closed_by_version"] == 2
        assert alert["closed_at"].endswith("Z")
        assert alert["evidence"][-1]["source"] == "inventory"
        assert alert["evidence"][-1]["detail"]["found"] == "pkg:pypi/pillow@13.0.0"

    _, still_open = cli("alerts", MODEL)
    assert still_open["alerts"] == []

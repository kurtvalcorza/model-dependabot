"""A newly published advisory appears at the next check (T029a, SC-006).

The first fixture set is derived from the recording: the batch answer as OSV would have given it
before the two pillow advisories were published (no match for either package).
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from model_dependabot.cli import EXIT_OK, main, make_handlers
from model_dependabot.sources.fetcher import RecordedFetcher

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
VULNERABLE = FIXTURES / "manifests" / "vulnerable.toml"
MODEL = "pillow-model"


def _before_publication(answer: dict[str, Any]) -> dict[str, Any]:
    return {"results": [{} for _ in answer["results"]]}


def test_a_new_advisory_opens_an_alert_at_the_next_check(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], derive_osv: Callable[..., Path]
) -> None:
    db = tmp_path / "md.db"

    def invoke(osv: Path, *argv: str) -> tuple[int, Any]:
        code = main(
            [*argv, "--db", str(db), "--json"], handlers=make_handlers(RecordedFetcher(osv))
        )
        out = capsys.readouterr().out
        return code, json.loads(out) if out.strip() else None

    earlier = derive_osv({"querybatch-vulnerable": _before_publication})
    assert invoke(earlier, "register", str(VULNERABLE))[0] == EXIT_OK
    assert invoke(earlier, "check", "--all")[0] == EXIT_OK
    _, listed = invoke(earlier, "alerts", MODEL)
    assert listed["alerts"] == []

    assert invoke(FIXTURES / "osv", "check", "--all")[0] == EXIT_OK
    _, listed = invoke(FIXTURES / "osv", "alerts", MODEL)
    assert sorted(alert["cause"]["advisory_id"] for alert in listed["alerts"]) == [
        "GHSA-24rc-8hj2-v98c",
        "GHSA-cp9v-662q-vvx9",
    ]
    assert all(alert["state"] == "open" for alert in listed["alerts"])

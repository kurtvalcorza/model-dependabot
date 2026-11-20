"""The ``--advice`` option of ``alert show`` (T017, contracts/cli.md, data-model.md, FR-004)."""

from __future__ import annotations

import io
import json
from contextlib import redirect_stderr, redirect_stdout
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from model_dependabot.assurance.advice import SEVERITY_NOTES, severity_note
from model_dependabot.cli import main, make_handlers
from model_dependabot.sources.fetcher import RecordedFetcher

NOW = datetime(2026, 11, 20, 9, 0, tzinfo=UTC)
VIEW_FIELDS = [
    "schema",
    "alert_id",
    "severity",
    "entry",
    "relationship",
    "runtime_use",
    "established",
    "not_established",
    "limitations",
    "claims",
    "impact",
    "owner_decision",
    "review_steps",
    "rule_doc",
]
ENTRY_FIELDS = [
    "status",
    "reason",
    "kind",
    "identifier",
    "matched_by",
    "in_current_version",
    "last_held_in_version",
    "opened_in_version",
    "closed_by_version",
    "places",
]


def run(db: Path, *argv: str) -> tuple[int, str]:
    out, err = io.StringIO(), io.StringIO()
    handlers = make_handlers(fetcher=RecordedFetcher(db.parent / "none"), now=lambda: NOW)
    with redirect_stdout(out), redirect_stderr(err):
        code = main([*argv, "--db", str(db)], handlers=handlers)
    return code, out.getvalue()


def keys(value: Any) -> list[str]:
    if isinstance(value, dict):
        return [k for key, item in value.items() for k in (key, *keys(item))]
    if isinstance(value, list):
        return [k for item in value for k in keys(item)]
    return []


def test_the_payload_is_today_s_plus_advice_last(advice_db: tuple[Path, dict[str, int]]) -> None:
    db, ids = advice_db
    for alert_id in ids.values():
        _, plain = run(db, "alert", "show", str(alert_id), "--json")
        _, advised = run(db, "alert", "show", str(alert_id), "--advice", "--json")
        before, after = json.loads(plain), json.loads(advised)
        assert list(after)[-1] == "advice"
        advice = after.pop("advice")
        assert after == before and list(after) == list(before)
        assert list(advice) == VIEW_FIELDS
        assert list(advice["entry"]) == ENTRY_FIELDS
        assert advice["schema"] == "advice/2"
        assert advice["alert_id"] == alert_id
        assert advice["impact"] == "impact undetermined"
        assert advice["severity"] == {
            "value": before["severity"],
            "origin": before["severity_origin"],
            "note": SEVERITY_NOTES[before["severity_origin"]],
        }
        assert not [k for k in keys(advice) if any(w in k for w in ("score", "weight", "rank"))]


def test_the_text_begins_with_the_bytes_of_today_s(advice_db: tuple[Path, dict[str, int]]) -> None:
    db, ids = advice_db
    for alert_id in ids.values():
        _, plain = run(db, "alert", "show", str(alert_id))
        _, advised = run(db, "alert", "show", str(alert_id), "--advice")
        assert advised.startswith(plain.removesuffix("\n") + "\n\nAdvice for #")
        assert not advised.endswith("\n\n")


@pytest.mark.parametrize(
    ("origin", "note"),
    [
        ("policy", "fixed by the service for this alert kind"),
        ("database_specific", "as published by the source"),
        ("cvss_v3", "band of the source's CVSS vector"),
        ("cvss_v4", "band of the source's CVSS vector"),
        ("unknown", "the source gave no severity"),
    ],
)
def test_each_severity_origin_has_its_fixed_note(origin: str, note: str) -> None:
    assert severity_note(origin) == note


def test_any_other_severity_origin_is_refused() -> None:
    assert set(SEVERITY_NOTES) == {"policy", "database_specific", "cvss_v3", "cvss_v4", "unknown"}
    with pytest.raises(ValueError, match="origin"):
        severity_note("estimated")


def test_an_unknown_alert_exits_1_with_and_without_advice(
    advice_db: tuple[Path, dict[str, int]],
) -> None:
    db, _ = advice_db
    for form in ((), ("--advice",)):
        for out in ((), ("--json",)):
            assert run(db, "alert", "show", "999", *form, *out)[0] == 1

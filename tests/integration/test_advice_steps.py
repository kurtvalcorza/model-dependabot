"""Review steps in the view (T032, US3 scenarios 1 to 3)."""

from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
from datetime import UTC, datetime
from pathlib import Path

import pytest

from model_dependabot import rules
from model_dependabot.cli import main, make_handlers
from model_dependabot.sources.fetcher import RecordedFetcher

NOW = datetime(2026, 11, 20, 9, 0, tzinfo=UTC)


def run(db: Path, *argv: str) -> str:
    out = io.StringIO()
    handlers = make_handlers(fetcher=RecordedFetcher(db.parent / "none"), now=lambda: NOW)
    with redirect_stdout(out):
        assert main([*argv, "--db", str(db)], handlers=handlers) == 0
    return out.getvalue()


def test_every_view_ends_with_its_rule_s_numbered_steps(
    advice_db: tuple[Path, dict[str, int]],
) -> None:
    db, ids = advice_db
    for alert_id in ids.values():
        payload = json.loads(run(db, "alert", "show", str(alert_id), "--advice", "--json"))
        advice = payload["advice"]
        texts = rules.texts_for(payload["rule_id"])
        assert advice["rule_doc"] == f"docs/rules/{payload['rule_id']}.md"
        steps = advice["review_steps"]
        if payload["state"] in ("open", "excepted"):
            assert len(steps) == len(texts.steps) + 1
        else:  # review round 1, M10-R6: no dismissal step for an alert that cannot be dismissed
            assert all("alert dismiss" not in step["text"] for step in steps)
            assert steps[-2]["text"].startswith(f"This alert is {payload['state']}, and only")
        assert steps[-1]["text"] == rules.CLOSING + texts.closes
        assert str(alert_id) in steps[0]["text"]
        text = run(db, "alert", "show", str(alert_id), "--advice")
        lines = text.rstrip("\n").splitlines()
        assert lines[-1] == f"    {len(steps)}. {rules.CLOSING}{texts.closes}"
        assert "  Review steps:" in lines


def test_a_rule_without_steps_fails_and_names_the_rule(tmp_path: Path) -> None:
    text = rules.RULE_TEXTS.read_text("utf-8")
    start = text.index("steps = [", text.index("[MDB401]"))
    end = text.index("]\n", start) + 2
    path = tmp_path / "rule-texts.toml"
    path.write_text(text[:start] + text[end:], encoding="utf-8")
    with pytest.raises(rules.RuleTextsError, match="MDB401"):
        rules.load_rule_texts(path)

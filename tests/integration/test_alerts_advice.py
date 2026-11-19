"""``alerts ID --advice`` (T036, FR-003, FR-018, US2 scenario 6, US4)."""

from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from model_dependabot.assurance.advice import EMPTY_MODEL_NOTE
from model_dependabot.cli import main, make_handlers
from model_dependabot.sources.fetcher import RecordedFetcher
from model_dependabot.store import Store

NOW = datetime(2026, 11, 20, 9, 0, tzinfo=UTC)
MODELS = ("advice-model", "unavailable-model", "record-model", "import-model")
STATES = ("open", "excepted", "closed", "all")


def run(db: Path, *argv: str) -> str:
    out = io.StringIO()
    handlers = make_handlers(fetcher=RecordedFetcher(db.parent / "none"), now=lambda: NOW)
    with redirect_stdout(out):
        assert main([*argv, "--db", str(db)], handlers=handlers) == 0
    return out.getvalue()


def without_advice(payload: dict[str, Any]) -> dict[str, Any]:
    payload = dict(payload)
    payload.pop("advice_summary", None)
    for name in ("alerts", "excepted"):
        payload[name] = [{k: v for k, v in item.items() if k != "advice"} for item in payload[name]]
    return payload


@pytest.fixture
def db(advice_db: tuple[Path, dict[str, int]]) -> Path:
    path, ids = advice_db
    build = __import__("advice_build")
    with Store(path, now=lambda: NOW) as store:
        build.except_weight_alert(store, ids["weight_file_scan"])
    return path


@pytest.mark.parametrize("state", STATES)
def test_one_view_per_alert_in_today_s_order(db: Path, state: str) -> None:
    for model in MODELS:
        plain = json.loads(run(db, "alerts", model, "--state", state, "--json"))
        advised = json.loads(run(db, "alerts", model, "--state", state, "--advice", "--json"))
        assert list(advised)[-1] == "advice_summary"
        assert without_advice(advised) == plain
        listed = advised["alerts"] + advised["excepted"]
        for item in listed:
            assert list(item)[-1] == "advice"
            assert item["advice"]["alert_id"] == item["alert_id"]
        assert all("advice" not in event for event in advised["watch_events"])
        summary = advised["advice_summary"]
        assert summary["alerts_listed"] == len(listed)
        assert summary["note"] == (EMPTY_MODEL_NOTE if not listed else None)


@pytest.mark.parametrize("state", STATES)
def test_the_text_begins_with_today_s_bytes(db: Path, state: str) -> None:
    for model in MODELS:
        plain = run(db, "alerts", model, "--state", state)
        advised = run(db, "alerts", model, "--state", state, "--advice")
        assert advised.startswith(plain.removesuffix("\n") + "\n\n")
        blocks = advised[len(plain.removesuffix("\n")) + 2 :].rstrip("\n").split("\n\n")
        payload = json.loads(run(db, "alerts", model, "--state", state, "--json"))
        ids = [item["alert_id"] for item in payload["alerts"] + payload["excepted"]]
        if ids:
            assert [b.splitlines()[0].split()[2] for b in blocks] == [f"#{i}" for i in ids]
        else:
            assert blocks == [EMPTY_MODEL_NOTE]


def test_a_model_with_no_open_alert_gives_the_empty_model_note(db: Path) -> None:
    advised = json.loads(
        run(db, "alerts", "record-model", "--state", "excepted", "--advice", "--json")
    )
    assert advised["advice_summary"] == {"alerts_listed": 0, "note": EMPTY_MODEL_NOTE}

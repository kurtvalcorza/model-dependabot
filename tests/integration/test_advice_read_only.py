"""The advisory view reads only (T015, FR-002, FR-003, SC-004; owner's ruling Q2).

Measured on a store already at the current schema (``tests/fixtures/advice/build.py``), so the
store's open has nothing to migrate: first a control shows that the plain commands leave the
database byte-identical, so a later failure is the view's.
"""

from __future__ import annotations

import hashlib
import io
from contextlib import redirect_stdout
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from model_dependabot.assurance.advice import advice_view
from model_dependabot.cli import main, make_handlers
from model_dependabot.store import Store

NOW = datetime(2026, 11, 20, 9, 0, tzinfo=UTC)


class SpyFetcher:
    """A fetcher that records every request and answers none."""

    def __init__(self) -> None:
        self.requests: list[Any] = []

    def __getattr__(self, name: str) -> Any:
        def record(*args: Any, **kwargs: Any) -> Any:
            self.requests.append((name, args, kwargs))
            raise AssertionError(f"the view asked a source: {name}")

        return record


def digests(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def run(db: Path, *argv: str, fetcher: Any) -> tuple[int, str]:
    out = io.StringIO()
    with redirect_stdout(out):
        code = main(
            [*argv, "--db", str(db)], handlers=make_handlers(fetcher=fetcher, now=lambda: NOW)
        )
    return code, out.getvalue()


def test_the_plain_commands_change_nothing_as_a_control(
    advice_db: tuple[Path, dict[str, int]],
) -> None:
    db, ids = advice_db
    before = digests(db.parent)
    spy = SpyFetcher()
    assert run(db, "alert", "show", str(ids["package_advisory"]), fetcher=spy)[0] == 0
    assert run(db, "alerts", "advice-model", "--state", "all", fetcher=spy)[0] == 0
    assert digests(db.parent) == before
    assert spy.requests == []


def test_building_every_view_makes_no_change(advice_db: tuple[Path, dict[str, int]]) -> None:
    db, _ = advice_db
    with Store(db, now=lambda: NOW) as store:
        before = store.conn.total_changes
        for model in store.model_ids():
            for alert in store.alerts_for(model):
                advice_view(store, alert)
        assert store.conn.total_changes == before


def test_the_advice_commands_leave_every_file_byte_identical(
    advice_db: tuple[Path, dict[str, int]],
) -> None:
    db, ids = advice_db
    before = digests(db.parent)
    spy = SpyFetcher()
    outputs = []
    for _ in range(2):
        for alert_id in ids.values():
            for form in ((), ("--json",)):
                code, text = run(db, "alert", "show", str(alert_id), "--advice", *form, fetcher=spy)
                assert code == 0
                outputs.append(text)
        for model in ("advice-model", "unavailable-model", "record-model", "import-model"):
            for form in ((), ("--json",)):
                argv = ("alerts", model, "--state", "all", "--advice", *form)
                code, text = run(db, *argv, fetcher=spy)
                assert code == 0
                outputs.append(text)
    assert digests(db.parent) == before
    assert spy.requests == []
    half = len(outputs) // 2
    assert outputs[:half] == outputs[half:], "two runs give identical bytes (FR-003)"

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


# --- review round 1, M10-R5: what the no-network check guards ------------------------------------
#
# The spy above only sees requests made through the handlers' fetcher, which the advice code is
# never handed. The checks below cover the other routes: every socket connection is already refused
# for this test run (``tests/conftest.py`` ``_block_network``, so any attempt would exit 3 and fail
# the exit-code assertions); here the default fetcher may not even be constructed, and the advice
# modules may import no source client or network module.


class _NoFetcher:
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        raise AssertionError("the advisory view constructed a fetcher")


def test_the_advice_commands_never_construct_a_fetcher(
    advice_db: tuple[Path, dict[str, int]], monkeypatch: Any
) -> None:
    import model_dependabot.cli as cli
    import model_dependabot.sources.fetcher as fetcher

    monkeypatch.setattr(cli, "UrlFetcher", _NoFetcher)
    monkeypatch.setattr(fetcher, "UrlFetcher", _NoFetcher)
    db, ids = advice_db
    handlers = make_handlers(fetcher=None, now=lambda: NOW)
    for argv in (
        ["alert", "show", str(ids["package_advisory"]), "--advice"],
        ["alerts", "advice-model", "--state", "all", "--advice", "--json"],
    ):
        out = io.StringIO()
        with redirect_stdout(out):
            assert main([*argv, "--db", str(db)], handlers=handlers) == 0


def test_the_advice_modules_import_no_source_or_network_module() -> None:
    import ast

    import model_dependabot.assurance.advice as advice
    import model_dependabot.assurance.affected as affected

    banned = ("model_dependabot.sources", "socket", "urllib", "http", "requests", "ssl")
    for module in (advice, affected):
        tree = ast.parse(Path(module.__file__).read_text("utf-8"))
        names = [a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names]
        names += [n.module or "" for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
        assert not [name for name in names if name.startswith(banned)], module.__name__

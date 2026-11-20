"""Shared helpers for the feature 011 lineage tests: the command line and derived hub answers."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from conftest import fixture_json
from model_dependabot.cli import main, make_handlers
from model_dependabot.sources import hf
from model_dependabot.sources.fetcher import RecordedFetcher

LINEAGE = Path(__file__).resolve().parent / "fixtures" / "lineage"
A = "0123456789abcdef0123456789abcdef01234567"
B = "89abcdef0123456789abcdef0123456789abcdef"
C = "fedcba9876543210fedcba9876543210fedcba98"
A2 = "1111111111111111111111111111111111111111"
DAY0 = datetime(2026, 11, 20, 6, 0, tzinfo=UTC)
H = timedelta(hours=1)


def manifest(name: str) -> str:
    return str(LINEAGE / f"{name}.toml")


def bom(name: str) -> str:
    return str(LINEAGE / f"{name}.json")


class Cli:
    """Runs the command line against one database with recorded answers only (offline)."""

    def __init__(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        self.db = tmp_path / "db" / "md.db"
        self.capsys = capsys
        self.none = tmp_path / "no-recordings"
        self.none.mkdir(exist_ok=True)

    def run(
        self, *argv: str, root: Path | None = None, at: timedelta = 0 * H, as_json: bool = True
    ) -> tuple[int, Any]:
        handlers = make_handlers(fetcher=RecordedFetcher(root or self.none), now=lambda: DAY0 + at)
        extra = ["--json"] if as_json else []
        code = main([*argv, "--db", str(self.db), *extra], handlers=handlers)
        captured = self.capsys.readouterr()
        if not as_json:
            return code, captured.out + captured.err
        return code, json.loads(captured.out) if captured.out.strip() else captured.err

    def ok(self, *argv: str, **kwargs: Any) -> Any:
        code, payload = self.run(*argv, **kwargs)
        assert code == 0, (argv, payload)
        return payload


def hub_answer(repo: str, **fields: Any) -> dict[str, Any]:
    """An ``extra`` recording: ``hf_upstream/model-normal`` answered for ``repo``."""
    body = fixture_json("hf_upstream/model-normal") | {"id": repo} | fields
    return {"url": hf.model_info_url(repo), "status": 200, "body": body}


def answers(derive_upstream: Callable[..., Path], **repos: dict[str, Any]) -> Path:
    """Hub answers for ``example-org`` repositories, keyed by a name for each recording."""
    extra = {name: hub_answer(spec.pop("repo"), **spec) for name, spec in repos.items()}
    return derive_upstream(extra=extra)

"""A marker-gated package end to end: register, check, ``alert show --advice`` (issue #28).

Model ``gated`` locks ``pillow==12.3.0`` only where ``sys_platform == "linux"``; model ``plain``
locks it with no marker. An offline OSV check (the recorded answers of ``derive_osv``) raises an
alert on each. The ``gated`` view names the marker and the ``plain`` view says it has none; neither
lists the limitation of an entry whose marker is not recorded.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from model_dependabot.assurance.advice import (
    MARKER_LIMITATION,
    MARKER_NOT_IMPORTED,
    MARKER_UNRESOLVED,
)
from model_dependabot.cli import EXIT_OK, main, make_handlers
from model_dependabot.sources.fetcher import RecordedFetcher

NOW = datetime(2026, 11, 20, 9, 0, tzinfo=UTC)
MARKER = 'sys_platform == "linux"'
HASH = "    --hash=sha256:3b8182a766685eaa002637e28b4ec8d6b18819a0c71f579bf0dbaa5830297cce\n"
# validators as in ``locks/vulnerable.txt``: the recorded OSV batch query names both packages.
VALIDATORS = (
    "validators==0.12.2 \\\n"
    "    --hash=sha256:172ac45f7d1944ce4beca3c5c53ca7c83e9759e39fd3fedc1cf28e2130268706\n"
)
LOCKS = {
    "gated": "pillow==12.3.0 ; sys_platform == 'linux' \\\n" + HASH + VALIDATORS,
    "plain": "pillow==12.3.0 \\\n" + HASH + VALIDATORS,
}
UNKNOWN = (MARKER_LIMITATION, MARKER_NOT_IMPORTED, MARKER_UNRESOLVED)


@pytest.fixture
def cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> Callable[..., Any]:
    db = tmp_path / "db" / "md.db"

    def invoke(*argv: str, recordings: Path | None = None, json_out: bool = True) -> Any:
        handlers = make_handlers(
            fetcher=RecordedFetcher(recordings or tmp_path / "none"), now=lambda: NOW
        )
        code = main([*argv, "--db", str(db), *(["--json"] if json_out else [])], handlers=handlers)
        out = capsys.readouterr().out
        assert code == EXIT_OK, out
        return json.loads(out) if json_out else out

    return invoke


@pytest.fixture
def alerts(
    cli: Callable[..., Any], tmp_path: Path, derive_osv: Callable[..., Path]
) -> dict[str, int]:
    found = {}
    for model_id, lock in LOCKS.items():
        root = tmp_path / model_id
        root.mkdir()
        (root / "requirements.txt").write_text(lock, encoding="utf-8")
        manifest = root / "model.toml"
        manifest.write_text(
            f'[model]\nid = "{model_id}"\n\n[environment]\nlock = "requirements.txt"\n',
            encoding="utf-8",
        )
        cli("register", str(manifest))
        cli("check", model_id, "--source", "osv", recordings=derive_osv())
        listed = cli("alerts", model_id)["alerts"]
        pillow = [a["alert_id"] for a in listed if a["cause"].get("package") == "pillow"]
        assert pillow, model_id
        found[model_id] = min(pillow)
    return found


def test_the_view_names_the_marker_of_a_marker_gated_package(
    cli: Callable[..., Any], alerts: dict[str, int]
) -> None:
    view = cli("alert", "show", str(alerts["gated"]), "--advice")["advice"]
    [place] = view["entry"]["places"]
    assert place["marker"] == {"state": "set", "expression": MARKER}
    limitations = [item["text"] for item in view["limitations"]]
    assert not set(limitations) & set(UNKNOWN)
    assert view["not_established"][-1]["text"] == (
        f"whether pillow is installed where the model runs: the lock installs it only where"
        f" `{MARKER}` holds, and this view does not evaluate the marker"
    )
    text = cli("alert", "show", str(alerts["gated"]), "--advice", json_out=False)
    assert f"    v1 manifest, [environment] lock, 12.3.0, marker {MARKER}\n" in text
    assert "marker not recorded" not in text


def test_a_package_with_no_marker_says_so_and_drops_the_limitation(
    cli: Callable[..., Any], alerts: dict[str, int]
) -> None:
    view = cli("alert", "show", str(alerts["plain"]), "--advice")["advice"]
    [place] = view["entry"]["places"]
    assert place["marker"] == {"state": "none", "expression": None}
    assert not {item["text"] for item in view["limitations"]} & set(UNKNOWN)
    assert view["not_established"][-1]["text"] == (
        "whether pillow is installed where the model runs"
    )
    text = cli("alert", "show", str(alerts["plain"]), "--advice", json_out=False)
    assert "    v1 manifest, [environment] lock, 12.3.0, no marker\n" in text


def test_inventory_show_lists_the_marker_only_where_there_is_one(
    cli: Callable[..., Any], alerts: dict[str, int]
) -> None:
    gated = {e["name"]: e for e in cli("inventory", "show", "gated")["entries"]}
    plain = {e["name"]: e for e in cli("inventory", "show", "plain")["entries"]}
    assert gated["pillow"]["marker"] == MARKER
    assert "marker" not in gated["validators"]
    assert "marker" not in plain["pillow"]

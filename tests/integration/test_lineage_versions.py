"""Alert identity across versions of a child's parents (T040, FR-025, FR-026, closure rules)."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from lineage_support import Cli

DYOUDIM = "sd-concepts-library/dyoudim-style"
SHA = "bb36f39d9eede01cc139dc4fadd193f1e4879fe3"


@pytest.fixture
def cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> Cli:
    return Cli(tmp_path, capsys)


def _write(tmp_path: Path, name: str, body: str) -> str:
    path = tmp_path / f"{name}.toml"
    path.write_text('[model]\nid = "example-moving"\n' + body, encoding="utf-8")
    return str(path)


def _parent(relationship: str, revision: str | None = SHA) -> str:
    pinned = "" if revision is None else f'revision = "{revision}"\n'
    return f'[[parents]]\nhub = "hf:{DYOUDIM}"\n{pinned}relationship = "{relationship}"\n'


def test_moving_retyping_a_gap_and_dropping_the_parent(
    cli: Cli, tmp_path: Path, derive_upstream: Callable[..., Path]
) -> None:
    legacy = f'[base_model]\nhub = "hf:{DYOUDIM}"\nrevision = "{SHA}"\n'
    cli.ok("register", _write(tmp_path, "v1", legacy))
    cli.ok("check", "example-moving", "--source", "hf-hub", root=derive_upstream())
    [opened] = cli.ok("alerts", "example-moving")["alerts"]
    assert opened["kind"] == "base_model_disabled"

    def register(name: str, body: str) -> dict:
        payload = cli.ok("register", _write(tmp_path, name, body), "--model-id", "example-moving")
        [alert] = cli.ok("alerts", "example-moving", "--state", "all")["alerts"]
        assert alert["alert_id"] == opened["alert_id"]
        return alert | {"_payload": payload}

    moved = register("v2", _parent("fine-tuned-from"))  # FR-025: carried forward, not reopened
    assert (moved["state"], moved["current_version"]) == ("open", 2)
    retyped = register("v3", _parent("quantized-from"))  # a type change alone carries it forward
    assert (retyped["state"], retyped["current_version"]) == ("open", 3)
    gap = register("v4", _parent("adapter-for", revision=None))  # FR-026: a gap never fixes
    assert gap["state"] == "open"
    dropped = register("v5", "")
    assert (dropped["state"], dropped["closed_by_version"]) == ("fixed", 5)

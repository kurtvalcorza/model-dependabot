"""The CLI baseline replay (T007, FR-016, SC-002, research R9).

Every invocation recorded from the build before feature 010 by ``tools/record_cli_baseline.py``
(``tests/fixtures/cli_baseline/pre-010-baseline.json``) is replayed on the current build, without
``--advice``, and its stdout, stderr and exit code compared byte for byte. The file's recorded
``src`` tree and its SHA-256 are pinned: a re-record fails here until the owner updates the pin.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
BASELINE_FILE = FIXTURES / "cli_baseline" / "pre-010-baseline.json"
# The src tree of the build before feature 010 (research R9).
EXPECTED_TREE = "4ca0c708b930870cbf5bce02b3f2ef20f4797882"
# Pinned: a re-record is an owner decision, recorded in
# specs/010-actionable-alert-view/validation.md.
BASELINE_SHA256 = "0dc6652e4afac576d291b5ba851bbfc07d9d7c82949a9ffb1866db3c72d650ac"


def _scenarios() -> ModuleType:
    name = "cli_baseline_scenarios"
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(
            name, FIXTURES / "cli_baseline" / "scenarios.py"
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


def test_the_baseline_is_the_pinned_recording() -> None:
    raw = BASELINE_FILE.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == BASELINE_SHA256
    assert json.loads(raw)["src_tree"] == EXPECTED_TREE


@pytest.fixture(scope="module")
def replayed(tmp_path_factory: pytest.TempPathFactory, craft: ModuleType) -> list[dict[str, Any]]:
    return _scenarios().run_all(tmp_path_factory.mktemp("cli-baseline"), craft)


def test_every_invocation_replays_byte_for_byte(replayed: list[dict[str, Any]]) -> None:
    recorded = json.loads(BASELINE_FILE.read_text("utf-8"))["invocations"]
    assert [item["name"] for item in replayed] == [item["name"] for item in recorded]
    for now, then in zip(replayed, recorded, strict=True):
        assert now["argv"] == then["argv"], then["name"]
        assert now["exit_code"] == then["exit_code"], then["name"]
        assert now["stdout"] == then["stdout"], then["name"]
        assert now["stderr"] == then["stderr"], then["name"]

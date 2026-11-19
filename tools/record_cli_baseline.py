"""Record the CLI baseline of feature 010 once, from the build before it (T003, FR-016, R9).

Builds the store of ``tests/fixtures/cli_baseline/scenarios.py`` in a temporary directory, offline
(recorded answers only), runs every named invocation and writes, per invocation, its argv, stdout,
stderr and exit code to ``tests/fixtures/cli_baseline/pre-010-baseline.json``, together with the
commit and the ``git rev-parse HEAD:src`` tree it was recorded from. Run it from the repository
root on the build before feature 010 only, giving the ``src`` tree that build must have:

    uv run python tools/record_cli_baseline.py 4ca0c708b930870cbf5bce02b3f2ef20f4797882

It refuses (exit 1, nothing written) unless ``src/`` has no uncommitted change, ``HEAD:src`` equals
the tree given and, when the baseline file exists, equals the tree recorded in it.
``tests/integration/test_cli_baseline.py`` replays the invocations on the current build and
compares them byte for byte (SC-002).
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
OUT = FIXTURES / "cli_baseline" / "pre-010-baseline.json"


def _load(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _git(*argv: str) -> str:
    return subprocess.run(
        ["git", *argv], capture_output=True, text=True, check=True, cwd=ROOT
    ).stdout.strip()


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: record_cli_baseline.py EXPECTED_SRC_TREE", file=sys.stderr)
        return 1
    expected = argv[0]
    if _git("status", "--porcelain", "--", "src"):
        print("src/ has uncommitted changes: record from a clean pre-010 build", file=sys.stderr)
        return 1
    tree = _git("rev-parse", "HEAD:src")
    if tree != expected:
        print(f"HEAD:src is {tree}, not the expected {expected}", file=sys.stderr)
        return 1
    if OUT.exists():
        recorded = json.loads(OUT.read_text("utf-8")).get("src_tree")
        if recorded != tree:
            print(f"{OUT.name} was recorded from src tree {recorded}, not {tree}", file=sys.stderr)
            return 1
    craft = _load("craft_pickles", FIXTURES / "pickles" / "craft.py")
    scenarios = _load("cli_baseline_scenarios", FIXTURES / "cli_baseline" / "scenarios.py")
    with tempfile.TemporaryDirectory() as work:
        invocations = scenarios.run_all(Path(work), craft)
    baseline = {
        "recorded_from": _git("rev-parse", "--short", "HEAD"),
        "src_tree": tree,
        "invocations": invocations,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(baseline, indent=1) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {OUT.relative_to(ROOT).as_posix()}: {len(invocations)} invocations")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

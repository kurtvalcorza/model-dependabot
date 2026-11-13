"""Record the default-policy equivalence baseline once, from the build before feature 004 (T005).

Runs every scenario of ``tests/fixtures/equivalence/scenarios.py`` in a temporary directory, offline
(recorded answers only), and writes their alerts and watch events, without ids and times, to
``tests/fixtures/equivalence/pre-004-baseline.json``. Run it from the repository root on the
pre-004 build only:

    uv run python tools/record_equivalence_baseline.py

``tests/integration/test_default_equivalence.py`` replays the same scenarios on the current build
and compares them with the file (SC-002, research S10). No weight file is loaded: the dangerous
pickle is built into the temporary directory by ``tests/fixtures/pickles/craft.py``.
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
OUT = FIXTURES / "equivalence" / "pre-004-baseline.json"


def _load(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def main() -> int:
    craft = _load("craft_pickles", FIXTURES / "pickles" / "craft.py")
    scenarios = _load("equivalence_scenarios", FIXTURES / "equivalence" / "scenarios.py")

    def git(*argv: str) -> str:
        return subprocess.run(
            ["git", *argv], capture_output=True, text=True, check=True, cwd=ROOT
        ).stdout.strip()

    commit = git("rev-parse", "--short", "HEAD")
    # The tree of src/ at that commit: equal to the tree of src/ on the pre-004 main.
    tree = git("rev-parse", "HEAD:src")
    if git("status", "--porcelain", "--untracked-files=no", "--", "src"):
        print("src/ has uncommitted changes: record from a clean pre-004 build", file=sys.stderr)
        return 1
    recorded = {}
    for name in scenarios.SCENARIOS:
        with tempfile.TemporaryDirectory() as work:
            recorded[name] = scenarios.run(name, Path(work), craft)
        print(f"{name}: recorded")
    baseline = {"recorded_from": commit, "src_tree": tree, "scenarios": recorded}
    OUT.write_text(
        json.dumps(baseline, indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
    )
    print(f"wrote {OUT.relative_to(ROOT).as_posix()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

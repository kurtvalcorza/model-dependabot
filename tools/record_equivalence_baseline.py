"""Record the default-policy equivalence baseline once, from the build before feature 004 (T005).

Runs every scenario of ``tests/fixtures/equivalence/scenarios.py`` in a temporary directory, offline
(recorded answers only), and writes their alerts and watch events, without ids and times, to
``tests/fixtures/equivalence/pre-004-baseline.json``. Run it from the repository root on the
pre-004 build only:

    uv run python tools/record_equivalence_baseline.py

Feature 011 records its own baseline with the same tool (T005, research L11): ``--scenarios`` names
another scenarios module, ``--out`` the file to write, and ``--expect-src-tree`` refuses to record
unless ``git rev-parse HEAD:src`` is the given tree; the defaults are feature 004's.

``tests/integration/test_default_equivalence.py`` replays the same scenarios on the current build
and compares them with the file (SC-002, research S10). No weight file is loaded: the dangerous
pickle is built into the temporary directory by ``tests/fixtures/pickles/craft.py``.
"""

from __future__ import annotations

import argparse
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


def _arguments(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Record an equivalence baseline.")
    parser.add_argument(
        "--scenarios",
        type=Path,
        default=FIXTURES / "equivalence" / "scenarios.py",
        help="the scenarios module (default: feature 004's)",
    )
    parser.add_argument("--out", type=Path, default=OUT, help="the baseline file to write")
    parser.add_argument(
        "--expect-src-tree",
        metavar="TREE",
        help="refuse to record unless `git rev-parse HEAD:src` is TREE (feature 011, review R8)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _arguments(sys.argv[1:] if argv is None else argv)
    craft = _load("craft_pickles", FIXTURES / "pickles" / "craft.py")
    module = args.scenarios.resolve()
    name = "equivalence_scenarios" if module.name == "scenarios.py" else module.stem
    scenarios = _load(name, module)

    def git(*argv: str) -> str:
        return subprocess.run(
            ["git", *argv], capture_output=True, text=True, check=True, cwd=ROOT
        ).stdout.strip()

    commit = git("rev-parse", "--short", "HEAD")
    # The tree of src/ at that commit: equal to the tree of src/ on the build recorded from.
    tree = git("rev-parse", "HEAD:src")
    if git("status", "--porcelain", "--untracked-files=no", "--", "src"):
        print("src/ has uncommitted changes: record from a clean build", file=sys.stderr)
        return 1
    if args.expect_src_tree is not None and tree != args.expect_src_tree:
        print(f"HEAD:src is {tree}, not the expected {args.expect_src_tree}", file=sys.stderr)
        return 1
    recorded = {}
    for name in scenarios.SCENARIOS:
        with tempfile.TemporaryDirectory() as work:
            recorded[name] = scenarios.run(name, Path(work), craft)
        print(f"{name}: recorded")
    baseline = {"recorded_from": commit, "src_tree": tree, "scenarios": recorded}
    out = args.out.resolve()
    out.write_text(
        json.dumps(baseline, indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
    )
    print(f"wrote {out.relative_to(ROOT).as_posix()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

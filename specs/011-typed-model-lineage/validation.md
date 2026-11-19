# Validation: Multi-parent, Typed Model Lineage

Recorded by the builder on 2026-11-20, on Windows 11 with Python 3.13 (`uv run`), offline. CI runs
the same gates on Ubuntu with Python 3.12; that platform was not run here.

## Baseline (T005)

On `main` at `6e146c1` (feature 010 merged; `src` tree
`c66a0b582c9dd4167396a2f977fef51fe0e7f631`), before any feature 011 code, each gate run on its own,
no pipe:

| Gate | Exit | Counts |
| :-- | :-- | :-- |
| `uv sync --frozen` | 0 | |
| `uv run pytest -q` | 0 | 1907 passed, 6 skipped, 13 deselected (1556 s) |
| `uv run ruff check` | 0 | All checks passed |
| `uv run ruff format --check` | 0 | 319 files already formatted |

The pytest run collected (and so imported) every module of `6e146c1` before any 011 file was
written; it ran for 26 minutes while the first 011 files were written. The two ruff gates were run
on an export of `6e146c1` (`git archive`) with the locked ruff, because the worktree held new files
by the time the pytest run ended.

## Equivalence baseline (T005, SC-001)

`tools/record_equivalence_baseline.py --scenarios tests/fixtures/equivalence/lineage_scenarios.py
--out tests/fixtures/equivalence/pre-011-baseline.json --expect-src-tree
c66a0b582c9dd4167396a2f977fef51fe0e7f631` recorded twelve `[base_model]` scenarios from commit
`0037f43` (the constitution amendment only; its `src` tree is that of `6e146c1`) with `src/` clean.
The same command with `--expect-src-tree 0000` was refused (exit 1, nothing written). The baseline
holds, per scenario, the alerts, watch events, inventory entries and every command's exit code;
`tests/integration/test_lineage_equivalence.py` compares SC-001's fields of each replay with it.

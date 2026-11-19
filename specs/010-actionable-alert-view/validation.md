# Validation: An Actionable Alert View for Model Maintainers

Recorded by the builder on 2026-11-19, on Windows 11 with Python 3.13 (`uv run`), offline. CI runs
the same three gates on Ubuntu with Python 3.12; that platform was not run here.

## Baseline (T001)

On `main` at `6d40ae3` (the commit this branch is based on; `src` tree
`4ca0c708b930870cbf5bce02b3f2ef20f4797882`, equal to the planning commit `47ebfbe`), before any
change, each gate run on its own, no pipe:

| Gate | Exit | Counts |
| :-- | :-- | :-- |
| `uv run pytest -q` | 0 | 1707 passed, 6 skipped, 13 deselected (2168 s) |
| `uv run ruff check` | 0 | All checks passed |
| `uv run ruff format --check` | 0 | 294 files already formatted |

The two ruff gates were run on an export of `6d40ae3` (`git archive`) with the locked ruff 0.17.2,
because the worktree already held new files by the time the pytest run ended.

## CLI baseline (T003, T007)

`tools/record_cli_baseline.py 4ca0c708b930870cbf5bce02b3f2ef20f4797882` recorded 44 invocations
(22 named invocations, text and `--json`) from `6d40ae3` with `src/` clean, into
`tests/fixtures/cli_baseline/pre-010-baseline.json`, SHA-256
`0dc6652e4afac576d291b5ba851bbfc07d9d7c82949a9ffb1866db3c72d650ac` (pinned in
`tests/integration/test_cli_baseline.py`). The recorder refused a wrong expected tree (exit 1,
nothing written). Two dry runs in different temporary directories gave identical bytes.

Mutation check: `alert_line` in `src/model_dependabot/reports.py` changed from `#{alert_id}` to
`%{alert_id}`; `test_every_invocation_replays_byte_for_byte` failed (1 failed, 1 passed); the change
was reverted and `git diff` on the file was empty again.

## Replays after the feature (T038)

With every `src/` change in place: `test_cli_baseline.py` (2 passed), `test_advice_read_only.py`
(3 passed, `alert show --advice` and `alerts --advice`, text and JSON), `test_exit_codes_advice.py`
and `test_alerts_advice.py` pass; counts are in the final run below.

## One alert per family, text view alone (T043, SC-005)

From the fixture store of `tests/fixtures/advice/build.py`:

| Family | Entry | Relationship | Established | Next step |
| :-- | :-- | :-- | :-- | :-- |
| weight files (MDB101) | `weight_file` `weights/model.pkl`, current version v2 | weight file of this model (local), owner declaration | picklescan reported the file's hash, evidence 1 | read the dangerous globals with `alert show 1` |
| packages (MDB201) | `package` `pkg:pypi/pillow@12.3.0`, v2 and v1 | package pinned in this model's environment lock | osv.dev reported the package for both advisories, evidence 5 and 6 | read the advisories' ranges and fixed versions |
| datasets and papers (MDB302) | `dataset` `10.5281/zenodo.3242074`, v2 | paper cited by a declared dataset, two steps from the model | crossref reported the paper | read the retraction notice and its reason |
| licences (MDB401) | `base_model` gpt2, v2, matched by repository | declared base model | hf-hub reported the licence | read the recorded and the new licence |
| base model (MDB501) | `base_model` gpt2, v2 | declared base model | hf-hub reported the repository disabled | read the hub's status for `openai-community/gpt2` |

Each view also reads `Impact: impact undetermined` and lists the impact question first under
`Not established`. A fixed alert (validators) reads `not in the current version; opened in v1; last
held in v1, fixed by v2`.

## Quickstart (T044)

| Scenario | Result |
| :-- | :-- |
| 1. Baseline holds | `tests/integration/test_cli_baseline.py`: pass |
| 2. Entry and relationship | the package view reads `(owner declaration, v2)` and `Runtime use: unknown`; after `alert dismiss … --reason not_used_at_runtime --by maintainer --note "CLI only"` it reads `Runtime use: declared not_used by maintainer at <time>: CLI only` and `Owner decision: dismissed not_used_at_runtime …`; impact unchanged |
| 3. Unresolved and no longer current | `tests/unit/test_affected.py`, `tests/unit/test_advice_statements.py`: pass |
| 4. Established apart | `tests/integration/test_advice_statements_by_rule.py` (renamed from the quickstart's `test_advice_statements.py`, see deviations): pass |
| 5. Review steps | `tests/unit/test_rule_texts.py`, `tests/unit/test_review_steps.py`: pass |
| 6. Read-only | `tests/integration/test_advice_read_only.py`: pass |
| 7. Exit codes and the gate | `tests/contract/test_exit_codes_advice.py`: pass |
| 8. Four questions | the table above |

## Final run (T045)

On the branch head after the last code commit, each gate run on its own, no pipe:

| Gate | Exit | Counts | Against the baseline |
| :-- | :-- | :-- | :-- |
| `uv run pytest -q` | 0 | 1837 passed, 6 skipped, 13 deselected (1827 s) | +130 passed (the new tests), 0 failed, skips and deselections unchanged |
| `uv run ruff check` | 0 | All checks passed | unchanged |
| `uv run ruff format --check` | 0 | 318 files already formatted | +24 files, all formatted |

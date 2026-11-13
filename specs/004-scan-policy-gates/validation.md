# Validation: Scan Exceptions, Strict Globals, Check Overview and an Opt-in Gate

**Feature**: [spec.md](spec.md) | **Quickstart**: [quickstart.md](quickstart.md) | **Date**: 2026-11-14

## Quickstart scenarios (T067)

Each scenario of quickstart.md was run through the test that automates it, offline, on Windows, in the
full suite below at commit `a442be6`. Every one passed.

| Quickstart scenario | Run through | Result |
| :-- | :-- | :-- |
| 1. The automated suite | `uv run pytest -q -p no:cacheprovider` | passed (counts below) |
| 2. An exception covers one global in one exact file (US1) | `tests/integration/test_exceptions.py`, `tests/contract/test_cli_exceptions.py`, `tests/unit/test_exception_rules.py` | passed |
| 3. The strict globals policy (US2) | `tests/integration/test_globals_policy.py`, `tests/unit/test_unlisted_globals.py`, `tests/unit/test_safe_globals.py` | passed |
| 4. Default policy changes nothing (SC-002, FR-007) | `tests/integration/test_default_equivalence.py` against `tests/fixtures/equivalence/pre-004-baseline.json` | passed: 9 scenarios, 10 databases, row for row |
| 5. The check overview (US3) | `tests/integration/test_overview.py`, `tests/contract/test_cli_run_show.py`, `tests/unit/test_overview_states.py` | passed |
| 6. Rule IDs (US4) | `tests/unit/test_rules.py`, `tests/contract/test_cli_json.py` | passed |
| 7. The gate (US5) and held dismissals (FR-020) | `tests/integration/test_gate.py`, `tests/contract/test_exit_codes.py`, `tests/integration/test_dismissal_holds.py`, `tests/unit/test_dismissal_hold.py` | passed |
| 8. Real-file acceptance check (T036) | run by hand on 2026-11-14, static scans only; see quickstart.md section 8 | as expected: both HIGH alerts excepted, `globals_policy` lists down from 23 to 22 and from 2 to 1, no safe-listed global listed |

Not covered by an automated test: an alert of severity `UNKNOWN` under `--fail-on UNKNOWN` (the test
shows that `UNKNOWN` counts a MODERATE alert, the lowest built here).

## Gates (T068)

Real exit codes, each command run on its own with its output written to a file (no pipe):

| Command | Exit code | Result |
| :-- | :-- | :-- |
| `uv run ruff check .` | 0 | All checks passed |
| `uv run ruff format --check .` | 0 | 271 files already formatted |
| `uv run pytest -q -p no:cacheprovider` | 0 | 1643 passed, 6 skipped, 13 deselected in 440.68 s |

Against the baseline recorded before T008 (`b642c4c`, Windows): 1436 passed, 6 skipped, 13 deselected.
That is 207 new passing tests, the same 6 skips (symlink tests Windows cannot run) and the same 13
deselected (live tests). No earlier test changed its expected alerts. The earlier tests that changed
are key sets that gain the new fields: `tests/contract/test_cli_json.py` (`excepted` in `alerts`,
`rule_id` and `rule_doc` in history items) and `tests/contract/test_cli_audit.py` (`alerts_excepted`,
`findings.excepted`).

Full runs by phase: Phase 1 at `3b1d20e`, 1442 passed; Phase 2 at `9db856d`, 1490; Phase 3 at
`f34b9e5`, 1551; Phase 4 at `bff3053`, 1576; Phases 5 and 6 at `1cb3363`, 1600; Phases 7 to 9 at
`a442be6`, 1643. Each had ruff and format exit 0 and pytest exit 0, with 6 skipped and 13 deselected.

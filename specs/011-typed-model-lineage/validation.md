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

## Quickstart scenarios (T057)

Scenarios 2, 4, 6 and 7 were run on 2026-11-20 through `cli.main` with a recorded-only fetcher (no
network: `uv run model-dependabot` would have asked the live hub for the `example-org` repositories);
scenarios 1, 3 and 5 are the automated suite. What each printed:

- 2: `register merge-two.toml` exit 0, `Lineage (2 edges)` both `merged-from`, origin manifest, owner;
  `inventory show example-merge` the same; `register adapter-no-revision.toml` exit 0, the edge
  `[no revision]`; `bad-relationship.toml` exit 1 `parents[0].relationship must be one of
  fine-tuned-from, adapter-for, merged-from, quantized-from`; `both-forms.toml` exit 1 `use either
  [base_model] or [[parents]], not both`.
- 4: `register four-types.toml` exit 0, 4 edges, problem `parent_not_registered:
  model:example-adapter-base@1 (parents[3])`; export exit 0; import of the export exit 0, 4 edges
  origin import, unverified, claimed manifest; `inventory audit example-four-copy` `Lineage (4 edges, 1
  problem)`; import of `third-party-two-untyped.json` exit 0, 2 unspecified edges.
- 6: `register cycle-a.toml` exit 0 `[parent not registered]`; `register cycle-b.toml` exit 0, `cycle:
  example-cycle-a v1 -> example-cycle-b v1 -> example-cycle-a v1` plus `parent_not_registered`
  for example-cycle-c; the audit lists the cycle; `check example-cycle-a --source picklescan` exit 0,
  0 watch events, one `lineage problem cycle: ...` line.
- 7: `discover card-two-merge -o proposed.toml` exit 0; two `# [[parents]]` blocks, each
  `# relationship = "merged-from"`.
- 8: the constitution preamble names "the models it was derived from by fine-tuning, adaptation,
  merging or quantisation"; the footer reads 1.1.0.

## Final gates (T058)

On `f814042` (`src` tree `068735839a99b93b26ca6ec134fe821da3c101b4`), each gate run on its own, no pipe:

| Gate | Exit | Counts | Against the baseline |
| :-- | :-- | :-- | :-- |
| `uv sync --frozen` | 0 | | unchanged |
| `uv run pytest -q` | 0 | 2115 passed, 6 skipped, 13 deselected (1220 s) | +208 passed, 0 failed |
| `uv run ruff check` | 0 | All checks passed | unchanged |
| `uv run ruff format --check` | 0 | 348 files already formatted | +29 files |

The run before it, on `52f2131`, failed one test (`test_every_watch_kind_is_on_exactly_one_page`:
`lineage_inherited` was on no rule page); `f814042` lists it on MDB501. The run before that found the
legacy edge text printing `None` (`test_cli_json_upstream`), fixed in `52f2131`. Pre-existing tests
changed on purpose: `test_inventory_profile.py` (the six new properties), `test_cli_audit.py` (the
`lineage` key), `test_discover_card.py` (the mapped type and the removed #9 gap).

## Feature 010's CLI baseline (T060)

None of the 44 recorded invocations (alerts, history, alert show, run show and check on models
without parents) changes: `check` adds `lineage.problems` only when a checked version has problems,
and only `lineage_inherited` events carry the new `text` key. `tests/integration/test_cli_baseline.py`
replays byte for byte on every phase's code, so the baseline was not re-recorded and its pinned
SHA-256 is unchanged. Changed output outside that baseline: `register`, `import` and `inventory show`
gain the lineage section (FR-021, contracts/manifest-parents.md); `alerts` and `alert show` text gain
`via ... edge` lines and the JSON cause gains `edges` (FR-009, FR-024); `inventory audit` gains
`lineage` (FR-030). No exit code changed (`test_exit_codes_lineage.py`, SC-007).

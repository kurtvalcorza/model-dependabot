# Validation: Evidence-Backed Dependency Discovery and Inventory Assurance

Recorded 2026-11-13 on branch `003-inventory-assurance` (from `main` at `308e323`), Windows 11, Python
3.12.10 under `uv`. Exit codes are the commands' own (no pipes in front of them). This is T054 (the
quickstart walk-through) and T055 (the suite and lint). The walk-through on a real model project and the
held-out discovery evaluation (FR-026) are recorded separately, by the owner's run.

## 1. Suite and lint (T055)

| Command | Result | Exit code | Time |
| :-- | :-- | :-- | :-- |
| `uv run pytest -q` before this feature (`308e323`) | 1113 passed, 12 deselected (the `live` tests) | 0 | 690 s |
| `uv run pytest -q` | 1376 passed, 2 skipped, 13 deselected (the `live` tests) | 0 | 864 s |
| `uv run ruff check` | All checks passed | 0 | under 1 s |
| `uv run ruff format --check` | 224 files already formatted | 0 | under 1 s |
| `uv run pytest -m live -k "format_check or discover" -rA` | 1 passed (the hub answers a ranged `GET` of a `resolve` URL with 206 after its redirect) | 0 | 5.4 s |

The network is blocked in the default run by `tests/conftest.py` (sockets and name resolution). The two
skipped tests each need a symbolic link to a file (one for `format-check`, one for the discovery
walk), which this Windows account may not create; the directory
cases of the same boundary run here through junctions, which `os.walk(followlinks=False)` would enter on
Windows if discovery did not refuse them itself.

`tests/property/test_claim_trust_machine.py` (T053) was also run once against a planted defect (a
`_code_free` that trusts every claim, injected by a throwaway pytest plugin, no source changed): the
machine failed with an imported, unconfirmed claim suppressing the alert, so the property is not
satisfied vacuously.

## 2. Quickstart walk-through (T054)

| Section | How it ran | Result |
| :-- | :-- | :-- |
| 1. The suite | as in section 1 above | see above |
| 2. A forged code-free claim | `tests/integration/test_claim_trust.py` (recorded hub answers) | the forged pickle gives `format_claim_contradicted` and an open `format_policy` alert naming the rule; the honest inventory gives `confirmed`, no alert and `verified` |
| 3. Old imports re-marked | `tests/integration/test_claim_trust_legacy.py` | after one `check` with `format-check` failing (exit 2) the alert is open and names the rule; the manifest-registered model keeps its alerts |
| 4. Audit after a check | `tests/integration/test_inventory_audit.py`, and by hand through `main()` with the same recorded answers (`hf-scan` failing with 503) | before the check: `not yet checked`; after it (exit 2): 0 open alerts, 1 watch event, 2 gaps, 2 uncheckable, `hf-scan` failed, the statement present; the database unchanged by each audit |
| 5. Discovery, offline | the real command line on a copy of `tests/fixtures/projects/detector` with a junction `link-out` to a folder outside it | 14 candidates; `link-out` and `../outside.txt` skipped as outside the project; `uv.lock` listed as not read; `runs/best.safetensors` verified as a pickle; the base model `no revision` and, with the manifest, `conflicts`; the proposed manifest registers 2 weight files and the 2 locked packages, no base model or dataset (since PR #15 round 3, T4, the lock pins the conflicting numpy, so it stays a comment and only the 2 weight files are registered); a second `-o` without `--force` exits 1 |
| 6. Discovery with hub lookups | `tests/integration/test_discover_upstream.py` (recorded hub answers) | the base model gets `proposed_revision` labelled "head at observation time, not established as the training revision"; the refused dataset is `unavailable` with the reason; exit 0; without `--upstream` no request |
| 7. Live | as in section 1 above | passed |

## 3. Reading the audit (SC-007)

SC-007 asks that a maintainer reading the audit can say in under two minutes which entries are
unverified and which sources failed. The audit of section 4 took 0.06 s to produce and is 17 lines of
text. Its second line answers both questions in counts ("0 declared but unverified … sources: 1
failed"), the Assurance block lists each entry with its status and the Coverage block names the failed
source with its reason and age. How long a person takes to read it was not measured here: that needs
the owner, or another maintainer, to time one reading.

## 4. Departures from tasks.md

- T028's integration tests are in `tests/integration/test_inventory_audit.py`, not `test_audit.py`:
  pytest refuses two test modules with one basename and `tests/unit/test_audit.py` exists (quickstart
  updated).
- A hub failure in `format-check` still records the local claim checks read in the same run (quickstart
  section 3 needs a manifest-registered model to keep its alerts in that run).
- `discover/__init__.py` said discovery never imports the store module; `inventory/build.py`, whose
  `hash_file` and `classify` discovery must reuse (T045), imports constants from it. The sentence now
  says what holds: discovery never opens a `Store`, and the integration tests check that no database
  file is created.
- A commented hub dataset in a proposed manifest is written `hub = "hf:datasets/owner/name"`, the form
  the manifest reader accepts; the contract's excerpt shows `hf:org/data`. Its gap is `no revision`.

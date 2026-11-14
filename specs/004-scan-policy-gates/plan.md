# Implementation Plan: Scan Exceptions, Strict Globals, Check Overview and an Opt-in Gate

**Branch**: `004-scan-policy-gates` | **Date**: 2026-11-13 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/004-scan-policy-gates/spec.md`

## Summary

Six increments on the existing command-line tool, in priority order.

1. **Global exceptions (US1, P1)**: an owner records an exception for one pickle global in one file,
   keyed by the file's SHA-256, with a reason, who accepted it and an optional expiry date. A new
   table holds exceptions, and a new table keeps the globals each scanned file imported, by file hash,
   so exceptions and the strict policy can be applied at any check without loading or rescanning a
   file. A `weight_file_scan` alert whose dangerous globals are all excepted stays stored as open but
   is marked excepted: it is shown as `excepted`, cites the exception as evidence and does not count as
   open (research S4).
2. **Strict globals policy (US2, P1)**: `policy ID --globals default|strict --by NAME`, stored beside
   the format policy. Under `strict`, a scanned pickle file with globals that are neither on the
   published safe list nor excepted, dangerous ones included, raises one `globals_policy` alert
   (MODERATE) per file, naming them; a dangerous global also keeps its HIGH `weight_file_scan` alert, and
   one exception covers it in both. The safe list is a versioned TOML file in the package, exact globals
   only (research S3, S7).
3. **Check overview (US3, P2)**: each `check` ends with a per-source, per-model overview (`passed`,
   `alerted`, `incomplete`, `failed`, with counts), tallied in the run as each source is applied and
   stored with the run; `run show RUN_ID` shows it again (research S6).
4. **Rule IDs (US4, P2)**: a rule registry maps every alert kind to a stable ID (`MDB101` and so on) and
   one page under a new `docs/rules/` folder; every alert carries `rule_id` in text and JSON (research
   S1).
5. **Gate (US5, P3)**: `check --fail-on SEVERITY` exits 4 when open, not excepted alerts at or above
   `SEVERITY` exist for the models in scope after the check, and also when a source in scope is
   `incomplete`, a model was checked by no relevant source or the scope matched no model (owner's ruling
   D8, FR-021); exit 2 for a failed source takes precedence; without the option every exit code is
   unchanged (research S5).
6. **Held dismissals (FR-020)**: a dismissed alert of any kind is not opened again by a later check
   unless the check brings new evidence for its cause, defined in research S13; this keeps US5's
   "dismiss, then `--fail-on` passes" true.

Decisions: [research.md](research.md). The owner ruled on the nine open questions (D1 to D9) on 2026-11-13
(research, Decisions table; spec, Clarifications); this plan follows the rulings.

## Technical Context

**Language/Version**: Python 3.12, type hints throughout (as 001 to 003)

**Primary Dependencies**: existing `packaging`, `jsonschema`, `picklescan` (1.0.5, pinned in
`pyproject.toml:10`), `cvss` and `PyYAML`; `tomllib` from the standard library reads the safe list. No
new runtime dependency

**Storage**: the existing SQLite database and evidence store. New tables `global_exceptions`,
`file_scans` and `check_run_overview`; new columns `models.globals_policy`,
`models.globals_policy_set_by`, `models.globals_policy_set_at` and `alerts.excepted_at`; the `alerts`
table is rebuilt once to widen its `kind` check for `globals_policy`, the same twelve-step rebuild
`_widen_watch_kinds` already does for watch events (`store.py:624-656`). All added on open, inside
`_atomic` (`store.py:540-553`); nothing removed or renamed ([data-model.md](data-model.md))

**Testing**: pytest, offline by default. Pickle fixtures built by `tests/fixtures/pickles/craft.py`
(a file mixing a safe-listed, a suspicious and a dangerous global; a protocol-2 file importing
`__builtin__.getattr`, `__builtin__.set`, `torch.Size` and a framework layer class), never loaded; a
pre-004 schema fixture (`tests/fixtures/db/schema-pre-004.sql`) for the migration; a baseline of
alerts and watch events recorded once from the pre-004 build (`tests/fixtures/equivalence/pre-004-baseline.json`)
for SC-002 (research S10); a registry test for FR-016

**Target Platform**: as 001 (Linux and macOS CI; Windows for local use)

**Project Type**: command-line tool (library plus CLI) in the existing single package

**Performance Goals**: no new source request. Applying exceptions and the strict policy reads one
`file_scans` row per code-capable local file and the model's exceptions; the overview is tallied in
memory during the run and written as one row per source and model. A check over hundreds of entries
stays bound by its source requests, as today

**Constraints**: no weight file is ever loaded (scans stay static, `sources/pickle_scan.py`); exceptions
and policies change no inventory and act on no model (FR-005); default behaviour and exit codes
unchanged (FR-007, FR-018, SC-002, SC-005); migrations additive and atomic; the audit's read-only open
(`store.py:441-471`) reads the new tables' defaults when they are absent

**Scale/Scope**: as 001: tens to hundreds of models; exceptions in the tens to low hundreds; a safe list
of 30 entries

No open NEEDS CLARIFICATION: the spec's five questions were answered on 2026-11-13, and the planning-time
choices are settled in research S1 to S14, with the owner's rulings D1 to D9.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | How this plan meets it | Before research | After design |
| :-- | :-- | :-- | :-- |
| I. Evidence on Every Alert | A `globals_policy` alert cites the file's SHA-256, each unlisted global, the scan that found it (scanner, version, time), the safe list's version and SHA-256 and the owner's policy setting (who, when), each as an evidence row. An exception applied to an alert is itself an evidence row (source `exception`: who, when, reason, expiry), so an excepted alert shows why. The owner's recorded policy applied to a pinned file is a primary source under 1.0.3 | Pass | Pass |
| II. Pinned Inventory, Open Standards | Exceptions key on the SHA-256 the inventory already pins; a file without one cannot be excepted. No inventory field is added and CycloneDX export is unchanged; exceptions, policies and overviews live in the database, not the BOM | Pass | Pass |
| III. Advise, Never Act | Nothing changes, loads or retires a model. A `globals_policy` alert closes as `cleared` only on an observation recorded as evidence: the owner's policy set back to `default`, a safe list version that lists the global or a recorded exception. The safe list is part of the policy source: the owner adopts it by setting `strict`, and each alert cites its version and SHA-256. A revoked or expired exception releases the finding at the next check, with the revocation or expiry as evidence. The gate only sets an exit code | Pass | Pass |
| IV. Precision First | The new alert kind needs a confirmed match: a complete or incomplete static scan of the pinned bytes that names the global, under the owner's own `strict` setting. Under `default` nothing new is raised (FR-007); `pathlib.PosixPath` stays a watch event. A file never scanned raises no `globals_policy` alert and shows as not covered in the overview. Under strict a dangerous global is named by two alerts (the owner's ruling D3): both are confirmed matches with their own evidence and rule ID; the second is the owner's own MODERATE policy finding; one exception settles both. So the repetition is opt-in, bounded to one extra alert per file and recorded in Complexity Tracking. Held dismissals (FR-020) reduce repeat alerts: an alert dismissed on unchanged evidence stays closed | Pass | Pass, with the strict repetition justified |
| V. Test-First with Offline Feed Tests | No new feed. Fixtures are crafted opcode bytes (`craft.py`), as in 001; every test task precedes the code it tests and fails first, the SC-002 equivalence test included (it asserts the recorded pre-004 baseline and the new `file_scans` rows, so it fails until file scans are written; research S10) | Pass | Pass |
| Neutral open source; privacy; polite to sources | The safe list is public and neutral; rule pages and specs name no institution or platform; no request is added; an exception's `--by` name stays in the local database, never sent anywhere | Pass | Pass |
| House style | British spelling, no serial comma, in the safe list, rule pages and output text | Pass | Pass |
| Development workflow | Specified, clarified and planned before code; tasks next; outward actions wait for the owner | Pass | Pass |

Result: **pass**, with justified exceptions in Complexity Tracking: stored state `open` for an excepted
alert; the `alerts` rebuild; a dangerous global repeated in the `globals_policy` alert (Principle IV); and the
change to how every alert kind treats a dismissed cause.

## Project Structure

### Documentation (this feature)

```text
specs/004-scan-policy-gates/
├── spec.md              # specification with clarifications
├── plan.md              # this file
├── research.md          # Phase 0: owner's rulings D1-D9, decisions S1-S14
├── data-model.md        # Phase 1: new tables and columns, alert and overview shapes
├── quickstart.md        # Phase 1: validation scenarios
├── contracts/
│   └── cli.md           # policy --globals, exception commands, overview, --fail-on, exit codes
├── checklists/requirements.md
└── tasks.md             # Phase 2 (/speckit-tasks)
docs/
└── rules/               # new: README.md index and one page per rule ID (FR-015)
```

### Source Code (repository root)

```text
src/model_dependabot/
├── cli.py                     # changed: policy --globals; exception record|list|revoke; run show;
│                              #          check --fail-on and exit code 4; overview in check output
├── store.py                   # changed: global_exceptions, file_scans, check_run_overview;
│                              #          models.globals_policy*; alerts.excepted_at; alerts kind rebuild
├── lifecycle.py               # changed: record file scans in _apply_report; globals rules pass after
│                              #          the format rules; per-source tallies; counting excludes excepted;
│                              #          held dismissals in _raise_or_carry, _weight_alert, _upstream_alert
├── rules.py                   # new: rule registry (ID, kind, page, family, related watch kinds)
├── reports.py                 # changed: rule_id on every alert; excepted list; overview text
├── safe_globals/
│   ├── README.md              # new: what the list is, how it is versioned and reviewed
│   └── safe-globals.toml      # new: version, entries {module, name, why, added_in}
├── assurance/
│   ├── audit.py               # changed: alerts_open excludes excepted; alerts_excepted count
│   ├── exceptions.py          # new: record, list, revoke, active-at, in-use
│   ├── globals_policy.py      # new: safe list loader; unlisted globals for one file scan
│   └── overview.py            # new: tallies to per-source and per-model states; storage view
tools/
└── record_equivalence_baseline.py  # new: records the SC-002 baseline once, from the pre-004 build
tests/
├── fixtures/pickles/craft.py  # changed: mixed, protocol-2 getattr, two-dangerous and unresolved fixtures
│                              #          (built at test time); posix-path.pkl (committed)
├── fixtures/equivalence/pre-004-baseline.json  # SC-002 baseline from the pre-004 build
├── fixtures/db/schema-pre-004.sql
├── fixtures/rules/assigned.json  # every rule ID ever assigned, with its kind (FR-016)
├── unit/                      # safe list loader; exception matching and expiry; overview states; registry
├── contract/                  # exit-code table with and without --fail-on; JSON shapes; rule_id
└── integration/               # US1-US5 independent tests; SC-002 default-policy equivalence; migration
```

**Structure Decision**: the existing single package. Exception rules, the safe list logic and the
overview live in `assurance/` beside `trust.py`, so they can be tested without a check run;
`lifecycle.py` calls them. The rule registry is a top-level module because `reports.py`, `cli.py` and
the test that guards FR-016 all read it. The safe list is a data file in the package (like
`licences/`), so it ships with the code whose version it is tied to.

## Delivery order

The order follows tasks.md's phases.

1. Schema additions and file scans (foundation), with global exceptions and the excepted representation
   (US1). One pull request.
2. Strict globals policy and the safe list (US2), with the real-file acceptance check. One pull request.
3. Check overview and `run show` (US3). One pull request.
4. Rule registry, `rule_id` on alerts and `docs/rules/` (US4), after the `globals_policy` kind exists, so
   all twelve rule IDs and pages land together. One pull request.
5. Held dismissals (FR-020), in the three insert paths. One pull request, before the gate.
6. `--fail-on` and exit code 4 (US5). One pull request.

Each increment is shippable alone and keeps the full suite green. The SC-002 equivalence test lands in
increment 1 and stays in the suite.

## Complexity Tracking

| Exception | Why needed | Simpler alternative rejected because |
| :-- | :-- | :-- |
| An excepted alert keeps the stored state `open`, marked by `alerts.excepted_at`; views show it as `excepted`, and every counting reader (summaries, audit, overview, gate) must exclude it. The spec's "MUST NOT count as open" is met in the views, not by the stored state | An exception can be revoked or expire, and the finding must then return with its history; an alert that stays open keeps its identity, evidence and version carry-forward (`reevaluate_version`, `lifecycle.py:1613-1700`) through the exception's life. A missed counting reader over-counts, which fails towards caution | A new stored state `excepted` would need every lifecycle reader that tracks a live cause (12 `find_open_alert` call sites, six `alerts_for(..., ["open"])` calls and five store queries, research S4) to accept it, plus a new partial unique index; a reader missed there silently opens a duplicate alert or never fixes an excepted one, which fails towards hiding findings |
| Under strict, a dangerous global is listed by two alerts: the HIGH `weight_file_scan` alert and the MODERATE `globals_policy` alert (owner's ruling D3) | The `globals_policy` alert is then the complete list of what the owner has not accepted for the file, readable and closable on its own (FR-008 as written) | Leaving dangerous globals out of the `globals_policy` alert (the plan's first recommendation) gives each global one alert, but the owner chose completeness; the repetition is limited to models the owner put under strict, and one exception for (global, hash) clears it in both |
| A dismissal now holds for every alert kind until new evidence arrives (owner's ruling D6), a change to features 001 and 002's lifecycle | Without it a dismissal lasts only until the next check (research S5 probe), so dismissing cannot quiet a reviewed finding and US5's dismissal case fails | Leaving dismissals as they were and correcting US5's test (the plan's first recommendation) keeps the old behaviour, which the owner ruled against; new evidence, defined in research S13, still reopens the cause, so constitution III and IV hold |
| The `alerts` table is rebuilt once on open | SQLite cannot widen a `CHECK` in place, and `globals_policy` is a new alert kind (`store.py:246`) | Reusing the `format_policy` kind with another cause key would give two meanings one rule ID, against FR-014 and FR-016 |

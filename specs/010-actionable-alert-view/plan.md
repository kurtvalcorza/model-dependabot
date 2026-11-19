# Implementation Plan: An Actionable Alert View for Model Maintainers

**Branch**: `plan/010-actionable-alert-view` | **Date**: 2026-11-19 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/010-actionable-alert-view/spec.md` (clarified 2026-11-19,
no markers open)

## Summary

One read-only addition to the command-line tool: an opt-in `--advice` flag on `alert show ALERT_ID` and
`alerts ID` that appends an advisory view to the unchanged output. Four increments, in priority order.

1. **Rule texts and the CLI baseline (foundation)**: the pre-feature CLI baseline is recorded first,
   from `main` at `47ebfbe` (FR-016, research R9). The limitations, closing text, fix text, review
   steps, relationship and not-established questions of every rule ID move into one versioned package
   data file, `rule_texts/rule-texts.toml`, read by `rules.py`; the three prose sections of each
   `docs/rules/MDB*.md` page are rendered from it and a test keeps them in step (FR-010, FR-014,
   research R4).
2. **Affected entry and relationship (US1, P1)**: a pure resolver in `assurance/affected.py` maps an
   alert's stored cause to the inventory entries that hold its identifier, by exact identifier or, for
   repository-keyed alerts, by repository; never by similarity (FR-005, FR-006, research R2). Runtime
   use reads `declared` (polarity `not_used`) only from this alert's own `not_used_at_runtime`
   dismissal, otherwise `unknown`, naming other such dismissals on the same entry as context (FR-007,
   FR-008, research R3).
3. **Established, not established, limitations and owner decision (US2, P1)**: `assurance/advice.py`
   builds one established statement per evidence row of the alert, the not-established list (always
   led by the impact question), the limitations from the rule text, the claim states of the entry
   (feature 003) and an owner-decision block for a dismissal or exception. Impact is the constant
   `impact undetermined` (FR-009 to FR-013).
4. **Review steps (US3, P2) and compatibility (US4, P3)**: the rule's numbered steps with placeholders
   filled from the alert's stored fields only; every command a step names is parsed by the real
   argument parser in a test (FR-014, FR-015). The flag is wired into `cli.py`; without it the
   recorded baseline replays byte for byte, and with it the exit code is unchanged (FR-016, FR-017).

Decisions: [research.md](research.md). Four planning-time questions need the owner's ruling (Q1 to Q4,
research, "Questions for the owner"); each has a recommendation, and the tasks follow the
recommendation until the owner rules.

## Technical Context

**Language/Version**: Python 3.12, type hints throughout (as 001 to 004)

**Primary Dependencies**: existing only. `tomllib` (standard library) reads `rule-texts.toml`, as
`assurance/globals_policy.py:15,47` reads the safe list; `packaging.utils.canonicalize_name` (already
used by `lifecycle.py:361-363`) normalises package names in the resolver. No new runtime dependency

**Storage**: none added. The view is computed from stored rows at read time and never stored (spec,
Key Entities). No table, column, index or migration: an alert from a database of any schema the
existing `Store` opens works unchanged (spec, Edge Cases). The commands open the store exactly as they
do today (`cli.py:546-547`, `_open`); research R8 and Q2 record why

**Testing**: pytest, offline by default (`tests/conftest.py:33-39` blocks sockets). New fixtures:
a CLI baseline recorded once from `main` at `47ebfbe` (`tests/fixtures/cli_baseline/`), a four-family
model with recorded answers that raises one alert of every rule ID (`tests/fixtures/advice/`), and a
fixed list of verdict phrases for FR-011 (`tests/fixtures/advice/verdicts.json`). Registry tests extend
`tests/unit/test_rules.py`

**Target Platform**: as 001 (Linux and macOS CI; Windows for local use)

**Project Type**: command-line tool (library plus CLI) in the existing single package

**Performance Goals**: no source request. One view reads the alert, its evidence, the model's stored
versions and their entries; `alerts ID --advice` reads each version's entries once per model and
reuses them for every alert. Bound by tens to hundreds of entries, as today

**Constraints**: read-only (FR-002): 0 store writes, measured as `sqlite3.Connection.total_changes`
unchanged and the database file byte-identical, and 0 network requests (SC-004); deterministic
(FR-003): lists in the orders of data-model.md, JSON with `sort_keys=False` as `cli.py:369` does today;
no score, weight or adjusted severity (FR-004); default output and exit codes unchanged byte for byte
(FR-016, FR-017); house style (British spelling, no serial comma) in every rule text

**Scale/Scope**: 12 rule IDs (`rules.py:28-118`), 4 entry kinds (`store.py:49`), 5 relationships
(FR-005); tens to hundreds of models

No NEEDS CLARIFICATION is open: the spec's three markers were resolved on 2026-11-19 (spec,
Clarifications) and the planning-time choices are settled in research R1 to R10, with Q1 to Q4 put
to the owner.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | How this plan meets it | Before research | After design |
| :-- | :-- | :-- | :-- |
| I. Evidence on Every Alert | No alert is raised or changed. Every established statement cites one or more evidence ids of the alert (`store.alert_evidence`, `store.py:1945-1950`) with source, URL, retrieval time and matched identifier; a statement with no evidence row is not established (FR-009). The relationship is shown as the inventory's declaration with its basis (version origin, manifest section, version), never as evidence or inference. "Inferred" in issue #7 is replaced by "not established" (spec, US2), so the tool presents no inference of its own | Pass | Pass |
| II. Pinned Inventory, Open Standards | No inventory field is added and the CycloneDX export is unchanged. The resolver matches only exact pinned identifiers. Q1 (environment markers are not stored, research R5) is answered inside this principle: the recommendation stores nothing new | Pass | Pass, Q1 open |
| III. Advise, Never Act | The view only reads. Every review step is an action for the maintainer with a command the CLI has (FR-015), checked by parsing each named command with `build_parser()` (`cli.py:162`). Impact is always `impact undetermined`; no command records an impact conclusion (FR-012) | Pass | Pass |
| IV. Precision First | No new alert or watch event. An identifier no stored version holds reads `unresolved` with its reason; no entry is picked by name, similarity or partial match (FR-006). Watch events get no advisory view (FR-003) | Pass | Pass |
| V. Test-First with Offline Feed Tests | No new feed. Every test task precedes its code and fails first; the FR-016 baseline is recorded from the pre-feature build before any `src/` change, so the replay test fails only if behaviour moves. The default run stays offline | Pass | Pass |
| Neutral open source; privacy; polite to sources | Rule texts and steps name no institution or platform; the view sends nothing anywhere; names in the owner-decision block (`dismissed_by`, `accepted_by`) are already stored locally and stay local | Pass | Pass |
| House style | British spelling, no serial comma, in `rule-texts.toml`, rule pages and output text; a test checks the verdict list, not style, so style is a review item (T046) | Pass | Pass |
| Development workflow | Specified, clarified and planned before code; tasks next; outward actions wait for the owner | Pass | Pass |

Result: **pass**, with no Complexity Tracking entry. Two points are put to the owner rather than
decided here, because they touch how the constitution's words are read, not whether the plan meets
them:

- **Q2, read-only and the store's open-time migrations.** `Store.__init__` (`store.py:662-687`) creates
  missing tables and migrates an older database on open, which is a write. Today `alerts` and
  `alert show` open the store that way. FR-002 and SC-004 say the view writes nothing. Recommendation:
  keep the existing open, so `--advice` cannot change an exit code (FR-017), and measure SC-004 on a
  database already at the current schema; the view code itself takes a `Store` and never calls a
  writing method (test T015). Alternative: open with `Store.open_read_only` (`store.py:631-660`) when
  `--advice` is given, which refuses a database older than feature 002 with exit 3 where the plain
  command migrates and exits 0, a change FR-017 forbids.
- **Constitution, "first user".** The constitution's Additional Constraints say "The first user is a
  model-hosting platform"; decision D3 (`specs/decisions/2026-11-04-rfc-5-6.md`) and the spec say the
  first user of this view is the model maintainer. They do not conflict in this plan (the view is
  generic and names no platform), so no exception is recorded. Recommendation: no amendment now; if
  the owner wants the wording aligned, a PATCH clarification ("the first deployment is on a
  model-hosting platform; the first user of alert views is the model maintainer") in a separate change.

## Project Structure

### Documentation (this feature)

```text
specs/010-actionable-alert-view/
├── spec.md              # specification with clarifications (on main)
├── plan.md              # this file
├── research.md          # Phase 0: decisions R1-R10, owner questions Q1-Q4
├── data-model.md        # Phase 1: view shape, relationship table, orders, rule-text file
├── quickstart.md        # Phase 1: validation scenarios
├── contracts/
│   └── cli.md           # --advice on alert show and alerts; JSON and text shapes; exit codes
├── checklists/requirements.md
└── tasks.md             # Phase 2 (/speckit-tasks)
docs/
└── rules/               # changed: three sections of each MDB*.md rendered from rule-texts.toml
```

### Source Code (repository root)

```text
src/model_dependabot/
├── cli.py                     # changed: --advice on alerts and alert show; text appended after
│                              #          today's text; JSON gains one `advice` key per alert
├── rules.py                   # changed: load rule texts; texts_for(rule_id); RELATIONSHIPS table
├── rule_texts/
│   ├── README.md              # new: what the file is, placeholders allowed, how pages are rendered
│   ├── __init__.py            # new: empty, module docstring (as safe_globals/__init__.py)
│   └── rule-texts.toml        # new: per rule ID: limitations, closes, fix, steps, not_established
├── assurance/
│   ├── affected.py            # new: resolve entry, relationship and basis, runtime use (US1)
│   └── advice.py              # new: statements, claims, owner decision, steps, impact; text (US2-3)
└── reports.py                 # unchanged in behaviour; advice_text lives in advice.py
tools/
├── record_cli_baseline.py     # new: records the FR-016 baseline once, from main at 47ebfbe
└── render_rule_pages.py       # new: writes the three prose sections of docs/rules/MDB*.md
tests/
├── fixtures/cli_baseline/     # scenarios.py + pre-010-baseline.json (FR-016)
├── fixtures/advice/           # family model, recorded answers, verdicts.json (FR-011)
├── unit/                      # rule texts registry; resolver; runtime use; statements; steps
├── contract/                  # --advice JSON shape and text layout; exit codes with and without
└── integration/               # US1-US4 independent tests; baseline replay; read-only and offline
```

**Structure Decision**: the existing single package. The resolver and the view builder sit in
`assurance/` beside `trust.py` (whose `claim_verification`, `trust.py:126-152`, they reuse), so they are
pure functions of stored rows and can be tested without a check run, as feature 004 placed
`overview.py`. The rule texts are a package data file, like `safe_globals/safe-globals.toml`, so they
ship with the code whose version they are tied to (FR-014 "versioned in the repository"); `rules.py`
stays the one registry that `reports.py`, `cli.py`, the page renderer and the registry test read.

## Delivery order

The order follows tasks.md's phases.

1. CLI baseline recorded and its replay test, rule texts moved into `rule-texts.toml` with the pages
   rendered from it and the registry test extended (foundation). One pull request; behaviour unchanged.
2. Affected entry, relationship and runtime use (US1), with `alert show --advice` showing that part.
   One pull request.
3. Statements, claims, owner decision and impact (US2), with the verdict guard. One pull request.
4. Review steps (US3) and `alerts ID --advice` with the compatibility checks (US4). One pull request.

Each increment keeps the full suite green and the baseline replay passing.

## Complexity Tracking

No constitution exception is needed. Two design costs are recorded so a reviewer can weigh them:

| Choice | Why needed | Simpler alternative rejected because |
| :-- | :-- | :-- |
| Three sections of every rule page become rendered output of `rule-texts.toml` | FR-010 and FR-014 require one source of text for the page and the view | Checking the view's text against hand-written pages by string equality keeps two copies that must be edited in step; a generator plus an "in sync" test edits one |
| The resolver re-reads every stored version's entries | FR-005 needs the version that last held a fixed alert's entry (spec, Edge Cases) and every place an entry is held | Reading only the current version cannot name the last holder of a `fixed` alert's entry |

---

description: "Task list for feature 004: scan exceptions, strict globals, check overview, held dismissals and an opt-in gate"
---

# Tasks: Scan Exceptions, Strict Globals, Check Overview and an Opt-in Gate

**Input**: Design documents from `/specs/004-scan-policy-gates/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/cli.md, quickstart.md

**Tests**: Required. Constitution principle V: every test task is written before the code it tests and
must fail first (run it, see it fail for the expected reason, then write the code). The SC-002
equivalence test fails first too: it asserts a recorded pre-004 baseline and the new `file_scans` rows
(research S10). The default run stays offline (`tests/conftest.py` blocks sockets). No weight file is
ever loaded: pickles are crafted opcode bytes (`tests/fixtures/pickles/craft.py`) or real files scanned
statically outside the repository.

**Organisation**: by user story, in priority order: US1 exceptions and US2 strict (P1), US3 overview and
US4 rule IDs (P2), then held dismissals (FR-020, owner's ruling D6) as their own phase, then the US5
gate (P3), which depends on them.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependency on an unfinished task)
- **[Story]**: Which user story the task belongs to (US1 to US5); the held-dismissal phase carries `[US5]`
  because FR-020 and its scenario sit under US5 in spec.md, and it is a prerequisite of the gate phase

## Path Conventions

The existing single project: `src/model_dependabot/` and `tests/` at the repository root (plan.md,
Project Structure). House style for every string and document: plain English, British spelling, no serial
comma; no institution or platform names. Terms: "`globals_policy` alert", "check overview", "held
dismissal".

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: skeletons, fixtures, the baseline and the checks that must happen before code relies on them

- [X] T001 Create `src/model_dependabot/safe_globals/__init__.py` (empty, with a module docstring) and `src/model_dependabot/safe_globals/README.md` stating what the list is, that "Every entry MUST be one exact global (module and name); prefixes and wildcards are not allowed" (FR-009), that no entry may contain `unknown` (research S14), how a version is bumped and the D2 trade-off: "`_codecs.encode` can rebuild arbitrary bytes" (research S3)
- [X] T002 [P] Create `docs/rules/README.md` as the index of rule IDs, listing the twelve IDs of research S1 (`MDB101` to `MDB502`) with their alert kinds and families, each linking to a page still to be written
- [X] T003 [P] Add `mixed()` (`collections.OrderedDict`, `model_dependabot_fixture.layers.CustomLayer`, `os.system`), `protocol2_getattr()` (`__builtin__.getattr`, `__builtin__.set`, `torch.Size`, `model_dependabot_fixture.layers.CustomLayer`) `two_dangerous()` (`os.system`, `builtins.eval`) and `unresolved()` (a `STACK_GLOBAL` whose module operand is not a string constant, which picklescan 1.0.5 reports as module `unknown`; confirm the scanner's output on it) to `tests/fixtures/pickles/craft.py`, built at test time and never committed; add `posix_path()` (`pathlib.PosixPath` with a string argument, suspicious to the scanner) and commit its output as `tests/fixtures/pickles/posix-path.pkl`, with a test that the committed bytes equal what `craft.py` builds; document all five in `tests/fixtures/pickles/NOTES.md` (research S12)
- [X] T004 [P] Write `tests/fixtures/db/schema-pre-004.sql`, the schema of `main` at `c07c14d` with a model, a version, an open `weight_file_scan` alert, a dismissed alert and one check run, built the way `tests/fixtures/db/schema-pre-003.sql` is
- [X] T005 On the pre-004 build (`main` at `c07c14d`, before any Phase 2 code, after T003), write `tools/record_equivalence_baseline.py` and run it to record `tests/fixtures/equivalence/pre-004-baseline.json` (recorded at `b642c4c`, whose `src/` tree equals that of `c07c14d`; the file records both): the alerts and watch events, without ids and times, of every weight-checking scenario of `tests/integration/test_check_weights.py` and `tests/integration/test_register_from_record.py`, plus one scenario that registers and checks `tests/fixtures/pickles/posix-path.pkl` with `--source picklescan` (FR-007's named example; research S10)
- [X] T006 [P] Check every entry of safe list group 2 (`torch._utils._rebuild_parameter`, `torch._utils._rebuild_parameter_with_state`, `torch.Size`, `builtins.set`, `__builtin__.set`, `builtins.frozenset`, `__builtin__.frozenset`) and group 3 (`_codecs.encode`, `numpy.core.multiarray.scalar`) against the allow-list in `torch/_weights_only_unpickler.py` of a named PyTorch release (torch 2.9.0 or the newest release at task time), read from the release's source distribution as text and never imported; record the version, the file's SHA-256 and the result for each entry in `specs/004-scan-policy-gates/research.md` (S3, replacing "inferred, to confirm"); flag any entry not found there for the owner
- [X] T007 Survey every recorded answer that becomes alert evidence, in `tests/fixtures/hf/`, `tests/fixtures/doi_ra/`, `tests/fixtures/crossref/`, `tests/fixtures/datacite/`, `tests/fixtures/zenodo/`, `tests/fixtures/figshare/`, `tests/fixtures/hf_upstream/`, `tests/fixtures/hf_takedowns/` and `tests/fixtures/osv/`, for fields that change on every request (counters, timestamps, request ids, cache tokens); `tests/fixtures/hf/` is known to carry `downloads`, `likes` and `lastModified`; record each field and source as the `VOLATILE_FIELDS` list of research S13 in `specs/004-scan-policy-gates/research.md`, and mark every field beyond those three as awaiting the owner's yes

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: the schema, file scans and the default-policy guard that every story builds on

**CRITICAL**: no user story work starts until this phase is complete.

### Tests first

- [X] T008 [P] Write `tests/integration/test_migration_004.py` (fails first): opening a database built from `tests/fixtures/db/schema-pre-004.sql` adds `global_exceptions`, `file_scans`, `check_run_overview`, `models.globals_policy`, `models.globals_policy_set_by`, `models.globals_policy_set_at` and `alerts.excepted_at`; every model reads `globals_policy` "`NOT NULL DEFAULT 'default'`"; every alert keeps its id, state and evidence; `alerts.kind` accepts `globals_policy`; after the rebuild the index `one_open_alert_per_cause` exists in `sqlite_master` and a second open alert for the same model and cause is refused; a second open changes nothing; an open interrupted inside the `alerts` rebuild leaves the old table and its index as they were; `Store.open_read_only` on the pre-004 file reads no exceptions, policy `default` and no overview without writing
- [X] T009 [P] Write `tests/unit/test_store_004.py` (fails first) for the store rules of data-model.md: `global_exceptions` "Rows are never deleted; a trigger refuses any update except setting the three revocation fields from null"; `file_scans` "The latest row per `sha256` (by `file_scan_id`) decides"; `check_run_overview.model_id` is "text, `NOT NULL`" with "`''` for the run-wide row, shown as null in every view" and the key `(run_id, model_id, source)` refuses a second run-wide row for the same run and source; `latest_alert(model_id, cause_key)` returns the most recent alert for the key in any state
- [X] T010 [P] Write `tests/integration/test_default_equivalence.py` (fails first): replay the scenarios recorded by T005 and assert that alerts and watch events equal `tests/fixtures/equivalence/pre-004-baseline.json` row for row under `globals_policy = 'default'` with no exceptions (ignoring the `rule_id` view field), including a `pathlib.PosixPath` global that stays a `scan_suspicious` watch event, and that every scanned file has a `file_scans` row, which fails until T016 (SC-002, FR-007, research S10)

### Implementation

- [X] T011 Add `globals_policy` to `ALERT_KINDS` and generalise `_widen_watch_kinds` into one rebuild helper taking the table and its kinds, then rebuild `alerts` with it inside `_atomic`, copying rows by explicit column list, recreating the partial unique index `one_open_alert_per_cause` (`WHERE state = 'open'`) in the same transaction, with `PRAGMA foreign_keys` off and a `foreign_key_check` before commit, in `src/model_dependabot/store.py` (research S2; `store.py:263-264`, `store.py:624-656`)
- [X] T012 Add to `SCHEMA` in `src/model_dependabot/store.py` the tables `global_exceptions` (with the revocation-only update trigger), `file_scans` and `check_run_overview` (`model_id TEXT NOT NULL`), with `CREATE TABLE IF NOT EXISTS`, the fields and types of data-model.md and `sha256` checked as "64 lower-case hexadecimal digits, without the `sha256:` prefix"
- [X] T013 Add the columns `models.globals_policy` (`NOT NULL DEFAULT 'default' CHECK (globals_policy IN ('default', 'strict'))`), `models.globals_policy_set_by`, `models.globals_policy_set_at` and `alerts.excepted_at` to an older database on open, guarded by `columns()` and inside one `_atomic` block that re-reads the columns under the write lock as `_add_origins` does, in `src/model_dependabot/store.py`
- [X] T014 Teach `Store.open_read_only` in `src/model_dependabot/store.py` to read the absent tables and columns as their defaults (no exceptions, policy `default`, no overview, `excepted_at` null), as feature 003 does
- [X] T015 Add store methods `add_file_scan`, `latest_file_scan(sha256)`, `set_globals_policy(model_id, policy, set_by=...)` (mirroring `set_format_policy`, refusing a blank name) and `latest_alert(model_id, cause_key)` in `src/model_dependabot/store.py`
- [X] T016 Make `_apply_report` in `src/model_dependabot/lifecycle.py` write one `file_scans` row per applied report, for local scans in a check (with `run_id`) and recorded scans at registration (`run_id` null), with each global and the scanner's label; "A scan that stopped on a hash mismatch or a read error writes no row"

**Checkpoint**: T008 to T010 pass; the full suite is green with no behaviour change.

---

## Phase 3: User Story 1 - Accept a reviewed global in one exact file (Priority: P1) 🎯 MVP

**Goal**: an exception for (global, file SHA-256) marks the finding excepted wherever those bytes are
registered, and nowhere else.

**Independent Test**: spec US1; quickstart scenario 2.

### Tests for User Story 1 (write first, see them fail)

- [X] T017 [P] [US1] Write `tests/unit/test_exception_rules.py` (renamed from `test_exceptions.py`: pytest refuses two test modules with one basename): parsing `--global MODULE.NAME` (split at the last dot) and `MODULE:NAME`; refusals for no reason, no name, a malformed hash, a module or name containing `unknown` (research S14), "an expiry date in the past is refused when recording" and "a second exception for the same `module`, `name` and `sha256` is refused while one is active"; activity "active ──(t after expires_on, 00:00Z the next day)──▶ expired" with a fixed clock; `__builtin__.getattr` and `builtins.getattr` never match each other (D7)
- [X] T018 [P] [US1] Write `tests/contract/test_cli_exceptions.py`: `exception record`, `exception list [--all] [--sha256 HEX]` and `exception revoke` JSON shapes and exit codes of `specs/004-scan-policy-gates/contracts/cli.md`, with `state` one of `active`, `expired` or `revoked`; and `alerts --state excepted`
- [X] T019 [P] [US1] Write `tests/integration/test_exceptions.py`: US1 acceptance scenarios 1 to 5 and the Independent Test with `craft.protocol2_getattr()`; the same bytes under a third model are excepted; with `craft.two_dangerous()` and one exception the alert stays counted as open with the excepted global listed; recording an exception changes no alert until the next check that asks a weight source, and a `check --source osv` does not apply it (FR-010); revocation and expiry return the finding on the same alert id with the release as evidence; an exception for a global the file does not contain, or for a hub file's hash, is listed as not in use; the excepted alert is linked to an evidence row of source `exception`; with `craft.unresolved()` the `unknown` global cannot be excepted and keeps its alert open
- [X] T020 [P] [US1] Extend `tests/contract/test_cli_audit.py` (and the `alerts` key set of `tests/contract/test_cli_json.py`, which gains `excepted`): with one excepted and one open alert, `inventory audit --json` gives `summary.alerts_open` 1, `summary.alerts_excepted` 1 and the excepted alert under `findings.excepted`
- [X] T021 [P] [US1] Extend `tests/integration/test_never_writes.py` so `exception record`, `exception list` and `exception revoke` leave every model version, inventory entry and manifest unchanged (FR-005)

### Implementation for User Story 1

- [X] T022 [US1] Add `add_exception`, `exceptions(sha256=None, include_inactive=False)` and `revoke_exception` to `src/model_dependabot/store.py`, each exception stored with its evidence row (source `exception`, URL `exception:<id>`, body the record as canonical JSON)
- [X] T023 [US1] Implement `src/model_dependabot/assurance/exceptions.py` on those store methods: record (all refusals of T017), list with "applies to" (versions pinning `sha256:<sha256>`) and "in use" (the latest file scan of the hash lists the global), revoke and `active_at(t)` per data-model.md
- [X] T024 [US1] Add `_apply_globals_rules` to `src/model_dependabot/lifecycle.py`, run right after `_apply_format_rules` under the same condition (`lifecycle.py:312`): set `excepted_at` on an open `weight_file_scan` alert when every global in its cause is covered by an active exception for its hash, link each exception's evidence, write `cause.excepted` as `{global, exception_id, accepted_by, recorded_at, expires_on}`; clear it and write `cause.released` with `why` `revoked` or `expired` when one stops being active (research S8)
- [X] T025 [US1] Present excepted alerts in `src/model_dependabot/reports.py`: view `state` is "`excepted` when stored state is `open` and `excepted_at` is set; otherwise the stored state"; the `alerts` payload gains an `excepted` array, its `alerts` array holds only open alerts that are not excepted; `STATE_FILTERS` gains `excepted`
- [X] T026 [US1] Make `summary.alerts_open` exclude excepted alerts and add `summary.alerts_excepted` and `findings.excepted` in `src/model_dependabot/assurance/audit.py`
- [X] T027 [US1] Add `exception record`, `exception list` and `exception revoke` and the `excepted` choice of `alerts --state` to `src/model_dependabot/cli.py`, with exit 1 for every refusal; let `dismiss_alert` in `src/model_dependabot/lifecycle.py` accept an excepted alert

**Checkpoint**: T017 to T021 pass; US1 works alone with the default globals policy.

---

## Phase 4: User Story 2 - A strict policy for globals (Priority: P1)

**Goal**: under `strict`, one `globals_policy` alert per file names every global neither on the safe list
nor excepted, dangerous ones included (D3).

**Independent Test**: spec US2; quickstart scenario 3.

### Tests for User Story 2 (write first, see them fail)

- [X] T028 [P] [US2] Write `tests/unit/test_safe_globals.py`: the loader refuses an entry with `*`, an empty part, a duplicate ("exact, unique, no `*` (FR-009)") or a module or name containing `unknown` (research S14); the file holds 30 entries in version 1 (frozenset dropped, owner 2026-11-14); a recorded SHA-256 of the entries per version fails the test when entries change without a new `version`
- [X] T029 [P] [US2] Write `tests/unit/test_unlisted_globals.py` (renamed: one basename per test module): `unlisted` holds "every global the scan reported, whatever the scanner's label, that is neither on the safe list nor excepted"; `os.system` appears in both the `weight_file_scan` cause and `unlisted`; an `unknown` global always stays in `unlisted`; an incomplete scan is never clean
- [X] T030 [P] [US2] Write `tests/integration/test_globals_policy.py`: US2 acceptance scenarios 1 to 5 and the Independent Test with `craft.mixed()`: one HIGH alert for `os.system`, one MODERATE `globals_policy` alert listing `os.system` and the layer class, none for `collections.OrderedDict`; one exception for (`os.system`, hash) excepts the HIGH alert and removes it from `unlisted` at the next check; a policy change alone changes no alert until the next check that asks a weight source, and a `check --source osv` does not apply it (FR-010); closing as `cleared` with cause `policy`, `safe_list` (a test safe list with a higher version) and `exception`, each with its evidence; the `globals-policy` evidence record carries the sorted `unlisted` and `excepted` lists; a version without the file fixes it
- [X] T031 [P] [US2] Extend `tests/contract/test_cli_json.py` with `policy ID --globals strict --by NAME`, `policy` with neither option (exit 1) and the `globals_policy`, `globals_set_by` and `globals_set_at` fields of `specs/004-scan-policy-gates/contracts/cli.md`; add `policy --globals` to `tests/integration/test_never_writes.py` (FR-005)

### Implementation for User Story 2

- [X] T032 [US2] Write `src/model_dependabot/safe_globals/safe-globals.toml`, version 1: the 23 globals of picklescan 1.0.5's `_safe_globals` (installed `picklescan/scanner.py`, lines 88-120), group 2 and group 3 of research S3 (30 entries), each `{module, name, why, added_in}`, plus a `[[changes]]` entry; use the release and results recorded by T006 in each `why`
- [X] T033 [US2] Implement `src/model_dependabot/assurance/globals_policy.py`: the safe list loader (refusals of T028, version and file SHA-256) and `unlisted(file_scan, safe_list, active_exceptions)`
- [X] T034 [US2] Extend `_apply_globals_rules` in `src/model_dependabot/lifecycle.py` with the `globals_policy` transitions of data-model.md: open (key `globals_policy:<sha256>`, severity `MODERATE`, `severity_origin: policy`, the cause shape of data-model.md, a `globals-policy` evidence record carrying the sorted `unlisted` and `excepted` lists), update when `unlisted` changes, close as `cleared` naming `policy`, `safe_list` and `exception` as they apply; add `globals_policy` to `WEIGHT_SEVERITY`; a file with no `file_scans` row raises nothing
- [X] T035 [US2] Add `--globals (default|strict)` to `policy` in `src/model_dependabot/cli.py`, making `--format` optional with at least one of the two required; add the three new payload fields
- [X] T036 [US2] Real-file acceptance check (after T027 and T034; prerequisite: the maintainer supplies `<UNTRUSTED_DIR>`, an isolated local folder outside the repository): scan the pose-detection checkpoint and the change-detection checkpoint in `<UNTRUSTED_DIR>` only through `model_dependabot.sources.pickle_scan.scan_path` (static, never `torch.load` or `pickle.load`); register each from a manifest in a scratch folder outside the repository, set `--globals strict`, check with `--source picklescan`, record an exception per file hash for the `getattr` global exactly as the scan reports it and check again; confirm the HIGH alert becomes excepted, the `globals_policy` alert drops that global, the safe-listed globals (`__builtin__.set`, `torch.Size`, `torch._utils._rebuild_parameter`, `_codecs.encode`, `numpy.core.multiarray.scalar`) are absent and the remaining framework classes stay listed; record the commands, counts and outcome as a new section of `specs/004-scan-policy-gates/quickstart.md`, describing the files only as a pose-detection and a change-detection checkpoint (no file names, no institution or platform names, no copies of the files)

**Checkpoint**: US1 and US2 pass together; default-policy equivalence (T010) still green.

---

## Phase 5: User Story 3 - See what a check run covered (Priority: P2)

**Goal**: every check ends with a per-source, per-model check overview that is stored with the run.

**Independent Test**: spec US3; quickstart scenario 5 (integration test only).

### Tests for User Story 3 (write first, see them fail)

- [X] T037 [P] [US3] Write `tests/unit/test_overview_states.py` (renamed: one basename per test module): state mapping "first match wins: failed, incomplete, alerted, passed" (D4), `skipped` maps to `failed`, the run-wide row is the worst state with summed counts, a source no model needed is `passed` with `entries: 0` and "no entry needed this source", a model with no relevant entry reads `checked: false` with "no entry of this model can be checked by the sources asked", the `policy` row's `entries` counts "the version's pinned code-capable weight files", `dismissals_held` is 0 until Phase 7
- [X] T038 [P] [US3] Write `tests/integration/test_overview.py`: the four-source run of US3's Independent Test (osv passed, hf-scan alerted, picklescan incomplete, crossref failed with its reason) in text and JSON, exit 2 unchanged, counts `null` for the failed source, rows stored in `check_run_overview`, `run show` called with the run id `check` printed; a `check --all` on an empty database prints `No models were checked`
- [X] T039 [P] [US3] Write `tests/contract/test_cli_run_show.py`: `run show RUN_ID` text and JSON match the stored overview; an unknown run exits 1; add `run show` to `tests/integration/test_never_writes.py` (FR-005)
- [X] T040 [P] [US3] Extend `tests/contract/test_cli_audit.py`: each `coverage.sources[]` item has `last_state`, the overview state of that source in its latest run for the version, or null when no overview row exists

### Implementation for User Story 3

- [X] T041 [US3] Tally per check source in `src/model_dependabot/lifecycle.py`: pass the source being applied into `_weight_alert`, `_watch`, `_upstream_alert`, `_upstream_watch` and the OSV path; record per model and source the alerts opened or carried forward, closed, watch events and the incomplete entries of research S6 (`scan_incomplete`, `hash_mismatch`, `weight_file_absent`, `hub_scan_unknown`, `format_claim_unreadable`, `dataset_unreachable`, `paper_not_found`, `base_model_refused`); the format rules and globals policy under `policy`
- [X] T042 [US3] Implement `src/model_dependabot/assurance/overview.py`: tallies to rows with `entries` from `audit.relevant_sources` (the `policy` row: pinned code-capable weight files), states and counts of data-model.md (Check overview); `dismissals_held` stays 0 until T059
- [X] T043 [US3] Write the overview to `check_run_overview` when the run finishes, and on an interrupted run with what was tallied, in `src/model_dependabot/lifecycle.py` (`run_check`) using a new `add_overview_rows` in `src/model_dependabot/store.py`, storing the run-wide rows with `model_id = ''`
- [X] T044 [US3] Add the overview to the `check` payload and text and the `run show RUN_ID` command in `src/model_dependabot/cli.py` and `src/model_dependabot/reports.py` (no overview is added to `alerts`; D5 chose `run show`)
- [X] T045 [US3] Add `last_state` to `coverage.sources[]` when overview rows exist, in `src/model_dependabot/assurance/audit.py`

**Checkpoint**: US3 passes; SC-004 answered from one `check` output.

---

## Phase 6: User Story 4 - Stable rule IDs with documentation (Priority: P2)

**Goal**: every alert kind has one `MDB` rule ID and one page.

**Independent Test**: spec US4; quickstart scenario 6.

### Tests for User Story 4 (write first, see them fail)

- [X] T046 [P] [US4] Write `tests/fixtures/rules/assigned.json` (the twelve IDs and kinds of research S1) and `tests/unit/test_rules.py`: one rule per `ALERT_KINDS` value (twelve, `globals_policy` included, so this phase follows Phase 2), IDs unique, no ID in `assigned.json` gone or naming another kind, every page in `docs/rules/` exists with exactly the four headings of FR-015, every `WATCH_KINDS` value on exactly one page (FR-016)
- [X] T047 [P] [US4] Extend `tests/contract/test_cli_json.py` so every alert in `alerts`, `alert show`, `history` and `inventory audit` JSON carries `rule_id` and `rule_doc`, and every text alert line shows the rule ID after the alert id

### Implementation for User Story 4

- [X] T048 [US4] Implement `src/model_dependabot/rules.py`: one record per alert kind with `rule_id`, `kind`, `title`, `page`, `family` and `watch_kinds` as data-model.md (Rule)
- [X] T049 [US4] Add `rule_id` and `rule_doc` to `alert_view` and `history_view` and the ID to `alert_line` in `src/model_dependabot/reports.py`
- [X] T050 [P] [US4] Write `docs/rules/MDB101.md`, `docs/rules/MDB102.md`, `docs/rules/MDB103.md` and `docs/rules/MDB104.md` (weight files), each with What raises it; What it does not prove; How it closes; How to fix or accept it, and their watch kinds; MDB101 and MDB104 explain that one exception covers a global in both alerts and that an `unknown` global can never be excepted
- [X] T051 [P] [US4] Write `docs/rules/MDB201.md` (package advisories) with the four headings, its watch kinds and how a dismissal holds until new evidence (FR-020)
- [X] T052 [P] [US4] Write `docs/rules/MDB301.md`, `docs/rules/MDB302.md`, `docs/rules/MDB303.md` and `docs/rules/MDB304.md` (datasets and papers) with the four headings and their watch kinds
- [X] T053 [P] [US4] Write `docs/rules/MDB401.md`, `docs/rules/MDB501.md` and `docs/rules/MDB502.md` (licences and base model) with the four headings and their watch kinds, and complete the links in `docs/rules/README.md`

**Checkpoint**: T046 and T047 pass.

---

## Phase 7: Held dismissals (FR-020, owner's ruling D6; prerequisite of US5)

**Goal**: a dismissed alert of any kind is not opened again by a later check unless the check brings new
evidence, as research S13 defines it.

**Independent Test**: spec US5 scenario 5; quickstart scenario 7, held dismissal.

### Tests (write first, see them fail)

- [ ] T054 [P] [US5] Write `tests/unit/test_dismissal_hold.py`: the new-evidence rule of research S13 ("a match has the same `source`, the same `url`, the same content key and the same `matched_identifier`", or a higher severity) for each insert path: weight files (`lifecycle.py:924`, insert at 927, compared before any evidence is stored), OSV (673, insert at 698, compared on the evidence rows already stored at 681-685) and upstream (2026, insert at 2028, compared on the stored evidence ids, including `each=True` refusals); the content key used for matching drops the `VOLATILE_FIELDS` of the evidence's source; a change in a `globals_policy` alert's `unlisted` or `excepted` list is new evidence; a latest alert `fixed`, `cleared` or `withdrawn` holds nothing
- [ ] T055 [P] [US5] Write `tests/integration/test_dismissal_holds.py`: the research S5 probe (dismiss, check again) opens no new alert and lists the id under `dismissals_held`; the same for an OSV alert with an unchanged recorded record, an upstream alert with an unchanged recorded answer and a dismissed `hub_scan` alert whose recorded hub answer differs only in `downloads`, `likes` and `lastModified`; a revoked exception that grows a dismissed `globals_policy` alert's `unlisted` reopens it; a changed OSV record or another `scanner_version` opens a new alert whose cause has `reopens`; a newly pinned package version reopens (another `matched_identifier`)

### Implementation

- [ ] T056 [US5] Add `VOLATILE_FIELDS` (by evidence source; to start `downloads`, `likes` and `lastModified` for the hub answers, plus any field T007 found that the owner approved) keyed by the evidence row's `source` exactly as stored (the host name `source_of` returns for the hub's scan answers) and removing top-level keys only, and a module function `matching_key(source, body)` beside `same_evidence` in `src/model_dependabot/store.py`, which serves both a stored row (its source and stored body) and a not-yet-stored observation; used only to decide whether evidence is new; stored evidence and `canonical_sha256` stay unchanged
- [ ] T057 [US5] Implement one helper `_held_dismissal(store, target, cause_key, severity, *, observations=None, evidence_ids=None)` in `src/model_dependabot/lifecycle.py`: with observations (weight path) it compares before any evidence is stored; with stored evidence ids (OSV and upstream paths) it compares those rows, which stay stored; matching uses the logic of the module function `same_evidence` with `matching_key` and `matched_identifier`
- [ ] T058 [US5] Call it in `_raise_or_carry`, `_weight_alert` and `_upstream_alert` in `src/model_dependabot/lifecycle.py` before `insert_alert`; on hold insert no alert, link no evidence and add the id to the summary's `dismissals_held`; on new evidence set `cause.reopens` to `{alert_id, dismissed_by, dismissal_reason, closed_at}`
- [ ] T059 [US5] Count `dismissals_held` per source in `src/model_dependabot/assurance/overview.py` and show it as the `held` column in the overview text of `src/model_dependabot/reports.py`

**Checkpoint**: T054 and T055 pass; no existing test changes its expected alerts except where a dismissal now holds.

---

## Phase 8: User Story 5 - An opt-in gate for pipelines (Priority: P3)

**Goal**: `check --fail-on SEVERITY` exits 4 on open, not excepted alerts at or above it and on missing
coverage (FR-021); 2 wins. Phase 7 (T054 to T059) is a prerequisite.

**Independent Test**: spec US5; quickstart scenario 7.

### Tests for User Story 5 (write first, see them fail)

- [ ] T060 [P] [US5] Write `tests/contract/test_exit_codes.py`: every row of the README exit-code table without `--fail-on` returns its old code (SC-005); with one open HIGH alert and complete sources `--fail-on CRITICAL` exits 0 and `--fail-on high` exits 4; an `incomplete` source, an unchecked model and an empty scope each exit 4 with `gate.incomplete`, `gate.unchecked` or `gate.empty_scope` set (FR-021); a failed source exits 2 with `gate.decided_exit: false`; `gate.decided_exit` is true on 4 and on 0 with `--fail-on`; an invalid severity exits 1; precedence 3 > 2 > 4 > 0
- [ ] T061 [P] [US5] Write `tests/integration/test_gate.py`: US5 acceptance scenarios 1 to 6 and the Independent Test, including "Dismiss or except the alert and confirm `--fail-on HIGH` exits 0" with the gate's own check after the dismissal; an incomplete scan tripping `--fail-on CRITICAL`; a version registered from a registration record whose bytes are absent (`weight_file_absent` at every check) tripping `--fail-on` on two checks in a row and passing once `--source` leaves `picklescan` out; `--fail-on UNKNOWN` counting unknown severities

### Implementation for User Story 5

- [ ] T062 [US5] Add `--fail-on` (case-insensitive, one of `CRITICAL`, `HIGH`, `MODERATE`, `LOW`, `UNKNOWN`), `EXIT_GATE = 4` and the precedence of research S5 to `src/model_dependabot/cli.py`, carrying the gate result in `CommandResult`
- [ ] T063 [US5] Compute the gate after the run in `src/model_dependabot/assurance/overview.py`: every alert of every model in scope with state `open`, `excepted_at` null and `severity_rank(severity) <= severity_rank(SEVERITY)`, plus the overview's `incomplete` rows, models with `checked: false` and an empty scope (FR-021); the `gate` object of data-model.md and its text lines

**Checkpoint**: every story passes; the full suite is green offline.

---

## Phase 9: Polish & Cross-Cutting Concerns

- [ ] T064 [P] Update `README.md`: the exit-code table with code 4, its coverage conditions and its precedence; `policy ID [--format ...] [--globals ...] --by NAME`; the `exception record|list|revoke` commands; `run show RUN_ID`; `alerts --state excepted`; that a dismissal holds until new evidence; that a model whose incomplete state never clears (absent record bytes, a hub verdict that stays unknown, a gated base model, a paper that stays not found) trips `--fail-on` on every run unless `--source` leaves that source out; the check overview; rule IDs and `docs/rules/`; the safe list and its D2 trade-off
- [ ] T065 [P] Bring `specs/004-scan-policy-gates/contracts/cli.md` and `specs/004-scan-policy-gates/data-model.md` in step with what was built (field names, text layout, refusal messages), and note the change to dismissals in `specs/001-inventory-alerts/contracts/cli.md` under `alert dismiss`
- [ ] T066 [P] Update the module docstrings that describe closing and dismissal in `src/model_dependabot/lifecycle.py`, `src/model_dependabot/store.py` and `src/model_dependabot/reports.py` so they state held dismissals, excepted alerts and the new kind
- [ ] T067 Run every scenario of `specs/004-scan-policy-gates/quickstart.md` (the integration-only parts through their tests) and record the results, with the real-file section of T036, in `specs/004-scan-policy-gates/validation.md`
- [ ] T068 Run `uv run pytest -q`, `uv run ruff check` and `uv run ruff format --check` with their real exit codes (no pipe) and record the counts against the baseline taken before T008 in `specs/004-scan-policy-gates/validation.md`

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: no dependencies. T005 runs after T003 on the pre-004 build before any Phase 2 code; T006 before T032; T007 and the owner's yes on any extra field before T056.
- **Foundational (Phase 2)**: after Setup; blocks every story. T011 to T014 touch `store.py` in order; T016 after T015.
- **US1 (Phase 3)**: after Phase 2.
- **US2 (Phase 4)**: after Phase 2; T034 extends `_apply_globals_rules` from T024, so after US1's T024. T036 after T027 and T034, and needs the path the maintainer supplies.
- **US3 (Phase 5)**: after Phase 2; independent of US1 and US2 except that its counts include excepted alerts once US1 lands.
- **US4 (Phase 6)**: after Phase 2 (`globals_policy` must be in `ALERT_KINDS`); the page of MDB104 needs US2's behaviour settled.
- **Held dismissals (Phase 7)**: after Phase 2; T059 after T042.
- **US5 (Phase 8)**: after Phase 7, US1 (excepted alerts do not count) and US3 (the gate reads the overview).
- **Polish (Phase 9)**: after the stories it documents; T067 needs T036's output.

### Within each story

Tests first, run and seen to fail; then store, then rules, then lifecycle, then views and CLI.

## Parallel Example: User Story 1

```text
T017 tests/unit/test_exception_rules.py
T018 tests/contract/test_cli_exceptions.py
T019 tests/integration/test_exceptions.py
T020 tests/contract/test_cli_audit.py
T021 tests/integration/test_never_writes.py
```

## Parallel Example: User Story 4

```text
T050 docs/rules/MDB101.md to MDB104.md
T051 docs/rules/MDB201.md
T052 docs/rules/MDB301.md to MDB304.md
T053 docs/rules/MDB401.md, MDB501.md, MDB502.md
```

## Implementation Strategy

### MVP first (User Story 1 only)

1. Phase 1 and Phase 2.
2. Phase 3 (US1): exceptions with excepted alerts.
3. Stop and validate with quickstart scenario 2 and the SC-002 equivalence test.

### Incremental delivery

The plan's pull requests, in phase order: Phase 2 with US1, then US2 with the real-file check, then US3,
then US4 (all twelve rule IDs and pages at once), then held dismissals, then US5. Each keeps the full
suite green and is shippable alone.

## Notes

- [P] means different files and no dependency on an unfinished task; tasks editing `lifecycle.py`,
  `store.py`, `cli.py` or `reports.py` are never [P] with each other.
- Commit after each task or logical group, only when the owner asks; outward actions wait for the
  owner's yes.
- Never load a weight file; never copy the real checkpoints into the repository.

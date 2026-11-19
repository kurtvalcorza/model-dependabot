---

description: "Task list for feature 010: an actionable alert view for model maintainers"
---

# Tasks: An Actionable Alert View for Model Maintainers

**Input**: Design documents from `/specs/010-actionable-alert-view/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/cli.md, quickstart.md

**Tests**: Required. Constitution principle V: every test task is written before the code it tests and
must fail first (run it, see it fail for the expected reason, then write the code). The FR-016 replay
test is the one guard that passes on arrival by design (the build has not moved yet); T007 shows it can
fail with a recorded mutation (research R9). The default run stays offline (`tests/conftest.py:33-39`
blocks sockets). No weight file is ever loaded: pickles are crafted by `tests/fixtures/pickles/craft.py`.

**Owner rulings**: Q1 to Q4 accepted as recommended on 2026-11-19 (research, "Questions for the owner");
010 lands before 011 (plan, "Overlap with feature 011"). A task whose content follows a ruling names it.

**Organisation**: by user story, in priority order: US1 entry and relationship and US2 statements
(P1), US3 review steps (P2), US4 compatibility (P3). Setup records the CLI baseline before any `src/`
change; Foundational moves the rule texts into one file.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependency on an unfinished task)
- **[Story]**: Which user story the task belongs to (US1 to US4)

## Path Conventions

The existing single project: `src/model_dependabot/` and `tests/` at the repository root (plan.md,
Project Structure). House style for every string and document: plain English, British spelling, no
serial comma; no institution or platform names. Terms: "advisory view", "advice block", "rule texts",
"CLI baseline", "`impact undetermined`".

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: the recorded baseline, fixtures and skeletons, before any code relies on them

- [x] T001 Before any change, on the build before this feature (the `main` commit 010's first `src/` pull request is based on; `47ebfbe` at planning time), run `uv run pytest -q`, `uv run ruff check` and `uv run ruff format --check` each on its own (no pipe), and record their exit codes and the pass, fail and skip counts as the baseline section of `specs/010-actionable-alert-view/validation.md`
- [x] T002 [P] Write `tests/fixtures/cli_baseline/scenarios.py`, modelled on `tests/fixtures/equivalence/scenarios.py`: one store built from recorded answers (`RecordedFetcher`) with a fixed clock, holding an open, an excepted, a dismissed, a fixed and a withdrawn or cleared alert and one run; the named invocation list of research R9 (`alerts ID` with `--state` `open`, `excepted`, `closed` and `all`; `alert show` for each of those alerts; `history ID`; `run show RUN_ID`; `check ID` and `check ID --fail-on HIGH` in copies of the store), each in text and `--json`; outputs with the scenario directory replaced by `<work>`
- [x] T003 On the build before this feature (the `main` commit 010's first `src/` pull request is based on; at planning time `47ebfbe`, `src` tree `4ca0c708b930870cbf5bce02b3f2ef20f4797882`), after T002 and before any `src/` change (T006 included), write `tools/record_cli_baseline.py` and run it to record `tests/fixtures/cli_baseline/pre-010-baseline.json`: per invocation, argv, stdout, stderr and exit code, plus the commit and the `git rev-parse HEAD:src` tree hash. The recorder takes the expected tree as an argument and refuses (exit 1, nothing written) unless `git status --porcelain -- src` is empty, `HEAD:src` equals that tree and, when the file exists, equals the tree recorded in it (FR-016, research R9)
- [x] T004 [P] Build `tests/fixtures/advice/`: manifests and recorded answers (copied from the existing `tests/fixtures/osv/`, `hf/`, `crossref/`, `datacite/`, `hf_upstream/` and `locks/` recordings, never fetched) for models that together raise one alert of every rule ID of `src/model_dependabot/rules.py:28-118` (a local pickle from `craft.py`, a hub weight file, a strict format and globals policy, a locked package at an affected version, a base model disabled in one model and unavailable in another, a DOI dataset citing a retracted paper, a removed and a not-findable dataset, a changed licence), plus one version registered from a record with absent bytes (`weight_file_absent`) and one imported version; document each in `tests/fixtures/advice/NOTES.md`
- [x] T005 [P] Write `tests/fixtures/advice/verdicts.json`: the fixed verdict phrases of research R10 ("clean result" included), each with the FR-011 clause it guards, and the `allowed` list of exact sentences with rule ID and field: the `limitations` sentences at `docs/rules/MDB101.md:13` and `docs/rules/MDB102.md:13`, verbatim
- [x] T006 After T003 (this is the first `src/` change), create `src/model_dependabot/rule_texts/__init__.py` (empty, with a module docstring, as `src/model_dependabot/safe_globals/__init__.py`) and `src/model_dependabot/rule_texts/README.md`: what `rule-texts.toml` holds, the placeholders allowed (research R4), that the three prose sections of `docs/rules/MDB*.md` are rendered from it by `tools/render_rule_pages.py`, and how `version` is bumped

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: the baseline replay and one source of rule texts, which every story reads

**CRITICAL**: no user story work starts until this phase is complete.

### Tests first

- [x] T007 [P] Write `tests/integration/test_cli_baseline.py`: replay every invocation of `tests/fixtures/cli_baseline/pre-010-baseline.json` with `tests/fixtures/cli_baseline/scenarios.py` and compare stdout, stderr and exit code byte for byte (FR-016, SC-002); assert that the file's recorded `src` tree equals the expected tree of research R9 and that the file's SHA-256 equals a constant pinned in the test, so a re-record fails the suite until the owner updates the pin; then change one character of `alert_line` in `src/model_dependabot/reports.py:241-244`, see the test fail, revert, and record that run in `specs/010-actionable-alert-view/validation.md`
- [x] T008 [P] Write `tests/unit/test_rule_texts.py` (fails first): every rule ID of `RULES` has a table in `rule-texts.toml` and no other table exists; `limitations`, `closes`, `fix`, `steps` (two or more) and `not_established` (one or more, the first "whether this alert affects model {model_id}") are present and non-empty; only the placeholders of research R4 appear; a recorded SHA-256 of the file fails when the text changes without a new `version`; no field of `rule-texts.toml` contains a phrase of `tests/fixtures/advice/verdicts.json` except inside a sentence on its `allowed` list for that rule ID and field, matched exactly (research R10), and every `allowed` sentence still occurs in its field; a texts file with one rule's `steps` removed is refused by the loader (SC-001, FR-014)
- [x] T009 [P] Extend `tests/unit/test_rules.py`: rendering every page with `tools/render_rule_pages.py` in memory gives the committed `docs/rules/MDB*.md` bytes (pages in step); the four headings stay (`tests/unit/test_rules.py:51-55`); every alert kind of `store.ALERT_KINDS` (`src/model_dependabot/store.py:52-66`) has at least one row in `rules.RELATIONSHIPS`, and `licence_changed` has one for `base_model` and one for `dataset` (FR-005)

### Implementation

- [x] T010 Write `src/model_dependabot/rule_texts/rule-texts.toml`, version 1: per rule ID, `limitations`, `closes` and `fix` copied verbatim from the "What it does not prove", "How it closes" and "How to fix or accept it" sections of `docs/rules/MDB101.md` to `MDB502.md` (the existing prose of each page is unchanged; only a sentence T008 refuses would be reworded); `not_established` with the impact question first and the rule's questions of the spec's review step table; `steps` covering the themes of the spec's table "Initial review steps", each naming only commands of `src/model_dependabot/cli.py:162-318`, the last restating `closes`
- [x] T011 Add to `src/model_dependabot/rules.py`: a cached loader of `rule_texts/rule-texts.toml` (path beside the package, read with `tomllib` as `src/model_dependabot/assurance/globals_policy.py:23,47` reads the safe list) that applies every refusal of T008; `texts_for(rule_id)`; and `RELATIONSHIPS`, the table of data-model.md keyed by (entry kind, alert kind)
- [x] T012 Write `tools/render_rule_pages.py`, which rewrites the "What it does not prove", "How it closes" and "How to fix or accept it" sections of each `docs/rules/MDB*.md` from `rule-texts.toml` (Q3 ruling: the fix prose, unchanged, then the numbered steps with placeholders shown as `<name>`, so every page gains its steps list), leaving the title, the kind line, "Related watch kinds" and "What raises it" as they are; run it and commit the pages

**Checkpoint**: T007 to T009 pass; the full suite is green; the replay finds no difference.

---

## Phase 3: User Story 1 - See which entry an alert affects and how it relates (Priority: P1) 🎯 MVP

**Goal**: `alert show ALERT_ID --advice` names the entry, its places, its relationship with basis and
runtime use, without changing a byte of today's output.

**Independent Test**: spec US1; quickstart scenarios 2 and 3.

### Tests for User Story 1 (write first, see them fail)

- [x] T013 [P] [US1] Write `tests/unit/test_affected.py` for `resolve_entry` over hand-built version and entry rows: each match rule of research R2's table; a repository-keyed base-model and hub-dataset alert resolves by repository whatever revision the entry pins (US1 scenario 4); `unresolved` with each of the three reasons and no match by name, similarity or prefix (FR-006); places in version-descending then `entry_id` order (US1 scenario 5); a fixed alert names `last_held_in_version` and `closed_by_version`, the fixing version (US1 scenario 3, Edge Cases); an `import` version gives `section` null and `declared_by` `imported`; a hub weight file's location is `hf:<repo>/<file>`; a paper alert gives `paper cited by a declared dataset` with `steps_from_model` 2
- [x] T014 [P] [US1] Write `tests/unit/test_runtime_use.py`: a `not_used_at_runtime` dismissal gives `declared`, `not_used`, with `by`, `at` and `note`; every other reason and every other state gives `unknown` with the fixed `why`; a second alert on the same identifier reads `unknown` with the dismissed one in `context` (FR-008); an alert reopened from a held dismissal (`cause.reopens`) reads `unknown` with the dismissed one in `context`; no input yields `observed`; and assert, as a regression test, that `store.close_alert` stamps `closed_at` on dismissal (confirmed at `src/model_dependabot/store.py:1752-1764`, research R3)
- [x] T015 [P] [US1] Write `tests/integration/test_advice_read_only.py` (FR-002, FR-003, SC-004; Q2 ruling): on a current-schema store from T004, built so the `first_linked_run` mark already exists (`src/model_dependabot/store.py:689-711`), first assert as a control that the plain `alert show ID` and `alerts ID` leave the database file byte-identical, so a later failure is the view's; then assert that building every advisory view leaves `store.conn.total_changes` unchanged; after `alert show ID --advice` (and, once T037 lands, `alerts ID --advice`), text and JSON, the database file and every file under `evidence/` are byte-identical and a spying fetcher records no request; two runs give identical bytes
- [x] T016 [P] [US1] Write `tests/integration/test_advice_entry.py`: US1 acceptance scenarios 1 to 5 and the Independent Test with the T004 model (a fixed alert's text names the last holding version and the fixing version; one alert per family names the right entry, section, relationship and basis, runtime use `unknown`; dismissing the package alert `not_used_at_runtime` shows the declaration with who and when); an imported version's relationship is shown as imported, never as the owner's own (Edge Cases)
- [x] T017 [P] [US1] Write `tests/contract/test_cli_advice.py`: `alert show ID --advice --json` has the payload of `alert show ID --json` plus `advice` as its last key, with the fields and order of `specs/010-actionable-alert-view/data-model.md` (`schema` `advice/1`); `severity.note` is the fixed text of data-model.md for each origin `policy`, `database_specific`, `cvss_v3`, `cvss_v4` and `unknown` (`src/model_dependabot/matching/severity.py:90-103`), and any other origin is refused (FR-004); no key named or containing `score`, `weight` or `rank`; the text output begins with the bytes of `alert show ID` (contracts/cli.md, Prefix); an unknown alert exits 1 with and without `--advice`

### Implementation for User Story 1

- [x] T018 [US1] Implement `resolve_entry(alert, versions)` and the `places` list in `src/model_dependabot/assurance/affected.py`, a pure function of `store.entries` rows (`src/model_dependabot/store.py:1458-1478`) and `model_versions.origin`, with the match rules and orders of research R2 (a paper match always requires `paper_dois` to hold `cause.paper_doi`); package names compared with `packaging.utils.canonicalize_name`; repository scoping by importing `_repository_scoped`, `_hub_scope`, `base_model_repo` and `hub_dataset_repo` from `src/model_dependabot/lifecycle.py` unchanged (no edit to `lifecycle.py`: plan, "Overlap with feature 011")
- [x] T019 [US1] Add `relationship(entry, alert, places)` to `src/model_dependabot/assurance/affected.py`, reading `rules.RELATIONSHIPS` and building the basis of data-model.md
- [x] T020 [US1] Add `runtime_use(alert, others)` to `src/model_dependabot/assurance/affected.py` per research R3, `others` being the model's other alerts resolved to the same identifier
- [x] T021 [US1] Implement `advice_view(store, alert, *, versions=None)` and `advice_text(view)` in `src/model_dependabot/assurance/advice.py`: `schema`, `alert_id`, `severity`, `entry`, `relationship`, `runtime_use`, `impact` (the constant `impact undetermined`) and `rule_doc`, with the remaining fields present as empty lists or null until Phases 4 and 5; only reading methods of `Store`; the text layout of contracts/cli.md
- [x] T022 [US1] Add `--advice` (`store_true`) to the `alert show` leaf in `src/model_dependabot/cli.py:277-278`; in `alert_show` (`src/model_dependabot/cli.py:863-869`) append `advice` to the payload and `"\n\n" + advice_text(...)` to `_alert_text`'s output only when it is set; keep `_open` (`src/model_dependabot/cli.py:546-547`) as it is (Q2 (a))

**Checkpoint**: T013 to T017 pass; T007 replay still finds no difference.

---

## Phase 4: User Story 2 - Tell what is established from what is not (Priority: P1)

**Goal**: established statements cite evidence rows; not-established and limitations are listed; claim
states and owner decisions stand apart; impact is always `impact undetermined`.

**Independent Test**: spec US2; quickstart scenario 4.

### Tests for User Story 2 (write first, see them fail)

- [x] T023 [P] [US2] Write `tests/unit/test_advice_statements.py`: one established statement per evidence row, each citing exactly that row's id (FR-009); a withdrawn or cleared alert states the closing row as established and not that the model was never affected (Edge Cases); redacted fields listed on the statement; `not_established` starts with the impact question, then the rule's items, then the conditional items of research R6 (unresolved entry, `import` version, hub weight file, `weight_file_absent` watch event, package marker limitation under Q1 (a)); `limitations` equal the rule's text; a `package_advisory` alert for an alias group lists every advisory id and keeps the stored severity (Edge Cases)
- [x] T024 [P] [US2] Write `tests/unit/test_advice_claims.py`: an imported entry's `unverified` and `contradicted` claims appear in `claims` with that state and in no established statement (FR-013, D6); an owner version's claims read `owner`
- [x] T025 [P] [US2] Write `tests/integration/test_advice_statements.py`: US2 acceptance scenarios 1 to 6 and the Independent Test over one alert of every rule ID from T004 (SC-003: 100% of established statements cite an evidence row of their alert, 100% read `impact undetermined`); a dismissed and an excepted alert show the owner-decision block (who, when, reason, note; exception id, global, expiry) and still read `impact undetermined` (FR-012); after removing each `allowed` sentence of `tests/fixtures/advice/verdicts.json` by exact content wherever it appears (in `limitations` or in the `closes` text inside the last review step), no string of any view, text or JSON, contains a phrase of the list (FR-011, research R10)

### Implementation for User Story 2

- [x] T026 [US2] Build `established` in `src/model_dependabot/assurance/advice.py` from `store.alert_evidence` (`src/model_dependabot/store.py:1945-1950`) per research R6, leaving an exception's evidence row to the owner-decision block
- [x] T027 [US2] Build `not_established` and `limitations` in `src/model_dependabot/assurance/advice.py` from `rules.texts_for` with placeholders filled from the alert's stored fields, plus the conditional items of research R6; under the Q1 ruling the package marker limitation and question (follow-up issue #28)
- [x] T028 [US2] Build `claims` in `src/model_dependabot/assurance/advice.py` with `trust.claim_verification` (`src/model_dependabot/assurance/trust.py:126-152`) and `store.claim_checks` (`src/model_dependabot/store.py:1536`) for the version of `places[0]`
- [x] T029 [US2] Build `owner_decision` in `src/model_dependabot/assurance/advice.py` per research R7, reading `view_state` (`src/model_dependabot/reports.py:61-63`), `cause.excepted` and `store.get_exception` (`src/model_dependabot/store.py:1222`)
- [x] T030 [US2] Render the Established, Not established, Limitations, Claims, Impact and Owner decision lines in `advice_text` in `src/model_dependabot/assurance/advice.py`, as contracts/cli.md shows

**Checkpoint**: US1 and US2 pass together; T007 and T015 still green.

---

## Phase 5: User Story 3 - Follow fixed review steps for the alert's kind (Priority: P2)

**Goal**: every view ends with the rule's numbered steps, filled only with the alert's own identifiers,
the last saying how the alert closes.

**Independent Test**: spec US3; quickstart scenario 5.

### Tests for User Story 3 (write first, see them fail)

- [x] T031 [P] [US3] Write `tests/unit/test_review_steps.py`: every placeholder of a rule's `steps` and `not_established` is present in the cause shape of that kind's T004 alert; two alerts of one rule ID on different entries give steps that differ only in substituted values; the last step starts with `How this alert closes:` and restates `closes` (FR-015); every backticked `model-dependabot …` command in a step, with placeholders replaced by sample values, parses with `build_parser()` (`src/model_dependabot/cli.py:162`) without error; no step contains `automatically` or names the tool as the actor (constitution III)
- [x] T032 [P] [US3] Write `tests/integration/test_advice_steps.py`: US3 acceptance scenarios 1 to 3 on the T004 alerts; with a patched texts file lacking one rule's steps, loading fails and the test names the rule (US3 scenario 2)

### Implementation for User Story 3

- [x] T033 [US3] Build `review_steps` in `src/model_dependabot/assurance/advice.py` from `rules.texts_for(rule_id).steps`, numbered from 1, placeholders filled from the alert's stored fields only, `not recorded` for a missing value (research R4)
- [x] T034 [US3] Render the Review steps lines in `advice_text` in `src/model_dependabot/assurance/advice.py`

**Checkpoint**: US1 to US3 pass; the rule pages are still in step (T009).

---

## Phase 6: User Story 4 - Keep today's output and exit codes unchanged (Priority: P3)

**Goal**: `alerts ID --advice` lists one view per alert in today's order; without the option nothing
changes; with it no exit code changes.

**Independent Test**: spec US4; quickstart scenarios 1 and 7.

### Tests for User Story 4 (write first, see them fail)

- [x] T035 [P] [US4] Write `tests/contract/test_exit_codes_advice.py`: every `alerts` and `alert show` invocation of `tests/fixtures/cli_baseline/pre-010-baseline.json` exits the same with `--advice` (FR-017); an unknown model or alert exits 1 with and without it; after advice views of every alert, `check --fail-on HIGH` returns the baseline's exit code and gate counts (US4 scenario 3); `check`, `history` and `run show` refuse `--advice` (exit 1, as any unknown option)
- [x] T036 [P] [US4] Write `tests/integration/test_alerts_advice.py`: `alerts ID --advice` gives one view per item of `alerts` then `excepted`, in that order, under each `--state` (FR-003); watch events carry no `advice`; `advice_summary.alerts_listed` counts the views, and a model with none gives the empty-model note (US2 scenario 6); with every `advice` and `advice_summary` key removed the JSON equals `alerts ID --json`, and the text begins with the bytes of `alerts ID` (FR-018)

### Implementation for User Story 4

- [x] T037 [US4] Add `--advice` to the `alerts` leaf in `src/model_dependabot/cli.py:271-273`; in `alerts` (`src/model_dependabot/cli.py:851-855`) read the model's versions and entries once, append `advice` to each object of `alerts` and `excepted` and `advice_summary` to the payload, and the advice blocks after `alerts_text`'s output, only when the flag is set
- [x] T038 [US4] Re-run T007, T015 (now with `alerts --advice`), T035 and T036, and record the result in `specs/010-actionable-alert-view/validation.md`

**Checkpoint**: every story passes; the full suite is green offline; the replay finds no difference.

---

## Phase 7: Polish & Cross-Cutting Concerns

- [x] T039 [P] Update `README.md` "Commands": `alert show ALERT_ID --advice` and `alerts ID --advice`; what the view shows (entry, relationship and basis, runtime use, established and not established, limitations, claims, `impact undetermined`, owner decision, review steps); that it reads only and changes no exit code; that it scores nothing and settles no impact
- [x] T040 [P] Bring `specs/010-actionable-alert-view/contracts/cli.md` and `specs/010-actionable-alert-view/data-model.md` in step with what was built (field names, text layout); check that the spec's marker edge case (`specs/010-actionable-alert-view/spec.md`, amended for the Q1 ruling on 2026-11-19, follow-up #28) still matches what was built
- [x] T041 [P] Update the module docstrings of `src/model_dependabot/cli.py` and `src/model_dependabot/rules.py` to name the advisory view and the rule texts (`reports.py` is not edited: plan, "Overlap with feature 011")
- [x] T042 [P] Note in `docs/rules/README.md` that three sections of each page are rendered from `src/model_dependabot/rule_texts/rule-texts.toml` by `tools/render_rule_pages.py`
- [x] T043 Walk through one alert per family (weight files, packages, datasets and papers, licences, base model) with the text view alone and record, for each, the entry, the relationship, what is established and the next step in `specs/010-actionable-alert-view/validation.md` (SC-005)
- [x] T044 Run every scenario of `specs/010-actionable-alert-view/quickstart.md` and record the results in `specs/010-actionable-alert-view/validation.md`
- [ ] T045 Run `uv run pytest -q`, `uv run ruff check` and `uv run ruff format --check` with their real exit codes (no pipe) and record the counts against the T001 baseline in `specs/010-actionable-alert-view/validation.md`
- [x] T046 Review `src/model_dependabot/rule_texts/rule-texts.toml`, the rendered `docs/rules/MDB*.md` sections and every fixed string of `src/model_dependabot/assurance/advice.py` for house style (British spelling, no serial comma) and for any institution or platform name

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: no dependencies. T001 first, on the untouched build. T003 after T002 and before any `src/` change; T004 and T005 any time; T006 after T003.
- **Foundational (Phase 2)**: after Setup; blocks every story. T010 after T006 and T008; T011 after T010; T012 after T011 and T009.
- **US1 (Phase 3)**: after Phase 2. T018 to T021 touch `assurance/affected.py` and `assurance/advice.py` in order; T022 after T021.
- **US2 (Phase 4)**: after US1 (it fills fields of the view US1 creates). T026 to T030 in order (one file).
- **US3 (Phase 5)**: after Phase 2 for its tests; T033 and T034 after T021, so after US1; independent of US2 except that both edit `assurance/advice.py` (never in parallel).
- **US4 (Phase 6)**: after US1 to US3; T037 edits `cli.py`, after T022.
- **Polish (Phase 7)**: after the stories it documents; T045 last.

### Within each story

Tests first, run and seen to fail; then the resolver, then the view, then text, then the CLI.

## Parallel Example: User Story 1

```text
T013 tests/unit/test_affected.py
T014 tests/unit/test_runtime_use.py
T015 tests/integration/test_advice_read_only.py
T016 tests/integration/test_advice_entry.py
T017 tests/contract/test_cli_advice.py
```

## Parallel Example: Setup

```text
T002 tests/fixtures/cli_baseline/scenarios.py
T004 tests/fixtures/advice/
T005 tests/fixtures/advice/verdicts.json
```

## Implementation Strategy

### MVP first (User Story 1 only)

1. Phase 1 and Phase 2 (baseline recorded, rule texts in one file).
2. Phase 3 (US1): `alert show --advice` with entry, relationship and runtime use.
3. Stop and validate with quickstart scenarios 1 to 3 and the replay test.

### Incremental delivery

The plan's pull requests, in phase order: Phase 1 and 2, then US1, then US2, then US3 with US4. Each
keeps the full suite green and the replay without difference, and is shippable alone.

## Notes

- [P] means different files and no dependency on an unfinished task; tasks editing `cli.py`,
  `rules.py`, `assurance/affected.py` or `assurance/advice.py` are never [P] with each other.
- The baseline (T003) is recorded once, from the build before this feature; T007 pins its SHA-256, so a
  re-record fails the suite until the pin is updated. A re-record is an owner decision recorded in
  `validation.md`; feature 011, which lands after 010, re-records it where 011 changes output (plan,
  "Overlap with feature 011").
- Commit after each task or logical group, only when the owner asks; outward actions wait for the
  owner's yes.

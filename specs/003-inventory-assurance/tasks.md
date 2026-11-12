---

description: "Task list for feature 003: evidence-backed dependency discovery and inventory assurance"
---

# Tasks: Evidence-Backed Dependency Discovery and Inventory Assurance

**Input**: Design documents from `/specs/003-inventory-assurance/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/, quickstart.md

**Tests**: Required. Constitution principle V and FR-025: tests are written before the code they test and
must fail first; hub answers are recorded responses only; the default run blocks sockets
(`tests/conftest.py`), so any network use in discovery or the audit fails loudly.

**Organization**: Tasks are grouped by user story (US1 to US4 of spec 003) so each can be built, tested and
shipped on its own, in the plan's delivery order: US1, then US2, then US3 and US4.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies on unfinished tasks)
- **[Story]**: Which user story this task belongs to (US1 to US4)

## Path Conventions

The existing single project: `src/model_dependabot/` and `tests/` at the repository root (plan.md,
Project Structure). House style for every string and document: plain English, British spelling, no serial
comma; no institution names.

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: dependency and package skeletons

- [ ] T001 Add PyYAML pinned to an exact version to `[project].dependencies` in `pyproject.toml` and refresh `uv.lock` with `uv lock` (research A6; plan Technical Context)
- [X] T002 [P] Create the package skeletons `src/model_dependabot/assurance/__init__.py` and `src/model_dependabot/discover/__init__.py`, each with a module docstring stating its purpose and that `discover` never imports `model_dependabot.store` (plan, Structure Decision)
- [ ] T003 [P] Create `tests/fixtures/format_check/NOTES.md`, `tests/fixtures/boms/NOTES.md` and `tests/fixtures/projects/NOTES.md` describing what each fixture is, where it came from and how it was recorded or built (research A13)

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: schema and classification changes every story needs. No story work starts before this phase is done.

- [X] T004 Write failing tests in `tests/unit/test_store_assurance_schema.py`: a fresh database has `model_versions.origin` with values limited to `manifest` | `record` | `import` | null; `inventory_entries.format_origin` limited to `bytes` | `name` | `record` | `import` | null; table `claim_checks` with `claim_check_id`, `model_id`, `version`, `entry_identifier`, `claim` limited to `code_free` | `identity`, `run_id` (nullable), `outcome` limited to `confirmed` | `contradicted` | `unreadable`, `measured_format`, `measured_can_run_code`, `reason`, `evidence_id`, `checked_at`; an existing pre-003 database gains all three on open, rows with `registration_record_sha256` get `origin = 'record'` and every other old row keeps `origin` null (data-model.md, Model version; research A2)
- [X] T005 Add the columns, the `claim_checks` table, the on-open back-fill and the watch-event kinds `format_claim_contradicted` and `format_claim_unreadable` to `WATCH_KINDS` in `src/model_dependabot/store.py`; add `Store.add_claim_check(...)`, `Store.latest_claim_check(model_id, version, identifier)` and `Store.claim_checks(model_id, version)`; make T004 pass
- [X] T006 [P] Write failing tests in `tests/unit/test_build.py` for `classify_lead(name, lead, total_size)` in `src/model_dependabot/inventory/build.py`: it gives the same class as `classify(name, content)` for full safetensors, GGUF, pickle (protocols 2 to 5), zip and ONNX fixtures when given their first 1 MiB and true size; a lead starting like a zip under a code-free name is never code-free; a safetensors header longer than the lead returns a sentinel saying more bytes are needed with the needed length (research A4)
- [X] T007 Implement `classify_lead` by making the private tests (`_is_safetensors`, `_is_gguf`, `_is_code_free`, `_starts_like_zip`) take a lead plus a total size, keeping `classify`'s behaviour byte-for-byte unchanged, in `src/model_dependabot/inventory/build.py`; make T006 and the existing `tests/unit/test_build.py` pass
- [X] T008 Write failing tests in `tests/integration/test_register.py` and `tests/integration/test_register_from_record.py`: `register` stores `origin = 'manifest'`, `register --from-record` stores `origin = 'record'`; local weights get `format_origin = 'bytes'`, manifest hub weights `format_origin = 'name'`, record weights `format_origin = 'record'`; other entry kinds have `format_origin` null; alerts and watch events of every existing integration test are unchanged (FR-007, SC-002)
- [X] T009 Set `format_origin` in `_local_weight` and `_hub_weight` in `src/model_dependabot/inventory/build.py` and in the record path in `src/model_dependabot/inventory/record.py`; pass `origin` through `_record` in `src/model_dependabot/cli.py` to `Store.add_version` in `src/model_dependabot/store.py`; make T008 pass

**Checkpoint**: schema in place, classification works on a lead, every existing test still green.

---

## Phase 3: User Story 1 - An imported code-free claim cannot hide a code-capable weight file (Priority: P1) 🎯 MVP

**Goal**: imported and legacy code-free claims count under the strict policy only once confirmed from local bytes or a bounded hub header read (FR-001 to FR-007, FR-002a, FR-002b).

**Independent Test**: import `tests/fixtures/boms/forged-code-free.json`, set strict, check with recorded answers: `format_policy` alert open, entry contradicted; import `confirmed-code-free.json`: no alert (quickstart §2, §3).

### Recording (needs a network that reaches the hub)

- [X] T010 [US1] Write a `live`-marked test in `tests/live/test_live_format_check.py` that sends a ranged `GET` (`Range: bytes=0-1048575`) to the `resolve` URL of one public safetensors file at a pinned commit through `UrlFetcher` and asserts a `206` with `Content-Range` after redirects that satisfy the SEC-02 rules; extend `tools/record_fixtures.py` to record the tree answer and ranged answers (meta key `range`) into `tests/fixtures/format_check/` for: a safetensors file, a GGUF file, a pickle named `.safetensors`, a zip, a `200` that ignores the range, a `403` refusal and a `503`. Run it where the hub is reachable and commit the recordings (research A4 "To verify"). If the live answer is not `206`, stop and revise research A4 before T014

### Tests for User Story 1 (write first, must fail)

- [X] T011 [P] [US1] Failing tests in `tests/unit/test_fetcher_hardening.py` for `get_range(url, length)` on `UrlFetcher` and `RecordedFetcher` in `src/model_dependabot/sources/fetcher.py`: sends `Range: bytes=0-{length-1}`, follows redirects under the SEC-02 rules, returns at most `length` bytes for a `206` or a `200`, never writes the ETag cache, keys its in-run cache by URL and range, and `RecordedFetcher` matches the meta `range` key
- [X] T012 [P] [US1] Failing tests in `tests/unit/test_hf_header.py` for `read_header(repo, commit, file, expected_sha256)` in `src/model_dependabot/sources/hf.py` against `tests/fixtures/format_check/`: hash from the tree differs → `contradicted` (claim `identity`); file missing from tree, or a `401`, `403` or `404` on the tree or the ranged read → `unreadable`, not a failure; safetensors header longer than 1 MiB → second range up to `8 + header length`, at most 16 MiB, longer → `unreadable`; total size from `Content-Range` or, for a `200`, `Content-Length`; a network error, a `5xx` after retries or a connection cut off mid-read raises `SourceFailedError`, never a confirmed result (FR-002a, FR-002b, research A4)
- [X] T013 [P] [US1] Failing tests in `tests/unit/test_trust.py` for `src/model_dependabot/assurance/trust.py`: `needs_confirmation(entry, version_origin)` is true exactly when `format_origin` is `import`, or when it is null and the version's `origin` is null or `import`; `counts_as_code_free(entry, version_origin, latest_check)` is true only for a pinned entry with `can_run_code` false whose claim is owner-trusted (`bytes`, `name`, `record`) or whose latest `code_free` claim check is `confirmed` (data-model.md, Rule FR-004); `claim_verification(entry, version_origin, checks)` returns, for each of `format`, `can_run_code`, `sha256` and `revision`, one of `owner`, `measured`, `confirmed`, `unverified` or `contradicted`, with `unverified` and the reason "no check confirms this claim" for imported package hashes and base-model or dataset revisions (FR-001, research A12)
- [X] T014 [P] [US1] Failing tests in `tests/unit/test_format_check.py` for `src/model_dependabot/assurance/format_check.py`. Local cases (no recordings needed): a local entry is read only inside the version's `base_dir` (a symbolic link or `..` out of it → `unreadable`, file not opened); a missing local file → `unreadable` with reason "file absent"; a local hash mismatch → `contradicted` (claim `identity`). Hub cases (need T010's recordings): an imported hub weight without a pinned revision is never read; a connection reset during `get_range` fails the source, records no claim check and leaves alerts unchanged; identity is checked for every imported pinned weight and the header only for code-free ones. Both: a final outcome (`confirmed` or `contradicted`) is never read again for the version; a version with nothing needing confirmation makes zero requests; each outcome stores one evidence row whose JSON body holds URL or path, commit, file, status, `Content-Range`, lead SHA-256, lead length and measured class, and no weight bytes (research A3 to A5)
- [X] T015 [P] [US1] Failing tests in `tests/integration/test_claim_trust.py` per quickstart §2: forged BOM → `format_claim_contradicted` watch event and open `format_policy` alert whose cause has `unconfirmed_claims` and `rule: "imported code-free claims count only once confirmed"`; honest BOM → `confirmed` claim check and no alert; an unconfirmed claim plus a `format-check` failure → alert open, `check` exits 2; a later confirmation closes the alert as `cleared` with the claim check's evidence (data-model.md, Alert)
- [X] T016 [P] [US1] Failing test `test_legacy_import` in `tests/integration/test_claim_trust_legacy.py` per quickstart §3: a database built with the pre-003 schema holding a strict-policy imported model whose code-free claim silenced the alert gets the alert after one check with `format-check` answering `503`; a legacy manifest model whose local file is present is confirmed and keeps its alerts unchanged (FR-005, FR-007)
- [X] T017 [P] [US1] Failing tests in `tests/integration/test_import_local_bytes.py`: importing a BOM whose local weight `model.safetensors` is a pickle beside the BOM stores the entry as `pickle`, `can_run_code` true, `format_origin = 'bytes'`, and records a `contradicted` claim check with `run_id` null; a weight path that resolves outside the BOM's directory is not read; `model-dependabot:format-origin` in the imported document is ignored (contracts/inventory-profile.md)
- [X] T018 [P] [US1] Failing contract tests in `tests/contract/test_cli_check_format.py`: `format-check` is in the default source list of `check`; `check --source osv` does not run it; `check --json` reports `"format-check": "ok" | "failed: …" | "skipped"` and per model `claim_checks: [{identifier, outcome, measured_format, reason}]`; every existing field is unchanged (contracts/cli.md)
- [X] T019 [P] [US1] Failing test in `tests/contract/test_inventory_profile.py`: `inventory export` writes `model-dependabot:format-origin` on weight components with a recorded origin and omits it for legacy entries; the exported document still validates against CycloneDX 1.7 (contracts/inventory-profile.md)

### Implementation for User Story 1

- [X] T020 [US1] Implement `get_range` on `UrlFetcher` and `RecordedFetcher`, and add it to the `Fetcher` protocol, in `src/model_dependabot/sources/fetcher.py`; make T011 pass
- [X] T021 [US1] Implement `read_header` in `src/model_dependabot/sources/hf.py` using `HuggingFace.hub_file`, `get_range` and `classify_lead`; make T012 pass
- [X] T022 [P] [US1] Implement `needs_confirmation`, `counts_as_code_free` and `claim_verification` in `src/model_dependabot/assurance/trust.py`; make T013 pass
- [X] T023 [US1] Implement the read-then-apply `format-check` in `src/model_dependabot/assurance/format_check.py` (read everything first, record `identity` and `code_free` claim checks and evidence after, retry `unreadable` next run, treat 401/403/404 and an over-limit header as `unreadable`, raise `SourceFailedError` on network errors, `5xx` after retries or a cut-off read); make T014 pass
- [X] T024 [US1] Wire `format-check` into `src/model_dependabot/lifecycle.py`: add the constant, add it to `WEIGHT_SOURCES`, run it before `_apply_format_rules`, record `format_claim_contradicted` and `format_claim_unreadable` watch events (the latter once per version and reason), make `_code_free` use `counts_as_code_free`, add `unconfirmed_claims` and `rule` to the `format_policy` cause, clear an open `format_policy` alert as `cleared` when a confirmation makes a code-free file count; add `format-check` to `CHECK_SOURCES` and `claim_checks` to the check JSON in `src/model_dependabot/cli.py`; make T015, T016 and T018 pass
- [X] T025 [US1] In `src/model_dependabot/inventory/cyclonedx.py` and the `import` command in `src/model_dependabot/cli.py`: store `origin = 'import'` and `format_origin = 'import'`; classify a present local weight file (inside the BOM's directory only) from its bytes and record the `contradicted` claim check; ignore an imported `model-dependabot:format-origin`; export the property; make T017 and T019 pass
- [X] T026 [US1] Update `src/model_dependabot/reports.py` so `alerts`, `alert show` and `inventory show` text output show "code-free claimed, unverified" or "contradicted" with the claim's origin and the rule text for affected `format_policy` alerts (US1 acceptance scenario 2)

**Checkpoint**: US1 complete and shippable alone as one pull request; SEC-01 closed; full suite green offline.

---

## Phase 4: User Story 2 - Audit what a clean check does and does not establish (Priority: P1)

**Goal**: `inventory audit ID [--version N] [--stale-after HOURS]` reports findings, assurance and coverage, read-only (FR-008 to FR-014).

**Independent Test**: quickstart §4: never-checked model shows `not_yet_checked`; after a check with one failed source, gaps and the failure are counted beside zero alerts; database bytes unchanged.

### Tests for User Story 2 (write first, must fail)

- [X] T027 [P] [US2] Failing unit tests in `tests/unit/test_audit.py` for `src/model_dependabot/assurance/audit.py`: entry status per research A12 (`verified`, `declared-but-unverified`, `conflicting`, `unavailable`); relevant sources per entry kind (package → `osv`; local code-capable weight → `picklescan`; hub weight → `hf-scan`; claim needing confirmation → `format-check`; base model → `hf-hub`; hub dataset → `hf-hub`, `hf-takedowns`; DOI → its routed sources), with `relevant_entries` a list of identifiers or locations; `claims[]` for `format`, `can_run_code`, `sha256` and `revision` with their `verification`; latest run after the version's registration whose scope is `all` or the model id and which requested the source; `not checked`, stale after `stale_after_hours`; uncheckable entries with reasons; `undeclared_kinds` limited to `environment`, `base_model`, `datasets`, `weights`
- [X] T028 [P] [US2] Failing integration tests in `tests/integration/test_audit.py` per quickstart §4 and US2 acceptance scenarios 1 to 5, including: the summary never omits gaps, unverified claims, failed sources or uncheckable entries when there are zero alerts (SC-003); the `statement` text is present; the database file's SHA-256 and every evidence file are unchanged by the audit, including on a database built with the pre-003 schema (read as defaults, never upgraded); a schema older than feature 002 exits 1 with "run any check once to upgrade this database"; no socket is opened; an audit of a model with 300 entries and 365 recorded runs finishes in under 5 seconds on CI (plan Performance Goals, generous bound)
- [X] T029 [P] [US2] Failing contract tests in `tests/contract/test_cli_audit.py`: JSON shape of contracts/cli.md (every field, `summary` counts named exactly as there); exit 0 whatever the content; exit 1 for an unknown model or version; `--stale-after` changes `stale` but nothing else

### Implementation for User Story 2

- [X] T030 [US2] In `src/model_dependabot/store.py`: add `Store.open_read_only(path)` (SQLite `mode=ro` URI, no schema creation, migration, back-fill or timestamp writes; missing 003 columns and tables read as defaults; a pre-002 schema raises an invalid-input error), and read helpers `check_runs_for(model_id, since)` and `registered_at(model_id, version)`; move `SCOPE_ALL` from `src/model_dependabot/reports.py` into `store.py` and import it in `reports.py` to avoid a circular import (research A12, Read-only open)
- [X] T031 [US2] Implement the audit report in `src/model_dependabot/assurance/audit.py` (uses `assurance/trust.py` for claims, opens the store read-only); make T027 and T028 pass
- [X] T032 [US2] Add `inventory audit` to `src/model_dependabot/cli.py` and its text output to `src/model_dependabot/reports.py` (summary first, then findings, assurance, coverage; the statement always printed); make T029 pass

**Checkpoint**: US2 shippable alone as one pull request.

---

## Phase 5: User Story 3 - Discover candidate dependencies from a project, offline (Priority: P2)

**Goal**: `discover PATH [--manifest FILE] [--model-id ID] [-o FILE [--force]]` proposes candidates with origin, status, time and gaps; contained, bounded, offline, read-only (FR-015 to FR-020, FR-022, FR-023).

**Independent Test**: quickstart §5 on `tests/fixtures/projects/detector`.

### Fixtures

- [ ] T033 [US3] Build `tests/fixtures/projects/detector/` (committed files) and a pytest fixture in `tests/conftest.py` that creates the parts git cannot hold (a symbolic link `link-out` to a directory outside the project, an oversized text file over 1 MiB, a directory tree deeper than 24 levels) in `tmp_path` at test time: `requirements.lock.txt` (hash-locked), `requirements-dev.txt` (unpinned, with `-r ../outside.txt`), `pyproject.toml` with `[project].dependencies`, `runs/best.safetensors` (a pickle), `weights/good.safetensors` (well formed), `README.md` with front matter (`base_model`, `datasets`, `license`, `license_link`, one unknown key), `uv.lock`, a `.venv/` directory and `model.toml` naming a different base model

### Tests for User Story 3 (write first, must fail)

- [ ] T034 [P] [US3] Failing tests in `tests/unit/test_discover_walk.py` for `src/model_dependabot/discover/walk.py`: limits 50,000 entries, depth 24, 2,000 weight files, 1 MiB text, 256 KiB card front matter; directories `.git`, `.hg`, `.svn`, `.venv`, `venv`, `node_modules`, `__pycache__`, `.tox`, `.mypy_cache`, `.ruff_cache`, `site-packages` not entered and each listed once under `skipped`; symbolic links out of the root, absolute paths and `..` paths never opened and reported `outside the project` (FR-020, SC-006)
- [ ] T035 [P] [US3] Failing tests in `tests/unit/test_discover_python.py` for `src/model_dependabot/discover/python_deps.py`: files matching `*requirements*.txt`, `*constraints*.txt`, `*.lock.txt`; fully hash-locked → candidates `declared-but-unverified` with version and hashes; otherwise gaps `not locked` or `no exact version`; `pyproject.toml` dependencies and optional dependencies with `not locked`; URL and VCS requirements with `not a registry package`; `uv.lock`, `poetry.lock`, `Pipfile.lock`, `pylock.toml` skipped with `lock format not read in this version`; `-r`/`-c` followed only inside the project (research A7)
- [ ] T036 [P] [US3] Failing tests in `tests/unit/test_discover_card.py` for `src/model_dependabot/discover/model_card.py`: only `base_model`, `base_model_relation`, `datasets`, `license`, `license_name`, `license_link` read; other keys listed unrecognised; an anchor or alias refused and the card reported unreadable; malformed front matter reported unreadable while discovery continues; a list of base models gives one candidate each with gap `several base models; multi-parent lineage is #9`; a card nested deeply enough to raise `RecursionError` is reported unreadable; every base model has gap `no revision`; `license_link` kept as text and never fetched; nothing inferred from the card's body text (FR-018, research A6)
- [ ] T037 [P] [US3] Failing tests in `tests/unit/test_discover_weights.py` for `src/model_dependabot/discover/weights.py`: SHA-256 and class from the bytes via `classify`; a pickle named `.safetensors` is `pickle`, `can_run_code` true, status `verified`, with a note naming the mismatch; the same bytes under two names marked `conflicting`
- [ ] T038 [P] [US3] Failing tests in `tests/unit/test_discover_compare.py` for `src/model_dependabot/discover/compare.py`: each candidate gets `matches`, `missing_from_manifest` or `conflicts` (with the manifest's value); manifest entries not seen go to `declared_not_seen`; two dependency files with different versions of one package are both `conflicting` (FR-019)
- [ ] T039 [P] [US3] Failing tests in `tests/unit/test_discover_propose.py` for `src/model_dependabot/discover/propose.py`: active entries only for `[model] id`, local `[[weights]] path` and `[environment] lock` when exactly one hash-locked file exists (several → all commented `several lock files; choose one`); every other candidate a comment block with status, origin and gaps; the header comment carries the FR-023 statement; the written file loads with `load_manifest`; an existing path refused without `--force`; written to a temporary name beside the target and renamed (research A10, FR-022)
- [ ] T040 [P] [US3] Failing integration tests in `tests/integration/test_discover.py` per quickstart §5: candidates, skips and statement as listed there; zero socket use; every pre-existing project file's SHA-256 and modification time unchanged; no database file created; registering the proposed manifest records only the weight files and the lock (SC-004, SC-005)
- [ ] T041 [P] [US3] Failing contract tests in `tests/contract/test_cli_discover.py`: JSON shape of contracts/cli.md (`project`, `observed_at`, `upstream`, `statement`, `candidates`, `declared_not_seen`, `skipped`, `limits`, `output`); every candidate has `origin`, `status` and `observed_at`; exit 1 for a non-directory `PATH`, an invalid `--manifest` or an existing `-o` without `--force`

### Implementation for User Story 3

- [ ] T042 [US3] Implement `src/model_dependabot/discover/walk.py`; make T034 pass
- [ ] T043 [P] [US3] Implement `src/model_dependabot/discover/python_deps.py` reusing `src/model_dependabot/lockfile.py`; make T035 pass
- [ ] T044 [P] [US3] Implement `src/model_dependabot/discover/model_card.py` with a PyYAML safe loader subclass that raises on alias and anchor events, normalising licences with `src/model_dependabot/upstream/licences.py`; make T036 pass
- [ ] T045 [P] [US3] Implement `src/model_dependabot/discover/weights.py` reusing `hash_file` and `classify` from `src/model_dependabot/inventory/build.py`; make T037 pass
- [ ] T046 [US3] Implement `src/model_dependabot/discover/compare.py` using `load_manifest(path, weights_present=False)`; make T038 pass
- [ ] T047 [US3] Implement `src/model_dependabot/discover/propose.py` (small TOML writer with escaping, atomic write); make T039 pass
- [ ] T048 [US3] Add `discover` to `src/model_dependabot/cli.py` (no store opened; `--db` ignored) and its text output to `src/model_dependabot/reports.py`, assembling the discovery result of data-model.md; make T040 and T041 pass

**Checkpoint**: US3 shippable alone; offline discovery works end to end.

---

## Phase 6: User Story 4 - Confirm hub references during discovery (Priority: P3)

**Goal**: `discover --upstream` reads hub model and dataset info for identities named in the card (FR-021, research A11).

**Independent Test**: quickstart §6 with recorded hub answers.

### Tests for User Story 4 (write first, must fail)

- [ ] T049 [P] [US4] Failing tests in `tests/integration/test_discover_upstream.py` using the recorded answers in `tests/fixtures/hf/` and `tests/fixtures/hf_upstream/`: without `--upstream` zero requests; with it, only hub identities named in the project are requested; a known base model gets `proposed_revision` with `label: "head at observation time, not established as the training revision"` and `observed_at`, and its declared licence with the SPDX form; a refused or failed lookup makes the candidate `unavailable` with the reason and exit stays 0; DOIs are not looked up

### Implementation for User Story 4

- [ ] T050 [US4] Implement `src/model_dependabot/discover/upstream.py` with `hf.read_model` and `hf.read_dataset` through an injected `Fetcher` (the CLI passes a `UrlFetcher` without an ETag cache); wire `--upstream` in `src/model_dependabot/cli.py`; make T049 pass

**Checkpoint**: all four stories complete.

---

## Phase 7: Polish & Cross-Cutting Concerns

- [ ] T051 [P] Update `README.md`: the commands table (`inventory audit`, `discover`), the `format-check` source, exit codes, "What it never does" (discovery reads nothing outside the project and writes only `-o`), the trust rule for imported claims and the legacy-version note; check every statement against the code (constitution, Development Workflow)
- [ ] T052 [P] Add a per-kind tally script `research/heldout/discover_eval.py` and its README section reporting found, missed and wrongly proposed candidates per kind, never a pooled figure (FR-026, SC-008); the report itself is produced separately, not in the test suite
- [ ] T053 [P] Add a hypothesis property test in `tests/property/test_claim_trust_machine.py`: over random sequences of imports, policy changes, claim-check outcomes and new versions, an entry whose claim needs confirmation and is not `confirmed` never suppresses a `format_policy` alert (SC-001)
- [ ] T054 Run the quickstart walkthrough end to end and time the audit reading of §4 against SC-007 (under two minutes to name unverified entries and failed sources); record the result in `specs/003-inventory-assurance/validation.md`
- [ ] T055 Run `uv run pytest -q`, `uv run ruff check` and `uv run ruff format --check` (configured in `pyproject.toml`); all green offline

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: none.
- **Foundational (Phase 2)**: after Setup; blocks every story.
- **US1 (Phase 3)**: after Phase 2. T010 (recording) needs a network that reaches the hub and blocks T012, the hub cases of T014, T015, T016, T021 and T023; the local cases of T014 and everything else in US1 can proceed meanwhile.
- **US2 (Phase 4)**: after Phase 2; uses `assurance/trust.py` from T022, so after T022. Independent of the rest of US1.
- **US3 (Phase 5)**: after Phase 2 (needs PyYAML from T001); independent of US1 and US2.
- **US4 (Phase 6)**: after US3.
- **Polish (Phase 7)**: after the stories it documents.

### Within Each User Story

Tests first and failing, then implementation in the listed order; the checkpoint test run is green before
the story's pull request is opened.

### Parallel Opportunities

- T002 and T003; T006 with T004.
- US1 tests T011 to T019 are in separate files and can be written together; T022 alongside T020 and T021.
- US2 tests T027 to T029 together.
- US3 tests T034 to T041 together; implementations T043, T044 and T045 together after T042.
- US2 and US3 can run in parallel once Phase 2 and T022 are done.

## Parallel Example: User Story 1

```text
Write together: T011 (fetcher), T012 (hub header), T013 (trust), T014 (format-check),
                T017 (import bytes), T018 (CLI contract), T019 (export property)
Then implement: T020 → T021 → T023 → T024, with T022 and T025 alongside
```

## Implementation Strategy

### MVP First (User Story 1 only)

1. Phases 1 and 2.
2. Record the hub answers (T010) where the hub is reachable.
3. Phase 3. Stop and validate with quickstart §2 and §3. This closes SEC-01 and unblocks #8.

### Incremental Delivery

1. US1 → pull request 1.
2. US2 → pull request 2 (the audit can then report `format-check` coverage).
3. US3, then US4 → pull requests 3 and 4.

## Notes

- Every new string uses British spelling and no serial comma.
- No task sends anything outward (no release, no post) without the owner's explicit yes.
- Commit after each task or logical group; never leave the suite red between commits on the shared branch.

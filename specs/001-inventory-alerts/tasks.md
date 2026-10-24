---

description: "Task list for feature 001: model inventory with library and weight-file alerts"
---

# Tasks: Model Inventory with Library and Weight-File Alerts

**Input**: Design documents from `/specs/001-inventory-alerts/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/, quickstart.md

**Tests**: Required. Constitution principle V: tests are written before the code they test and must fail
first; feed tests use recorded responses only, and the default test run makes no network calls.

**Organization**: Tasks are grouped by user story so each story can be built and tested on its own.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (US1 to US5)

## Path Conventions

Single project: `src/model_dependabot/` and `tests/` at the repository root (plan.md, Project Structure).

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Project initialisation and basic structure

- [X] T001 Create `pyproject.toml`: project `model-dependabot`, `requires-python = ">=3.12"`, dependencies `packaging==26.3`, `jsonschema==4.26.0`, `picklescan==1.0.5`; dev group `pytest`, `ruff`; console script `model-dependabot = "model_dependabot.cli:main"`; pytest config registering marker `live` and default `addopts = "-m 'not live'"`; then `uv lock`
- [X] T002 Create the package and test skeleton from plan.md: `src/model_dependabot/` with `__init__.py`, `inventory/`, `sources/`, `matching/` (each with `__init__.py`); `tests/unit/`, `tests/contract/`, `tests/integration/`, `tests/fixtures/`
- [X] T003 [P] Add `tests/conftest.py` with an autouse fixture that blocks all socket connections unless the test is marked `live` (constitution V: the default run must fail loudly on any network call)
- [X] T004 [P] Add ruff settings to `pyproject.toml` and a `.gitignore` covering `*.db`, the evidence store directory `evidence/`, `.venv/` and caches
- [X] T005 [P] Vendor the CycloneDX schemas into `src/model_dependabot/inventory/schema/`: `bom-1.7.schema.json`, `spdx.schema.json`, `jsf-0.82.schema.json` from the CycloneDX/specification repository at a recorded commit, plus `SHA256SUMS` and a `README.md` naming the source URL, commit and licence

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Fetching, storage and the CLI frame that every story uses

**CRITICAL**: No user story work can begin until this phase is complete

- [X] T006 [P] Write failing tests in `tests/unit/test_fetcher.py`: a `RecordedFetcher` serves responses from `tests/fixtures/` by method, URL and body; the real `UrlFetcher` sends a generic User-Agent (no personal data, no email address), applies a timeout, retries with back-off on 429/5xx and caches by URL and body; every response returns its body, status, URL and retrieval time; a per-source request ceiling throttles the Hugging Face source to its published limit (research R8), `Retry-After` is honoured and repeated `429`s mark that source `failed` for the run (FR-020)
- [X] T007 Implement `src/model_dependabot/sources/fetcher.py` (`Fetcher` protocol, `UrlFetcher` on `urllib.request`, `RecordedFetcher`) until T006 passes
- [X] T008 [P] Write failing tests in `tests/unit/test_store.py` for the SQLite schema of data-model.md: tables for models, model versions, inventory entries, advisories, check runs, evidence, alerts and watch events; "At most one `open` alert per `model_id` and `cause_key`" enforced by the database; evidence bodies stored as files named by SHA-256 and referenced by `body_sha256`; a model version's inventory cannot be updated once recorded (FR-005)
- [X] T009 Implement `src/model_dependabot/store.py` until T008 passes
- [X] T010 [P] Write failing tests in `tests/contract/test_cli_frame.py`: every command accepts `--db` and `--json`; exit codes 0 success, 1 invalid input, 2 a source failed, 3 unexpected error (contracts/cli.md)
- [X] T011 Implement the command frame in `src/model_dependabot/cli.py` (argument parsing, text and JSON output, exit codes) until T010 passes

**Checkpoint**: fetching, storage and the CLI frame are ready; stories can start

---

## Phase 3: User Story 1 - Register a model and see its inventory (Priority: P1) MVP

**Goal**: An owner registers a model from a manifest and sees a pinned inventory with gaps listed; the inventory exports to valid CycloneDX 1.7 and imports back unchanged.

**Independent Test**: Register `tests/fixtures/manifests/example.toml` (small local weight files, a hash-locked lock file, a pinned base-model revision, a dataset DOI with SHA-256) and confirm every item and gap appears; export, validate against the schema and re-import with 0 differences (SC-001, SC-005).

### Tests for User Story 1

- [X] T012 [P] [US1] Write failing tests in `tests/unit/test_lockfile.py`: `name==version` with one or more `--hash=sha256:` and backslash continuations is pinned; a missing `==` or missing hash is a gap with reason "no exact version" or "no hash"; names normalised with `packaging.utils.canonicalize_name` (research R10); use a trimmed copy of a real uv-generated lock as the fixture in `tests/fixtures/locks/`
- [X] T013 [P] [US1] Write failing tests in `tests/contract/test_manifest.py` for contracts/manifest.md: `model.id` required; unknown keys are an error (exit 1); a hub weight file without `revision` is a gap "no revision"; paths resolve relative to the manifest; registration never fails because of a gap
- [X] T014 [P] [US1] Write failing tests in `tests/unit/test_build.py`: weight files hashed with SHA-256, size recorded, format classified as pickle-based (`.pt`, `.pth`, `.bin`, `.ckpt`, `.pkl`, `.joblib`, PyTorch zip) or code-free (`.safetensors`, `.onnx`, `.gguf`) with `can_run_code` set (FR-002); every entry has `kind` in `weight_file`, `package`, `base_model`, `dataset`; `pinned` false requires a `gap_reason`
- [X] T015 [P] [US1] Write failing tests in `tests/unit/test_hf_tree.py` with recorded Hugging Face tree and model-info responses in `tests/fixtures/hf/`: a hub file's SHA-256 comes from the tree API's `lfs.oid` and the revision from `X-Repo-Commit`; a 401 response is recorded as a gap, not an error
- [X] T016 [P] [US1] Write failing tests in `tests/contract/test_inventory_profile.py` for contracts/inventory-profile.md: each entry kind lands at its documented CycloneDX location and identifier; exports validate against the vendored `bom-1.7.schema.json`; export then import yields identical entries and identifiers; custom values only as `model-dependabot:` properties, and exactly the documented set (`format`, `can-run-code`, `size`, `hub-repo`, `hub-revision`, `hub-file`, `gap`), with a hub weight file's repository, revision and file name surviving the round trip; CycloneDX 1.5 and 1.6 inputs import, with unreadable entries becoming gaps
- [X] T017 [US1] Write a failing integration test in `tests/integration/test_register.py`: `register`, `inventory show`, `inventory export`, `import` on `tests/fixtures/manifests/example.toml`; a second `register` with `--model-id` creates version 2

### Implementation for User Story 1

- [X] T018 [P] [US1] Implement `src/model_dependabot/lockfile.py` until T012 passes
- [X] T019 [P] [US1] Implement `src/model_dependabot/manifest.py` with `tomllib` until T013 passes
- [X] T020 [P] [US1] Implement the tree and revision part of `src/model_dependabot/sources/hf.py` until T015 passes
- [X] T021 [US1] Implement `src/model_dependabot/inventory/build.py` (manifest to inventory entries, hashing, gaps) until T014 passes
- [X] T022 [US1] Implement `src/model_dependabot/inventory/cyclonedx.py` (entries to and from CycloneDX 1.7 JSON, validation with `jsonschema` against the vendored schemas) until T016 passes
- [X] T023 [US1] Add `register`, `import` and `inventory show|export` to `src/model_dependabot/cli.py` until T017 passes

**Checkpoint**: User Story 1 works on its own

---

## Phase 4: User Story 2 - Alerts for vulnerable packages (Priority: P1)

**Goal**: Pinned packages are checked against OSV.dev; an alert opens only when OSV's match and the local range evaluation agree, with severity, fixed version and evidence; withdrawn advisories close their alerts.

**Independent Test**: With recorded OSV responses, a model pinning an affected version gets exactly one alert per advisory with evidence; an unaffected version gets none (SC-002, SC-003).

### Tests for User Story 2

- [X] T024 [US2] Write `tools/record_fixtures.py` (marked live, run by hand) that records OSV.dev `POST /v1/querybatch` and `GET /v1/vulns/{id}` responses for a chosen package list into `tests/fixtures/osv/`, with the retrieval date in a sidecar file; record a set including an affected version (for example `pillow==12.3.0`), an unaffected one (`pillow==13.0.0`) and one withdrawn advisory
- [X] T025 [P] [US2] Write failing tests in `tests/unit/test_versions.py`: evaluation of OSV `affected[].ranges` (`introduced`, `fixed`, `last_affected` events, `ECOSYSTEM` type) and `affected[].versions` under PEP 440 with `packaging` (research R2), including pre-releases and multiple ranges
- [X] T026 [P] [US2] Write failing tests in `tests/unit/test_severity.py`: `database_specific.severity` first, else a band from a CVSS v3 or v4 score, else `UNKNOWN`; origin recorded (research R3)
- [X] T027 [P] [US2] Write failing tests in `tests/unit/test_osv.py` against the recorded fixtures: batch query, detail fetch, aliases, fixed versions, the `withdrawn` field; only package entries with `pinned` true are queried (FR-003)
- [X] T028 [P] [US2] Write failing tests in `tests/unit/test_lifecycle_packages.py`: alert only when OSV and the local evaluation agree, otherwise a watch event of kind `advisory_unmatched` (FR-007); alert fields per FR-008; withdrawal closes the alert as `withdrawn` with the withdrawal as evidence (FR-009); never two open alerts per model, advisory and package, the alert being carried forward rather than raised again (FR-010, the `cause_key` rule tested in T008); a source that failed in a run changes no alert (FR-016); the same advisory in two models gives each model its own alert; two recorded responses for one advisory with different severity and fixed version: the alert shows the new values and keeps both evidence records (spec edge case)
- [X] T029 [US2] Write a failing integration test in `tests/integration/test_check_packages.py`: `register` then `check` then `alerts --json` with the recorded fixtures; exit code 2 and no state change when OSV is made to fail (SC-007)
- [X] T029a [US2] Write a failing integration test in `tests/integration/test_new_advisory.py`: a first `check` against a recorded fixture set with no advisory for the pinned version opens nothing; a second `check` against a set where a newly published advisory affects it opens the alert, so with the daily schedule an advisory appears within one scheduled interval (SC-006)

### Implementation for User Story 2

- [X] T030 [P] [US2] Implement `src/model_dependabot/matching/versions.py` until T025 passes
- [X] T031 [P] [US2] Implement `src/model_dependabot/matching/severity.py` until T026 passes
- [X] T032 [P] [US2] Implement `src/model_dependabot/sources/osv.py` until T027 passes
- [X] T033 [US2] Implement package alerts, watch events, evidence and check runs in `src/model_dependabot/lifecycle.py` until T028 passes
- [X] T034 [US2] Add `check (ID | --all) [--source ...]`, `alerts` and `alert show` to `src/model_dependabot/cli.py` until T029 and T029a pass

**Checkpoint**: User Stories 1 and 2 work on their own

---

## Phase 5: User Story 3 - Alerts for unsafe weight files (Priority: P2)

**Goal**: Pickle-based files get a watch event; a static scan finding `dangerous` content, or an explicit hub "unsafe" verdict for the matching hash, raises an alert.

**Independent Test**: A model with a crafted dangerous pickle, a benign pickle and an `.onnx` file gives one alert, two `pickle_format` watch events and nothing for the ONNX file; recorded hub responses give an alert only for "unsafe" with a matching hash.

### Tests for User Story 3

- [X] T035 [P] [US3] Create crafted pickle fixtures in `tests/fixtures/pickles/`, built as raw opcode bytes by a fixture script and never loaded: one importing `os.system` (dangerous), one importing only `collections.OrderedDict` and `torch._utils._rebuild_tensor_v2` (innocuous), one importing a suspicious global; plus a PyTorch-zip-wrapped copy of the dangerous one
- [X] T036 [P] [US3] Write failing tests in `tests/unit/test_pickle_scan.py`: the adapter calls `picklescan.scanner.scan_bytes` with the file extension, never unpickles and maps `dangerous`, `suspicious` and `innocuous` globals to findings with the global names as evidence
- [X] T037 [P] [US3] Write failing tests in `tests/unit/test_hf_scan.py` with recorded `GET /api/models/{repo}?securityStatus=true` responses in `tests/fixtures/hf/`: an explicit unsafe verdict for a file whose SHA-256 matches the inventory raises a `hub_scan` alert with severity `HIGH` and `severity_origin: "policy"`, the hub's verdict and scanners, the file's location, the source and the retrieval time (FR-012, FR-013); missing, pending, unrecognised or hash-mismatched results are watch events (`hub_scan_unknown`, `hash_mismatch`) (research R5)
- [X] T038 [P] [US3] Write failing tests in `tests/unit/test_lifecycle_weights.py`: every pickle-based file gets a `pickle_format` watch event with format and suggestion (FR-011); a `dangerous` scan raises a `weight_file_scan` alert with severity `HIGH` and `severity_origin: "policy"`, the file's hash and location, the scanner, the dangerous globals, the source and the retrieval time (FR-013); `suspicious` adds a `scan_suspicious` watch event; code-free formats get nothing; the same dangerous pickle registered in two models gives each model its own alert (spec edge case)
- [X] T039 [US3] Write a failing integration test in `tests/integration/test_check_weights.py` covering the Independent Test above, plus a registered `.joblib` file that is classified as code-capable and gets a `pickle_format` watch event (and the `scan_incomplete` event of T039b)
- [X] T039a [P] [US3] Write failing tests in `tests/unit/test_format_policy.py`: under `default` a pickle-only file gives only the `pickle_format` watch event; under `strict` it raises a `format_policy` alert naming the policy, with severity `MODERATE` and `severity_origin: "policy"`, and evidence holding the file's SHA-256, format, the policy value, who set it and when (constitution I, 1.0.2); a code-free sibling file in the same version suppresses it (FR-021); `policy --by` CLI round trip records who and when
- [X] T039b [P] [US3] Write failing tests in `tests/unit/test_pickle_scan_incomplete.py` with a crafted joblib-style fixture (pickle opcodes followed by raw array bytes): the scanner's stop becomes a `scan_incomplete` watch event with scanner and byte position, never `innocuous` (FR-022)

### Implementation for User Story 3

- [X] T040 [P] [US3] Implement `src/model_dependabot/sources/pickle_scan.py` until T036 passes
- [X] T041 [P] [US3] Implement the security-status part of `src/model_dependabot/sources/hf.py` until T037 passes
- [X] T042 [US3] Add weight-file findings to `src/model_dependabot/lifecycle.py` and wire the `picklescan` and `hf-scan` sources into `check` until T038 and T039 pass
- [X] T042a [US3] Add `format_policy` (with who set it and when) to the model store, the `policy` command to `src/model_dependabot/cli.py`, stop-position reporting to `src/model_dependabot/sources/pickle_scan.py` and the `format_policy` alert and the `scan_incomplete` watch event to `src/model_dependabot/lifecycle.py` until T039a and T039b pass

**Checkpoint**: User Stories 1 to 3 work on their own

---

## Phase 6: User Story 4 - Alerts close when a new model version fixes the cause (Priority: P2)

**Goal**: Registering a newer version closes alerts whose cause it removed, carries forward those it still has and lets people dismiss with a listed reason; a source that clears the cause closes its alert as `cleared`.

**Independent Test**: Version 2 with the package upgraded past the fixed version closes the alert as `fixed` by version 2 (SC-004); a dismissal records reason, person and time.

### Tests for User Story 4

- [X] T043 [P] [US4] Write failing tests in `tests/unit/test_lifecycle_versions.py` for the data-model.md state transitions: a new version without the cause closes the alert as `fixed` with `closed_by_version`; a new version with the cause moves `current_version` forward; a cause found again after closing opens a new alert and keeps the old one in history; this re-evaluation happens at `register` by comparing the two inventories and makes no source request (the recorded fetcher sees no call), so a failed source cannot affect it (FR-014, SC-004)
- [X] T043a [P] [US4] Write failing tests in `tests/unit/test_lifecycle_cleared.py` for the `cleared` transitions (FR-023): a recorded advisory response whose affected ranges are narrowed so the pinned version is no longer affected, with OSV's match and the local evaluation both agreeing, closes the alert as `cleared` with the new response as evidence; if only one of the two agrees, the alert stays open and an `advisory_unmatched` watch event is recorded; a hub verdict for the matching hash that changes from unsafe to an explicit safe verdict closes the `hub_scan` alert as `cleared` with the new verdict as evidence; a missing, pending or unrecognised later verdict changes nothing; a source that failed in the run clears nothing (FR-016); a withdrawn advisory still closes as `withdrawn`, not `cleared`
- [X] T044 [P] [US4] Write failing tests in `tests/unit/test_dismiss.py`: dismissal needs a reason from "`not_used_at_runtime`, `risk_accepted`, `false_positive`, `fix_not_available`" plus an optional note, and records who and when (FR-015); any other reason is invalid input (exit 1)
- [X] T045 [US4] Write a failing integration test in `tests/integration/test_autoclose.py` following quickstart.md section 5

### Implementation for User Story 4

- [X] T046 [US4] Implement version re-evaluation on `register` in `src/model_dependabot/lifecycle.py` until T043 passes
- [X] T046a [US4] Implement the `cleared` state and its transitions in `src/model_dependabot/lifecycle.py` (and the state in `src/model_dependabot/store.py`) until T043a passes
- [X] T047 [US4] Add `alert dismiss` to `src/model_dependabot/cli.py` until T044 and T045 pass

**Checkpoint**: User Stories 1 to 4 work on their own

---

## Phase 7: User Story 5 - See a model's alerts, watch events and history (Priority: P3)

**Goal**: Per model: open alerts by severity, watch events separately, closed history with outcomes; evidence one step away.

**Independent Test**: For a model with open, closed and watch items, each appears in the right list, and `alert show` reaches the evidence (SC-003).

### Tests for User Story 5

- [X] T048 [P] [US5] Write failing tests in `tests/unit/test_reports.py`: ordering by severity (`CRITICAL`, `HIGH`, `MODERATE`, `LOW`, `UNKNOWN`), watch events listed separately, history shows `fixed`, `dismissed`, `withdrawn` or `cleared` with time and evidence (FR-018, FR-019)
- [X] T049 [P] [US5] Write failing contract tests in `tests/contract/test_cli_json.py` checking `alerts --json` and `history --json` against the shapes in contracts/cli.md

### Implementation for User Story 5

- [X] T050 [US5] Implement `src/model_dependabot/reports.py` until T048 passes
- [X] T051 [US5] Wire `alerts` text and JSON output and `history` in `src/model_dependabot/cli.py` until T049 passes

**Checkpoint**: all user stories work on their own

---

## Phase 8: Polish & Cross-Cutting Concerns

- [X] T052 [P] Add `live`-marked smoke tests in `tests/live/test_live_sources.py` that query OSV.dev and the Hugging Face API once each, to catch format changes; excluded from the default run
- [X] T053 [P] Write `README.md` usage (install, manifest, commands, scheduling with cron, a systemd timer and Windows Task Scheduler) and update `research/` links; British spelling, no serial comma, no institution names
- [X] T054a [P] Write a test in `tests/integration/test_never_writes.py` proving the service never writes (FR-017, constitution III): over `register`, `check`, `policy`, `alert dismiss` and `inventory export` on the worked example, a spying fetcher records every request and none is `PUT`, `PATCH` or `DELETE`; the only `POST` is to OSV's read-only `/v1/querybatch`; the SHA-256 and modification time of every registered local weight file, the manifest and the lock file are unchanged after `register` and after `check`
- [X] T054 Run the full suite with the network blocked and ruff with no findings; record the commands, counts and exit codes in `specs/001-inventory-alerts/validation.md`
- [X] T055 Walk through quickstart.md sections 1 to 7 on a real model inventory (owner-provided), record each section's result in `specs/001-inventory-alerts/validation.md`, including the wall-clock time of `register` on the worked example (target under 5 minutes, SC-001) and of `check` on a model with about 100 locked packages (target under 60 seconds, plan.md Performance Goals), and fix anything it misses
- [X] T056 Neutrality and privacy check across `src/`, `tests/`, docs and commit messages: no institution names, no personal data in fixtures, generic User-Agent only

---

## Dependencies & Execution Order

### Phase Dependencies

- Setup (Phase 1) has no dependencies.
- Foundational (Phase 2) depends on Setup and blocks every story.
- US1 (Phase 3) depends on Phase 2. US2 to US5 need registered inventories, so they depend on US1.
- US2 (Phase 4) and US3 (Phase 5) are independent of each other once US1 is done.
- US4 (Phase 6) depends on US2 (it closes package alerts); its weight-file cases, including the hub cases of T043a, need US3.
- T054a (Phase 8) needs every command it exercises, so it follows US1 to US5.
- US5 (Phase 7) depends on the alert lifecycle from US2.
- Polish (Phase 8) comes last.

### Within Each User Story

- Tests are written and seen failing before the code they cover (constitution V).
- Fixtures before the adapter tests that read them (T024 before T027; T035 before T036).
- Adapters and matching before `lifecycle.py`; `lifecycle.py` before the CLI commands.

### Parallel Opportunities

- Setup: T003, T004 and T005 together.
- Foundational: the three test files (T006, T008, T010) together, then their implementations.
- US1: tests T012 to T016 together; implementations T018 to T020 together.
- US2 and US3 can run side by side after US1.

## Parallel Example: User Story 1

```text
Task: "T012 failing tests for lockfile parsing in tests/unit/test_lockfile.py"
Task: "T013 failing tests for the manifest in tests/contract/test_manifest.py"
Task: "T014 failing tests for inventory building in tests/unit/test_build.py"
Task: "T015 failing tests for Hugging Face tree hashes in tests/unit/test_hf_tree.py"
Task: "T016 failing tests for the CycloneDX profile in tests/contract/test_inventory_profile.py"
```

## Implementation Strategy

### MVP First (User Story 1, then User Story 2)

1. Phases 1 and 2.
2. Phase 3 (US1): the inventory alone is useful; stop and validate with quickstart.md section 2.
3. Phase 4 (US2): the first alerts; this pair is the "Dependabot for models" core.

### Incremental Delivery

US3 (weight files), then US4 (auto-close and dismissal), then US5 (views), each tested on its own before
the next. The Polish phase ends with the quickstart walkthrough on a real model.

---

description: "Task list for feature 002: upstream watch for base models and training datasets"
---

# Tasks: Upstream Watch for Base Models and Training Datasets

**Input**: Design documents from `/specs/002-upstream-watch/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/, quickstart.md; and feature 001's
tasks ([001 tasks](../001-inventory-alerts/tasks.md)), cited below as `001:T###`

**Tests**: Required. Constitution principle V: tests are written before the code they test and must fail
first; every source adapter is tested against recorded responses only, and the default test run makes no
network calls (001:T003 blocks sockets).

**Organization**: Tasks are grouped by user story so each story can be built and tested on its own.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (US1 to US4 of spec 002)

## Path Conventions

Feature 001's single project: `src/model_dependabot/` and `tests/` at the repository root (plan.md, Project
Structure). This feature adds files to that layout and changes some of 001's; it does not redo 001's tasks.

## Prerequisite from feature 001

Feature 001's Phases 1 and 2 (001:T001 to 001:T011: package, socket block, fetcher, store, CLI frame) MUST be
complete before this feature's Phase 1. Later dependencies on 001 are named on each task.

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Vendored licence data and new folders

- [X] T001 Vendor the SPDX licence list: download `json/licenses.json` from the `spdx/license-list-data` repository at tag `v3.29.0` into `src/model_dependabot/licences/spdx-licenses-3.29.0.json`; add `src/model_dependabot/licences/SHA256SUMS` and `src/model_dependabot/licences/README.md` naming the source URL, the tag, the release date (2026-09-16), the licence count (740) and the data licence as that repository states it (research U8)
- [X] T002 [P] Create `src/model_dependabot/upstream/__init__.py` and `src/model_dependabot/licences/aliases.toml` holding only a header comment that defines the entry format (an alias string mapped to an SPDX identifier, with a `source` note naming the repository that uses the spelling); entries are added in T039
- [X] T003 [P] Create the fixture folders `tests/fixtures/crossref/`, `tests/fixtures/datacite/`, `tests/fixtures/zenodo/`, `tests/fixtures/figshare/`, `tests/fixtures/doi_ra/`, `tests/fixtures/hf_upstream/` and `tests/fixtures/hf_takedowns/`; add `tests/fixtures/README.md` stating that fixtures are recorded by `tools/record_fixtures.py`, stored redacted (research U10) and dated in a sidecar file

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Redaction, pacing, observations, storage, inventory additions, DOI routing, the `--scheduled`
flag and recorded fixtures that every story uses

**CRITICAL**: No user story work can begin until this phase is complete

- [X] T004 [P] Write failing tests in `tests/unit/test_redact.py` for research U10: the stored body removes exactly these fields: takedown log `index.csv` "the `requesting_entity` column"; Zenodo tombstone "`removed_by`, `note` and `citation_text`"; Crossref and DataCite records "`author`, `creators`, `contributors` and `editor`"; Hugging Face model and dataset info: nothing. The evidence record keeps `original_sha256`, `body_sha256` and `redacted_fields`; for a source with nothing to remove the two hashes are equal and `redacted_fields` is empty
- [X] T005 Implement `src/model_dependabot/redact.py` (one rule set per source name) until T004 passes
- [X] T006 [P] Write failing tests in `tests/unit/test_fetcher_upstream.py` extending 001:T006: a 3xx response is not followed silently; the response records `redirected_from` and the target as `redirected_to`; requests to one source run one at a time with pacing "Crossref one a second, Figshare one a second, Zenodo 60 a minute, Hugging Face 500 API requests per five minutes" (research U13), checked with a fake clock; ETag caching sends `If-None-Match` and serves a 304 from the cache; the redaction rule for the source (T005) is applied before the body reaches the evidence store; every request to a new source (`doiRA`, Crossref, DataCite, Zenodo, Figshare, the hub and the takedown log) uses only `GET` or `HEAD` (FR-017) and carries no `Authorization` header, token, cookie or account parameter (FR-002)
- [X] T007 Implement the additions in `src/model_dependabot/sources/fetcher.py` until T006 passes; 001:T006 must still pass
- [X] T008 [P] Write failing tests in `tests/unit/test_store_upstream.py` for data-model.md: tables for upstream observations (every field listed under "Upstream observation"), DOI routing (`doi` "Normalised to lower case", `agency`, `repository` one of `zenodo`, `figshare` or `other`, `repository_id`, `looked_up_at`) and takedown notices (`date`, `reported_content`; the schema has **no** `requesting_entity` and no `file` column); evidence gains `original_sha256` and `redacted_fields`; check runs gain `trigger` "`scheduled` (from `check --all --scheduled`) or `on_demand`"; alerts of the new kinds use feature 001's `cleared` state (001:T046a), and no new alert state is added
- [X] T009 Implement the additions in `src/model_dependabot/store.py` until T008 passes; 001:T008 must still pass
- [X] T010 [P] Write failing tests in `tests/unit/test_observe.py`: an observation's `outcome` is one of "`reachable`, `refused` (HTTP 401, 403 or 404 from the hub), `not_found` (404 from DataCite, Crossref or Figshare), `removed` (Zenodo 410), `redirected`"; only a DataCite `not_found` is marked as able to open an alert, while a Crossref or Figshare `not_found` is marked as a watch event (data-model.md); a failed request (timeout, connection error, HTTP 5xx) writes no observation (FR-018); a new observation is compared with the previous observation of the same item from the same source; the first observation is the baseline and raises nothing by itself
- [X] T011 Implement `src/model_dependabot/upstream/observe.py` and the comparison core of `src/model_dependabot/upstream/changes.py` until T010 passes
- [X] T012 [P] Write failing contract tests in `tests/contract/test_manifest_upstream.py` for contracts/manifest.md: `paper_doi` is a list of DOIs; a `[[datasets]]` table "has either `doi` or `hub`, not both"; both is an error (exit code 1) and neither is 001's gap "no DOI"; a `hub` dataset without `revision` is a gap "no revision" and is not checked; 001's rules still hold (001:T013)
- [X] T013 [P] Write failing contract tests in `tests/contract/test_inventory_profile_upstream.py` for contracts/inventory-profile.md: recorded licences in `licenses` as `{"license": {"id": …}}`, `{"license": {"name": …}}` or `{"expression": …}`; a paper tie as `externalReferences` `{"type": "citation", "url": "https://doi.org/<doi>"}`; a hub dataset with `bom-ref: "hf-dataset:<owner>/<name>@<commit>"` and a `distribution` reference; exports validate against the vendored `bom-1.7.schema.json`; export then import keeps licences, paper ties and hub datasets; an imported inventory without `licenses` is valid
- [X] T014 Implement the additions in `src/model_dependabot/manifest.py`, `src/model_dependabot/inventory/build.py` and `src/model_dependabot/inventory/cyclonedx.py` until T012 and T013 pass (needs 001:T019, 001:T021 and 001:T022); licence recording at registration comes in T040
- [X] T015 [P] Write failing tests in `tests/unit/test_doi_ra.py` with recorded `GET https://doi.org/doiRA/{doi}` answers in `tests/fixtures/doi_ra/` (`DataCite` for `10.5281/zenodo.3242074`, `Crossref` for `10.1177/1758835919874651`): the agency is cached and not looked up again once known; a failed lookup leaves it empty and it is retried at the next check; DOIs are lower-cased (research U1)
- [X] T016 Implement `src/model_dependabot/sources/doi_ra.py` and call it from `register` until T015 passes
- [X] T017 [P] Write failing contract tests in `tests/contract/test_cli_check_upstream.py` for contracts/cli.md: `check --all --scheduled` records `trigger` `scheduled` and any other `check` records `on_demand`; `--source` accepts `hf-hub`, `hf-takedowns`, `crossref`, `datacite`, `zenodo` and `figshare` alongside 001's names; omitting `--source` runs every source; exit codes are 001's
- [X] T018 Implement `--scheduled` and the new source names in `src/model_dependabot/cli.py` until T017 passes (needs 001:T034)
- [X] T019 Extend `tools/record_fixtures.py` (live, run by hand, after T005 and T007) to record the new sources through the redaction rules into `tests/fixtures/`, each with a dated sidecar: Crossref `works/10.1177/1758835919874651` (retracted, with `retraction-watch` and `publisher` entries), an unretracted DOI, a DOI with a `correction` update and a DOI with an `expression_of_concern` update (each one found by search at recording time) and a 404; DataCite a findable DOI, a 404, a record with an `IsObsoletedBy` related identifier and a record with `IsPreviousVersionOf` or `HasVersion` pointing to a newer version (each one found by search at recording time); Zenodo record `3242074` (200), a record whose `links.latest` points to a newer version (one found by search at recording time) and one deleted record (410 tombstone); Figshare one public article, an article whose licence is `CC BY 4.0` (one found by search at recording time) and one 404; Hugging Face model info for a normal model, a gated model (`meta-llama/Llama-3.1-8B`) and a nonexistent model (401), dataset info for `yavon/muxue` (disabled), a nonexistent dataset (401) and `the_pile_books3` (307); the takedown log `index.csv` (stored without its `requesting_entity` and `file` columns); `doiRA` for both agencies. Record in `specs/002-upstream-watch/research.md` U5 the exact form of `reported_content` and in U7 how a disabled **model** answers (or that none was found)

**Checkpoint**: redaction, pacing, observations, storage, inventory additions, routing, `--scheduled` and
fixtures are ready; stories can start

---

## Phase 3: User Story 1 - Alert when a training dataset is retracted or removed (Priority: P1) MVP

**Goal**: Retraction notices (Crossref, including Retraction Watch), Zenodo tombstones, hub `disabled` flags and
DataCite 404s raise alerts with evidence; Figshare 404s, hub refusals and hub moves are watch events.

**Independent Test**: quickstart.md section 2: with recorded responses, a dataset tied to a retracted paper, a
Zenodo 410, a disabled hub dataset listed in the takedown log and a DataCite 404 each give exactly one alert
with evidence; a dataset in none of them gives none (SC-001).

### Tests for User Story 1

- [X] T020 [P] [US1] Write failing tests in `tests/unit/test_crossref.py` against `tests/fixtures/crossref/`: `updated-by` entries of type `retraction`, `withdrawal` or `removal` become retraction findings with notice DOI, `source` (`publisher` or `retraction-watch`), `record-id` and date; `expression_of_concern` and `correction` become notices; a 404 is `not_found` and yields a watch-event finding, never an alert finding (`dataset_unreachable` for a dataset DOI, `paper_not_found` for a tied paper DOI); author fields are absent from stored evidence (U10); only Crossref-agency DOIs are queried (research U2)
- [X] T021 [P] [US1] Write failing tests in `tests/unit/test_datacite.py` against `tests/fixtures/datacite/`: a 404 is `not_found`; `url` routes the DOI to `zenodo` (`zenodo.org`), `figshare` (`figshare.com` or a `*.figshare.com` portal) or `other`, with `repository_id`; only DataCite-agency DOIs are queried (research U1, U3)
- [X] T022 [P] [US1] Write failing tests in `tests/unit/test_zenodo.py` against `tests/fixtures/zenodo/`: 200 is `reachable`; 410 is `removed` with `tombstone.removal_date` and `tombstone.removal_reason.id`; `removed_by`, `note` and `citation_text` are not in the stored body (research U4)
- [X] T023 [P] [US1] Write failing tests in `tests/unit/test_figshare.py` against `tests/fixtures/figshare/`: the article id comes from the DataCite `url`; 200 is `reachable`; 404 is `not_found`; no Figshare answer produces a removal finding (research U6)
- [X] T024 [P] [US1] Write failing tests in `tests/unit/test_hf_datasets.py` against `tests/fixtures/hf_upstream/`: `disabled: true` is recorded; HTTP 401, 403 or 404 is `refused`; a 307 to another namespace is `redirected` with the target; `gated`, `sha` and `cardData.license` are read (research U5)
- [X] T025 [P] [US1] Write failing tests in `tests/unit/test_hf_takedowns.py` against `tests/fixtures/hf_takedowns/`: the `requesting_entity` and `file` columns are dropped when the CSV is read and never reach the store; a row matches a hub dataset only by the dataset path in the form recorded in research U5; rows reading `Multiple` never match; a match yields only `date` labelled `notice_date` and `reported_content`, and its evidence points to the log by its URL and the notice date; the log is fetched at most once per check run and only when a hub dataset is in scope
- [X] T026 [P] [US1] Write failing tests in `tests/unit/test_lifecycle_datasets.py` for data-model.md: `dataset_retracted` (cause key "kind + dataset DOI"), `paper_retracted` ("kind + dataset identifier + paper DOI"), `dataset_removed` ("kind + dataset identifier") for a Zenodo 410 or a hub `disabled: true`, and `dataset_not_findable` ("kind + dataset DOI") for a DataCite 404, each `HIGH` with `severity_origin: "policy"`; a takedown-log row alone never opens an alert; a hub dataset alert shows the notice date labelled "notice date, not removal date" (never the notice's file), or "no reason given"; a correction or concern adds evidence to an open retraction alert, otherwise an `upstream_notice` watch event; a retraction alert closes as `withdrawn` when a later successful Crossref response lists no retraction, withdrawal or removal; `dataset_moved` and `dataset_unreachable` are watch events; a Crossref 404 records `dataset_unreachable` for a Crossref-registered dataset DOI and `paper_not_found` for a tied paper DOI and never opens an alert (FR-006 covers DataCite DOIs only); the same dataset in two models gives each its own alert; a failed source opens, changes or closes nothing (FR-018)
- [X] T027 [US1] Write a failing integration test in `tests/integration/test_check_datasets.py` following quickstart.md section 2; include two consecutive scheduled runs where the first replays a clean response and the second a retraction or a Zenodo 410, and assert the alert opens at the second run (SC-006: within one scheduled interval, as 001:T029a does for advisories); also assert that every in-scope source is read on every scheduled run

### Implementation for User Story 1

- [X] T028 [P] [US1] Implement `src/model_dependabot/sources/crossref.py` until T020 passes
- [X] T029 [P] [US1] Implement `src/model_dependabot/sources/datacite.py` (findability and routing) until T021 passes
- [X] T030 [P] [US1] Implement `src/model_dependabot/sources/zenodo.py` until T022 passes
- [X] T031 [P] [US1] Implement `src/model_dependabot/sources/figshare.py` until T023 passes
- [X] T032 [P] [US1] Implement the dataset part of `src/model_dependabot/sources/hf.py` until T024 passes (extends 001:T020)
- [X] T033 [P] [US1] Implement `src/model_dependabot/sources/hf_takedowns.py` until T025 passes
- [X] T034 [US1] Add the dataset alert and watch-event kinds to `src/model_dependabot/lifecycle.py`, store routing at `register` and wire the six new sources into `check` until T026 and T027 pass (needs 001:T033 and 001:T034)

**Checkpoint**: User Story 1 works on its own

---

## Phase 4: User Story 2 - Alert when a licence changes (Priority: P1)

**Goal**: Licences are recorded at registration, normalised against the SPDX list and compared at each check;
a real change raises an alert, spelling and alias differences do not.

**Independent Test**: quickstart.md section 3: recorded licence pairs give one `licence_changed` alert for a
real change and none for case or alias differences (SC-002).

### Tests for User Story 2

- [X] T035 [P] [US2] Write failing tests in `tests/unit/test_licences.py` for research U8: normalisation order "exact SPDX identifier ignoring case; SPDX full name ignoring case; an entry in `licences/aliases.toml`"; expressions normalised "term by term with operators upper-cased"; anything else is `unrecognised` and kept as declared; the vendored list is checked against `SHA256SUMS` when loaded
- [X] T036 [P] [US2] Write failing tests in `tests/unit/test_register_licences.py` for FR-008: `register` records the declared licence of the base model (`cardData.license`) and each dataset (DataCite `rightsList`, Zenodo `metadata.license.id`, Figshare `license.name`, hub `cardData.license`) in the inventory's `licenses` (T013 forms); a source that fails at registration leaves the licence empty; the first successful observation then becomes the baseline (labelled as such) and raises nothing
- [X] T037 [P] [US2] Write failing tests in `tests/unit/test_lifecycle_licences.py`: `licence_changed` (cause key "kind + item", one alert per item, `HIGH`) only when both licences are recognised and their normalised forms differ, showing recorded, declared and evidence; A then B then C gives one alert whose declared licence is C, with both observations as evidence; A then B then A closes the alert as `cleared` with the A observation as evidence (constitution 1.0.2); with no recorded licence, the comparison is against the first stored observation (the baseline); `apache-2.0` against `Apache-2.0` and Figshare `CC BY 4.0` against `CC-BY-4.0` raise nothing; an unrecognised declared licence records `licence_unrecognised`; a source that no longer declares a recorded licence records `licence_missing`
- [X] T038 [US2] Write a failing integration test in `tests/integration/test_check_licences.py` following quickstart.md section 3

### Implementation for User Story 2

- [X] T039 [US2] Implement `src/model_dependabot/upstream/licences.py` and add to `src/model_dependabot/licences/aliases.toml` only spellings seen in the recorded fixtures (T019), each with its `source`, until T035 passes
- [X] T040 [US2] Record licences at registration in `src/model_dependabot/inventory/build.py` using the US1 adapters (T028 to T032) until T036 passes
- [X] T041 [US2] Add licence comparison to `src/model_dependabot/upstream/changes.py` and the licence kinds to `src/model_dependabot/lifecycle.py` (cause key kind + item; a further change adds evidence and updates the declared licence; a return to the recorded licence closes as 001's `cleared`, needs 001:T046a) until T037 and T038 pass

**Checkpoint**: User Stories 1 and 2 work on their own

---

## Phase 5: User Story 3 - Alert when the base model is disabled or no longer publicly available (Priority: P2)

**Goal**: A disabled base model raises an alert at once; an unbroken run of scheduled refusals spanning at
least 24 hours raises "no longer publicly available", which clears when the base model is reachable again.

**Independent Test**: quickstart.md section 4: replayed hub answers across simulated runs give an alert only
once an unbroken run of scheduled refusals spans 24 hours (including daily runs a few seconds short of 24
hours apart, which alert on the third run), none for a single refusal and `cleared` when reachable again
(SC-003).

### Tests for User Story 3

- [X] T042 [P] [US3] Write failing tests in `tests/unit/test_hf_models.py` against `tests/fixtures/hf_upstream/`: model info reads `disabled`, `gated`, `private`, `sha`, `cardData` and `lastModified`; HTTP 401, 403 or 404 is `refused`; a timeout, connection error or HTTP 5xx is a source failure, not an observation; U7's fail-safe: a model-info answer for a disabled model that does not match the dataset shape recorded in T019 (200 with `disabled: true`) records a watch event with the hub's response as evidence and opens no alert (research U7)
- [X] T043 [P] [US3] Write failing tests in `tests/unit/test_refusal_rule.py` for research U7's refusal-span rule: the alert opens when "an unbroken run of refusal observations from scheduled check runs, with no reachable observation from any run in between, spans at least 24 hours from its first to its latest refusal"; two scheduled refusals 23 hours apart do not qualify; daily scheduled refusals landing a few seconds under 24 hours apart do not qualify on the second run and do qualify on the third; an on-demand refusal neither counts towards the span nor breaks the run; a reachable observation from any run (scheduled or on-demand) ends the run, and the next refusal starts a new one; a failed request is ignored; a refusal that does not qualify records `base_model_refused`
- [X] T044 [P] [US3] Write failing tests in `tests/unit/test_lifecycle_base_model.py`: `base_model_disabled` (cause key "kind + base-model purl", `MODERATE`) opens at once with the hub response as evidence; `base_model_unavailable` (`LOW`) states "no longer publicly available (deleted or made private)" and shows the refusals of the run; it closes as 001's `cleared` when the base model is reachable again, with that observation as evidence (FR-016, constitution 1.0.2); a later qualifying run after `cleared` opens a new alert (001's re-open rule)
- [X] T045 [US3] Write a failing integration test in `tests/integration/test_check_base_model.py` following quickstart.md section 4, including daily scheduled runs that land a few seconds under 24 hours apart: no alert on the second refused run, one `base_model_unavailable` alert on the third

### Implementation for User Story 3

- [X] T046 [US3] Implement the model-info part of `src/model_dependabot/sources/hf.py` until T042 passes (after T032, same file)
- [X] T047 [US3] Implement the refusal-span rule in `src/model_dependabot/upstream/changes.py` until T043 passes
- [X] T048 [US3] Add the base-model kinds and their transition to 001's `cleared` state to `src/model_dependabot/lifecycle.py` (needs 001:T046a) until T044 and T045 pass

**Checkpoint**: User Stories 1 to 3 work on their own

---

## Phase 6: User Story 4 - Watch events for upstream changes that are not problems on their own (Priority: P3)

**Goal**: New revisions, new-version pointers, gating and card changes, newer dataset versions, replacements
and moves are recorded as watch events with evidence, never alerts.

**Independent Test**: quickstart.md section 5: each replayed change gives one watch event and no alert.

### Tests for User Story 4

- [X] T049 [P] [US4] Write failing tests in `tests/unit/test_watch_events_base_model.py`: `base_model_new_revision` shows the pinned and newest revision; `base_model_new_version_pointer` when `cardData.new_version` appears or changes; `gating_changed` when `gated` changes (`false`, `auto` or `manual`); `card_changed` when the SHA-256 of canonical `cardData` "without licence fields and `new_version`" changes; each recorded once per change, never as an alert (FR-013)
- [X] T050 [P] [US4] Write failing tests in `tests/unit/test_watch_events_datasets.py`: `dataset_new_version` from Zenodo `links.latest` or DataCite `IsPreviousVersionOf` / `HasVersion`; `dataset_replaced` from DataCite `IsObsoletedBy`, naming the newer or replacing record; never an alert (FR-007)
- [X] T051 [US4] Write a failing integration test in `tests/integration/test_check_watch_events.py` following quickstart.md section 5

### Implementation for User Story 4

- [X] T052 [US4] Add revision, pointer, gating, card and dataset-version detection to `src/model_dependabot/upstream/changes.py` and the watch-event kinds to `src/model_dependabot/lifecycle.py` until T049, T050 and T051 pass

**Checkpoint**: all user stories work on their own

---

## Phase 7: Polish & Cross-Cutting Concerns

- [X] T053 [P] Write a failing integration test in `tests/integration/test_upstream_fixed.py` for FR-015: registering a newer model version whose inventory no longer has the affected base model or dataset closes that alert as `fixed` by that version; `alert dismiss` works on the new kinds (needs 001:T046 and 001:T047)
- [X] T054 [P] Write failing contract tests in `tests/contract/test_cli_json_upstream.py` checking `alerts --json` against the shapes in contracts/cli.md (new kinds, `severity_origin: "policy"`, `last_check.trigger`) and that `alert show` displays `original_sha256`, `body_sha256` and `redacted_fields` for redacted evidence; `history` lists closed alerts of the new kinds with how they closed, including `cleared` for `base_model_unavailable` and `licence_changed` and `withdrawn` for a retraction alert (needs 001:T050 and 001:T051)
- [X] T055 Make T053 and T054 pass in `src/model_dependabot/lifecycle.py`, `src/model_dependabot/reports.py` and `src/model_dependabot/cli.py`
- [X] T056 [P] Write an integration test in `tests/integration/test_source_failure_upstream.py` following quickstart.md section 6: with each new source made to fail in turn, exit code 2, the source recorded as failed and no alert opened, changed or closed because of it (SC-005)
- [X] T056a [P] Extend 001:T054a's test in `tests/integration/test_never_writes.py` to this feature (FR-017, constitution III): over `register` and `check --all --scheduled` on a worked example with a base model, a DOI dataset tied to a paper and a hub dataset, the spying fetcher records every request to `doiRA`, Crossref, DataCite, Zenodo, Figshare, the hub and the takedown log, and each is `GET` or `HEAD`; none carries an `Authorization` header or token (FR-002)
- [X] T057 [P] Write an integration test in `tests/integration/test_privacy.py` following quickstart.md section 7: after the US1 to US4 suites, the database and evidence store contain none of the fixtures' `requesting_entity`, `citation_text`, `removed_by` or Crossref author values, and the evidence records list them in `redacted_fields`
- [X] T058 [P] Add `live`-marked smoke tests in `tests/live/test_live_upstream.py` that check one live answer per new source against the recorded shapes (for example `yavon/muxue` `disabled: true`, a nonexistent dataset 401, a Zenodo 410 tombstone); excluded from the default run
- [X] T059 [P] Update `README.md`: the new checks, the manifest's `paper_doi` and hub datasets, scheduling with `check --all --scheduled` (which supersedes 001's `check --all` for the scheduler: a host already running `check --all` must add `--scheduled`, or its refusals never count towards the refusal-span rule), the vendored SPDX list and the sources used; British spelling, no serial comma, no institution names
- [X] T060 Run the full suite with the network blocked and ruff with no findings; time a check of one model with a base model and ten datasets against recorded fixtures with real pacing (budget 60 seconds, plan.md); record commands, counts, timings and exit codes in `specs/002-upstream-watch/validation.md`
- [X] T061 Walk through quickstart.md sections 1 to 9 on a real model inventory (owner-provided), record each section's result in `specs/002-upstream-watch/validation.md` and fix anything it misses
- [X] T062 Neutrality and privacy check across `src/`, `tests/`, docs and commit messages: no institution names, no personal data in fixtures (including the recorded takedown log and tombstones), generic User-Agent only. Third-party repository identifiers used only as test data (for example the gated-model fixture `meta-llama/Llama-3.1-8B`) are not institution names in the constitution's neutrality sense: that rule is about the project's own users and authors, so such identifiers stay

---

## Dependencies & Execution Order

### Phase Dependencies

- Feature 001 Phases 1 and 2 (001:T001 to 001:T011) come first.
- Setup (Phase 1) has no further dependencies.
- Foundational (Phase 2) depends on Setup and blocks every story. T014 needs 001's US1 inventory code
  (001:T019, 001:T021, 001:T022); T018 needs 001:T034; T019 needs T005 and T007.
- US1 (Phase 3) depends on Phase 2 and on 001's alert lifecycle (001:T033) and `check` command (001:T034).
- US2 (Phase 4) depends on US1's adapters (T028 to T032) for dataset licences.
- US3 (Phase 5) depends on Phase 2 only; T046 follows T032 because both change `sources/hf.py`.
- US4 (Phase 6) depends on US3 (T046) for base-model fields and on US1 (T029, T030) for dataset versions.
- T041 and T048 need 001's `cleared` state (001:T046a).
- Polish (Phase 7) comes last; T053 needs 001:T046 and 001:T047, T054 needs 001:T050 and 001:T051, T056a
  needs 001:T054a.

### Within Each User Story

- Tests are written and seen failing before the code they cover (constitution V).
- Fixtures (T019) before any adapter test that reads them.
- Adapters before `upstream/changes.py`; `upstream/changes.py` before `lifecycle.py`; `lifecycle.py` before
  the CLI wiring.
- `lifecycle.py` and `upstream/changes.py` are changed by several stories, so those tasks run in story order.

### Parallel Opportunities

- Setup: T002 and T003 together.
- Foundational: the test files T004, T006, T008, T010, T012, T013, T015 and T017 together, then their
  implementations.
- US1: tests T020 to T026 together; adapters T028 to T033 together.
- US2 tests T035 to T037 together; US3 tests T042 to T044 together; US4 tests T049 and T050 together.
- US3 can run beside US1 once Phase 2 is done, except T046 after T032.

## Parallel Example: User Story 1

```text
Task: "T020 failing tests for Crossref retractions in tests/unit/test_crossref.py"
Task: "T021 failing tests for DataCite findability and routing in tests/unit/test_datacite.py"
Task: "T022 failing tests for Zenodo tombstones in tests/unit/test_zenodo.py"
Task: "T023 failing tests for Figshare in tests/unit/test_figshare.py"
Task: "T024 failing tests for hub datasets in tests/unit/test_hf_datasets.py"
Task: "T025 failing tests for the takedown log in tests/unit/test_hf_takedowns.py"
```

## Implementation Strategy

### MVP First (User Story 1)

1. Feature 001's Phases 1 and 2, then this feature's Phases 1 and 2.
2. Phase 3 (US1): retraction and removal alerts are the most confirmable upstream signal; stop and validate
   with quickstart.md section 2.

### Incremental Delivery

US2 (licences), then US3 (base model), then US4 (watch events), each tested on its own before the next. The
Polish phase ends with the quickstart walkthrough on a real model.

---

description: "Task list for feature 011: multi-parent, typed model lineage"
---

# Tasks: Multi-parent, Typed Model Lineage

**Input**: Design documents from `/specs/011-typed-model-lineage/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/manifest-parents.md,
contracts/cyclonedx-lineage.md, contracts/edge-evidence.md, quickstart.md

**Tests**: Required. Constitution principle V: every test task is written before the code it tests and
must fail first (run it, see it fail for the expected reason, then write the code). The SC-001
equivalence test fails first too: it asserts the recorded pre-011 baseline and the new edge rows. The one
exception is T011's characterisation half, which pins behaviour that exists today and must pass before
any change. The default run stays offline (`tests/conftest.py` blocks sockets).

**Organisation**: by user story. US1 and US2 (P1), then US4 before US3 (both P2), because propagation
stops at cycles and needs resolved references, then US5 (P3).

## Format: `[ID] [P?] [Story] Description`

- **[P]**: can run in parallel (different files, no dependency on an unfinished task)
- **[Story]**: US1 to US5 of spec.md

## Path Conventions

The existing single project: `src/model_dependabot/` and `tests/` at the repository root (plan.md, Project
Structure). Line references are to `main` at `47ebfbe`; feature 010 lands first (owner, 2026-11-19), so the
first task that edits a file re-checks its references on the `main` 010 leaves. House style for every string and document: plain
English, British spelling, no serial comma; fixture names `example-org/*`, no institution names.

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: the constitution amendment, skeletons, fixtures and the baseline

- [x] T001 Amend `.specify/memory/constitution.md` as research L12 states, only after the owner's explicit yes on the wording: replace "the base model it was fine-tuned from" in the preamble (`constitution.md:4`) with "the models it was derived from by fine-tuning, adaptation, merging or quantisation" (no parenthesis nested in the preamble's list), set the footer to `**Version**: 1.1.0` and `**Last Amended**` to the commit date (`constitution.md:88`), and record the rationale ("several parents of four types widen the watched scope: a material expansion, MINOR per Governance", `constitution.md:84-85`) and the owner's approval in the commit message; no other line changes
- [x] T002 [P] Create `src/model_dependabot/lineage/__init__.py` with a module docstring, `RELATIONSHIPS = ("fine-tuned-from", "adapter-for", "merged-from", "quantized-from")`, `UNSPECIFIED = "unspecified"` and `EDGE_KINDS = ("hub", "model")` (data-model.md, Relationship)
- [x] T003 [P] Write the manifests of quickstart.md in `tests/fixtures/lineage/`: `merge-two.toml`, `adapter-no-revision.toml`, `bad-relationship.toml`, `unspecified-relationship.toml`, `both-forms.toml`, `hub-and-model.toml`, `four-types.toml` (one of each type, the `adapter-for` one a registered model), `duplicate.toml`, `ambiguous.toml`, `same-repo-two-revisions.toml`, `cycle-a.toml`, `cycle-b.toml`, `cycle-c.toml`, `self.toml`, `same-model-v2.toml`, `chain-grandparent.toml`, `chain-parent.toml`, `chain-child.toml` and `merge-one-parent.toml`, with `example-org/*` repositories and 40-hex revisions whose hub answers exist in `tests/fixtures/hf_upstream/`; document each in `tests/fixtures/lineage/NOTES.md`
- [x] T004 Write the CycloneDX 1.7 documents in `tests/fixtures/lineage/` (after T003, which also writes `NOTES.md`): `third-party-two-untyped.json` (two `pkg:huggingface` ancestors, no properties), `same-purl-twice.json` (two ancestors with one purl, no properties), `two-no-purl.json` (two ancestors without purl or `parent-model`), `unrecognised-type.json` (`model-dependabot:relationship` = `distilled-from`), `claims-manifest.json` (`model-dependabot:edge-origin` = `manifest`), `one-parent-two-types.json`, `self-reference.json` and `registered-no-version.json`; the 300-ancestor document is built at test time, not committed; add them to `tests/fixtures/lineage/NOTES.md`
- [x] T005 Once feature 010 has merged, on the `main` it leaves and before any Phase 2 code (after T003): run `uv run pytest -q` and record the pass count, the commit and its `git rev-parse HEAD:src` in `specs/011-typed-model-lineage/validation.md`; write `tests/fixtures/equivalence/lineage_scenarios.py`, importing `Scenario`, `snapshot` and `run` from `tests/fixtures/equivalence/scenarios.py` (`:49`, `:295`, `:325`), with one function per `[base_model]` scenario mirroring `tests/integration/test_check_base_model.py`, `tests/unit/test_lifecycle_base_model.py`, `tests/unit/test_lifecycle_base_model_moved.py` and `tests/integration/test_register.py`, a `SCENARIOS` mapping as 004's (`scenarios.py:243`) and a snapshot extended with entry identifiers, gaps and each command's exit code; give `tools/record_equivalence_baseline.py` the options `--scenarios MODULE`, `--out FILE` and `--expect-src-tree TREE` (defaults unchanged for 004), refusing to record unless `src/` is clean and `HEAD:src` equals `TREE`, and writing `recorded_from` and `src_tree`; run it to record `tests/fixtures/equivalence/pre-011-baseline.json` (SC-001, research L11, review R7, R8)
- [x] T006 [P] Write `tests/fixtures/db/schema-pre-011.sql`, the schema of `main` at `47ebfbe` with one model, two versions (one with a `base_model` entry, one legacy with null origin), an open `base_model_disabled` alert and one check run, built the way `tests/fixtures/db/schema-pre-004.sql` is
- [x] T007 [P] Add the discovery projects `tests/fixtures/projects/card-two-merge/` (a `README.md` model card with `base_model: [example-org/base-a, example-org/base-b]` and `base_model_relation: merge`), `tests/fixtures/projects/card-unmapped/` (`base_model_relation: other`) and `tests/fixtures/projects/card-no-relation/` (two base models, no relation)

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: the edge table, the new watch kind, the trust states and the default-behaviour guard

**CRITICAL**: no user story work starts until this phase is complete.

### Tests first

- [x] T008 [P] Write `tests/integration/test_migration_011.py` (fails first): opening a database built from `tests/fixtures/db/schema-pre-011.sql` adds `lineage_edges` with its triggers and unique index; `watch_events.kind` accepts `lineage_inherited` and every watch event keeps its id; every alert keeps its id, state and evidence; a second open changes nothing; `Store.open_read_only` on the pre-011 file reads no stored edges, synthesises one `unspecified` edge per `base_model` entry and writes nothing
- [x] T009 [P] Write `tests/unit/test_store_lineage.py` (fails first) for data-model.md, Lineage edge: an edge row cannot be updated or deleted; a second row with the same identity is refused, while two hub edges without a repository and with different `source_key`s are both accepted (review R2); `state = 'verified'` is refused by the `CHECK` (FR-008); `add_version(..., edges=...)` records a version and its edges all or nothing; `edges(model_id, version)` returns stored edges in `position` order and, for a version without rows, synthesised edges with origin from `model_versions.origin` and state `owner` for `manifest`/`record`, `unverified` for `import` or null; `version_exists` answers by id and version
- [x] T010 [P] Write `tests/integration/test_lineage_equivalence.py` (fails first), modelled on `tests/integration/test_default_equivalence.py`: assert the baseline's `src_tree` is recorded and its scenarios equal `lineage_scenarios.SCENARIOS`, then run each scenario through `lineage_scenarios.run` in a temporary directory and assert equality with `tests/fixtures/equivalence/pre-011-baseline.json` on exactly SC-001's fields, and that each registered `[base_model]` version has one stored edge with relationship `unspecified`, origin `manifest`, state `owner` and `source_key` `base_model` (SC-001, FR-003)
- [x] T011 [P] Write `tests/contract/test_inventory_profile_ancestors.py`, the multi-ancestor import test the spec found missing (spec, Background): (a) a characterisation test, passing on today's code, that `import_bom` (`inventory/cyclonedx.py:557`) of a CycloneDX 1.7 document with two `pkg:huggingface` ancestors returns two pinned `base_model` entries with their revisions, that two ancestors with one purl return two entries (no de-duplication, `:595-596`) and that an ancestor without purl gives the gap "no Hugging Face purl" (`:466-468`); (b) failing first, that importing the two-ancestor document through `model-dependabot import` records two edges with relationship `unspecified`, origin `import`, state `unverified` (US2 AS2), and that an ancestor carrying `model-dependabot:parent-model` gives an edge and no entry (review R1)

### Implementation

- [x] T012 Add `lineage_edges` to `SCHEMA` in `src/model_dependabot/store.py` (`store.py:127`) with the columns and checks of data-model.md, `REFERENCES model_versions (model_id, version)`, a unique index on edge identity using `COALESCE` for nullable parts, and `lineage_edges_no_update` and `lineage_edges_no_delete` triggers beside the inventory ones (`store.py:440-443`)
- [x] T013 Add `lineage_inherited` to `WATCH_KINDS` in `src/model_dependabot/store.py` (`store.py:73-103`) under a `# feature 011` comment, relying on `_widen_watch_kinds` (`store.py:815-822`) to rebuild an older `watch_events` on open; confirm T008's rebuild assertion passes
- [x] T014 Add `edges` to `Store.add_version` (`store.py:1371-1412`), inserting edge rows in the same `with self.conn:` block; add `edges(model_id, version)` with the legacy synthesis, `all_edges()` and `version_exists(model_id, version)`; teach `Store.open_read_only` (`store.py:631`) to read an absent `lineage_edges` as empty, in `src/model_dependabot/store.py`
- [x] T015 Add `EDGE_STATES = ("owner", "unverified")` and `edge_state(version_origin)` (owner for `OWNER_VERSIONS`, else unverified) beside `OWNER_VERSIONS` (`assurance/trust.py:25`) in `src/model_dependabot/assurance/trust.py`, with its docstring naming FR-008

**Checkpoint**: T008, T009 pass; T010 and T011(b) still fail until US1 and US2 write edges.

---

## Phase 3: User Story 1 - Declare several typed parents in the manifest (Priority: P1) MVP

**Goal**: `[[parents]]` with four types; one edge per parent; legacy `[base_model]` unchanged.

**Independent Test**: spec US1; quickstart scenarios 2 and 3.

### Tests first

- [x] T016 [P] [US1] Write `tests/contract/test_manifest_parents.py` (fails first): `load_manifest` (`manifest.py:171`) parses `merge-two.toml` and `four-types.toml` into `Manifest.parents`; every error of contracts/manifest-parents.md is a `ManifestError` with the stated message (both forms, a type outside the four, `unspecified`, `hub` and `model`, neither, `revision` with `model`, `version` with `hub`, a non-positive `version`, an unknown key); `[base_model]` still parses to `Manifest.base_model` and to one `ParentSpec` with `form = "base_model"` and `relationship = "unspecified"`, and still refuses a `relationship` key as unknown (`_BASE_MODEL_KEYS`, `manifest.py:25`)
- [x] T017 [P] [US1] Write `tests/unit/test_lineage_edges.py` (fails first): `edges_from_manifest` gives one edge per identity in declaration order; a repeat with the same type folds into one edge with `declared_count = 2`; the same parent with two types gives two edges; gaps "no revision", "revision is not a commit" (`inventory/build.py:38-39`) and "no version"; origin `manifest` or `record`; source file, SHA-256 and key (`parents[1]`, `base_model`); `entry_identifier` the pinned purl of `huggingface_purl` (`inventory/build.py:462-466`)
- [x] T018 [P] [US1] Extend `tests/unit/test_build.py` (fails first): `build_entries` (`inventory/build.py:547`) makes one `base_model` entry per distinct hub (repository, revision) of `Manifest.parents`, none for a registered-model parent, and for a legacy `[base_model]` exactly the entry `_base_model` makes today (`inventory/build.py:469-479`)
- [x] T019 [P] [US1] Write `tests/integration/test_register_parents.py` (fails first): US1 AS1 to AS5 through `model-dependabot register`, including exit 1 and nothing recorded for AS4 and AS5; a registered-model parent that does not exist registers with the gap "parent not registered"; a registration from a registration record (`cli.py:588-602`) records origin `record` and the record's SHA-256; `inventory show` lists the edges (contracts/manifest-parents.md, Register output)

### Implementation

- [x] T020 [US1] Add `parents` to `_TOP_KEYS` (`manifest.py:21`), `_PARENT_KEYS = {"hub", "revision", "model", "version", "relationship"}`, `ParentSpec` beside `BaseModelSpec` (`manifest.py:46-49`), `Manifest.parents` after `base_model` (`manifest.py:74`) and the `[[parents]]` parsing and errors beside the `[base_model]` block (`manifest.py:205-213`), with `[base_model]` also given as one `ParentSpec`, in `src/model_dependabot/manifest.py`
- [x] T021 [US1] Write `src/model_dependabot/lineage/edges.py`: `edges_from_manifest(manifest, *, origin, source_file, source_sha256, recorded_at)` with identity, folding and gaps as T017 states
- [x] T022 [US1] Change `build_entries` in `src/model_dependabot/inventory/build.py` (`:565-566`) to make the `base_model` entries from `Manifest.parents`' distinct hub parents through `_base_model` (`:469-479`), unchanged for a legacy manifest
- [x] T023 [US1] In `register` (`cli.py:604-642`), build the edges with `edges_from_manifest` (origin `manifest`, or `record` with the record's SHA-256), mark unresolved registered-model edges with `version_exists`, pass them through `_record` (`cli.py:439-475`) to `add_version`, and add `lineage.edges` to the payload, in `src/model_dependabot/cli.py`
- [x] T024 [US1] Add the "Lineage (N edges)" section to `_inventory_text` (`cli.py:416-427`) and `lineage` to the `inventory show` payload (`cli.py:681-689`), in `src/model_dependabot/cli.py`

**Checkpoint**: T010 passes (SC-001); US1 works alone; T060 done for this pull request.

---

## Phase 4: User Story 2 - Keep every edge on a CycloneDX round trip (Priority: P1)

**Goal**: one ancestor per edge with documented properties; imported edges `import`, `unverified`.

**Independent Test**: spec US2; quickstart scenario 4.

### Tests first

- [x] T025 [P] [US2] Write `tests/contract/test_inventory_profile_lineage.py` (fails first): `export_bom` writes one ancestor per edge with `model-dependabot:relationship` and `model-dependabot:edge-origin`; the `bom-ref` is `base-model:<n + k>` and a legacy version's ref equals today's (`cyclonedx.py:227`); a registered-model ancestor has no purl and carries `parent-model` and `parent-version`; no two refs repeat, with one parent under two types and a self-reference; every document validates against the official 1.7 schema (`cyclonedx.validate`, `:130`); `PROPERTIES` (`:68`) lists every new property
- [x] T026 [P] [US2] Write `tests/unit/test_import_ancestors.py` (fails first) for the six import rules of contracts/cyclonedx-lineage.md: the 256 limit, its gap entry and gap edge on a 300-ancestor document built in the test; origin `import`, state `unverified` and `claimed_origin` from `claims-manifest.json`; `unspecified` with no property; `unspecified` with `relationship_recorded = "distilled-from"`; a registered-model reference with and without a version, giving no entry (review R1); `same-purl-twice.json` giving two entries and one edge with `declared_count = 2`; `two-no-purl.json` giving two gap entries and two edges, no `duplicate_parent` (review R2); the "no Hugging Face purl" gap unchanged
- [x] T027 [P] [US2] Write `tests/integration/test_lineage_round_trip.py` (fails first) for SC-002: export, import, export of versions with 0, 1, 2 and 4 parents (one a registered-model reference) reproduces references, revisions, types and gaps, with claimed origin `manifest` on every imported edge; import then export of `third-party-two-untyped.json`, `unrecognised-type.json`, `one-parent-two-types.json`, `self-reference.json` and `two-no-purl.json` (two gap ancestors back) as SC-002 states; import, export, import of the 300-ancestor document keeps the limit gap (review R3); a resolved imported registered-model reference stays `unverified`

### Implementation

- [x] T028 [US2] Add `P_RELATIONSHIP`, `P_RELATIONSHIP_RECORDED`, `P_EDGE_ORIGIN`, `P_CLAIMED_ORIGIN`, `P_PARENT_MODEL` and `P_PARENT_VERSION` beside `P_FORMAT_ORIGIN` (`cyclonedx.py:65-67`) and to `PROPERTIES` (`:68`), and `MAX_ANCESTORS = 256`, in `src/model_dependabot/inventory/cyclonedx.py`
- [x] T029 [US2] Give `export_bom` (`cyclonedx.py:272-298`) an `edges` argument, writing ancestors from edges with the ref formula of research L4, a hub ancestor through `_base_model_component` (`:224-236`) with the new properties and a registered-model ancestor without purl, in `src/model_dependabot/inventory/cyclonedx.py`
- [x] T030 [US2] Add `import_ancestors(document)` to `src/model_dependabot/inventory/cyclonedx.py`, reading `pedigree.ancestors[]` (`:595-596`) up to `MAX_ANCESTORS` into imported edges by the six rules (an edge without a parent identity keyed by its `source_key`), plus the limit gap edge; change `import_bom` only so that it skips an ancestor carrying `model-dependabot:parent-model` and adds the limit gap entry, keeping one entry per other ancestor exactly as `_import_base_model` makes it today (`:463-486`), with no de-duplication (research L4, review R1)
- [x] T031 [US2] In `import_inventory` (`cli.py:644-679`) record the imported edges with origin `import`, state `unverified`, the document's SHA-256 (`cli.py:670`) and `ancestors[i]` keys, resolving registered-model references with `version_exists`; in `_record` (`cli.py:439-475`) pass the edges to `export_bom`, in `src/model_dependabot/cli.py`

**Checkpoint**: T011(b), T025 to T027 pass.

---

## Phase 5: User Story 4 - Detect cycles, duplicates and ambiguous edges (Priority: P2)

**Goal**: lineage problems at registration, import, audit and check, never stopping registration.

**Independent Test**: spec US4; quickstart scenario 6.

### Tests first

- [x] T032 [P] [US4] Write `tests/unit/test_lineage_graph.py` (fails first) for SC-005: cycles of length 1 (`self.toml`), 2 and 3 each reported once with members in path order; `duplicate_parent`, `ambiguous_relationship` and `parent_not_registered` each exactly once; version 2 referencing version 1 of the same id reports nothing; a reference that resolves after its parent registers stops being a gap and one that stops resolving becomes it again (FR-021a); the note `merge_with_one_parent`
- [x] T033 [P] [US4] Write `tests/integration/test_lineage_problems.py` (fails first): US4 AS1 to AS6 through `register`, `inventory audit` and `check`, with exit codes unchanged and registration never refused; the mutual pair forms its cycle only after the second registration (AS5)

### Implementation

- [x] T034 [US4] Write `src/model_dependabot/lineage/graph.py`: `resolve(edges, exists)`, `problems(edges_by_version, exists)` with iterative depth-first cycle search and the rotation rule of research L8, pure functions of edge rows
- [x] T035 [US4] Report `lineage.problems` in the `register` and `import` payloads and text (`cli.py:604-679`), from `store.all_edges()` and `version_exists`, in `src/model_dependabot/cli.py`
- [x] T059 [US4] Report lineage problems in `check`: add `lineage.problems` for every checked version to the check payload and a "Lineage problems" line per problem to `_check_text` (`cli.py:481-490`), from `lineage.graph` over `store.all_edges()`, with no overview row and no exit code change (FR-021, US4 AS1; T033 asserts it, review R4), in `src/model_dependabot/cli.py`

**Checkpoint**: T032, T033 pass.

---

## Phase 6: User Story 3 - Findings travel only along known, relevant edges (Priority: P2)

**Goal**: hub findings name every edge; registered parents' findings travel by the closed matrix as
inherited watch events.

**Independent Test**: spec US3; quickstart scenario 5.

### Tests first

- [x] T036 [P] [US3] Write `tests/unit/test_lineage_matrix.py` (fails first) for SC-004: for each row of `TRAVELS` (data-model.md) and each of the four types, `unspecified` and an ambiguous pair, the kind travels or not as the matrix says; a kind absent from `TRAVELS` (a made-up `future_kind`) travels on none; no watch event kind travels
- [x] T037 [P] [US3] Write `tests/unit/test_lineage_propagate.py` (fails first): direct and transitive reach; full paths with each edge's type; parallel one-edge paths give one finding, direct; each version visited at most once on a diamond and on a cycle; an `unverified` edge carries nothing; relevance by the referenced version's stored inventory (owner's ruling C5): a child pinning parent v1 inherits a v1 alert that v2 later fixed (`closed_by_version = 2`), does not inherit an alert on an item only v2 holds, inherits an alert first seen while the parent was at v3 when v1 holds the item, and inherits nothing from a `dismissed`, `cleared` or `withdrawn` alert or one fixed by v1
- [x] T038 [P] [US3] Write `tests/integration/test_lineage_propagation.py` (fails first) with recorded hub answers (`tests/fixtures/hf_upstream/model-disabled.json`): US3 AS1 to AS6; SC-003 with N = 1 to 4 edges to one repository giving exactly one alert whose `cause.edges` lists N edges; an inherited finding is a `lineage_inherited` watch event citing the parent's alert id and evidence, never an alert
- [x] T039 [P] [US3] Write `tests/contract/test_exit_codes_lineage.py` (fails first): every row of the exit code table of `tests/contract/test_exit_codes.py` gives the same code for lineage fixtures, and `check --fail-on LOW` on a child whose only findings are inherited exits as with no findings (SC-007, FR-027)
- [x] T040 [P] [US3] Write `tests/integration/test_lineage_versions.py` (fails first): moving a parent from `[base_model]` to `[[parents]]` with the same repository carries its open alert forward (FR-025, `reevaluate_version` at `lifecycle.py:2392`); a version without the parent closes it as `fixed`; a gap never fixes (FR-026); a type change alone carries the alert forward
- [x] T061 [P] [US3] Write `tests/integration/test_lineage_pass_failure.py` (fails first): with `lineage.propagate.inherited` patched to raise, `check` finishes its run with every source's status and the interrupted reason, stores the overview and reports the error as before (review F7 behaviour, `lifecycle.py:409-425`), and a passing lineage pass adds no overview row (review R5)

### Implementation

- [x] T041 [US3] In `src/model_dependabot/lifecycle.py`, build per target a map from repository to its edges before the loop of `_apply_upstream` (`:3520-3527`), and add `edges` to the causes of `base_model_disabled` and `base_model_unavailable` (`_disabled_state` `:3185-3209`, `_apply_refusal` `:3359`, `_apply_moved_base_model` `:3212-3257`) and a base model's `licence_changed` (`_apply_licence` `:3419-3484`), and `edges` to the `base_model_*` watch details (`_base_model_events` `:3260-3286`); cause keys unchanged
- [x] T042 [US3] Write `src/model_dependabot/lineage/propagate.py`: `TRAVELS`, `travels(kind, relationships)`, `candidates(alerts, entries, version)` (the C5 rule of research L7: item in the referenced version's stored entries, using the repository rules of `lifecycle.py:3572-3620`; state `open` or `fixed` with `closed_by_version > version`) and `inherited(child, edges, alerts_of, entries_of, exists)`, the bounded walk
- [x] T043 [US3] Add `_apply_lineage(store, targets)` to `src/model_dependabot/lifecycle.py` and call it as the last step of `_check` (`:457`), so it runs inside `run_check`'s `try` and the review-F7 handler (`:409-425`) finishes the run if it raises (review R5); it records one `lineage_inherited` event per parent alert per child with the parent alert's evidence ids, reads parents with `store.entries` and `store.alerts_for` in every state, appends only to `target.summary["watch_events"]` and never touches `target.tally` or `target.held` (`_store_overview`, `:432-454`)
- [x] T044 [US3] In `src/model_dependabot/reports.py`, add the edge lines under hub causes (`_cause_text`, `:172`) and the inherited event text (`watch_view`, `:93`) of contracts/edge-evidence.md

**Checkpoint**: T036 to T040 and T061 pass; T039 shows no exit code change; T060 done for this pull request.

---

## Phase 7: User Story 5 - Discovery and audit show lineage without trusting the model card (Priority: P3)

**Goal**: one candidate per card base model with a mapped type; audit lists edges and problems.

**Independent Test**: spec US5; quickstart scenario 7.

### Tests first

- [ ] T045 [P] [US5] Extend `tests/unit/test_discover_card.py` (fails first): the four `base_model_relation` values map to the four types; `other` and an absent relation give `unspecified` with the card value kept in the origin; one value applies to every listed name; the gap "several base models; multi-parent lineage is #9" never appears (FR-028)
- [ ] T046 [P] [US5] Extend `tests/unit/test_discover_compare.py` (fails first): each candidate is matched against every hub parent of `Manifest.parents`, not only one (FR-029)
- [ ] T047 [P] [US5] Extend `tests/unit/test_discover_propose.py` (fails first): one commented `[[parents]]` block per candidate with `relationship` when mapped, the placeholder line of research L9 when `unspecified`; the proposal, uncommented without choosing a type, is refused by `load_manifest`
- [x] T048 [P] [US5] Extend `tests/contract/test_cli_audit.py` (fails first): `inventory audit` JSON and text carry `lineage.edges`, `lineage.problems` and `lineage.notes` as contracts/edge-evidence.md states, including "resolved by id and version only"; no output of `register`, `import`, `inventory show`, `inventory audit`, `alerts` or `check` contains an edge state `verified` (SC-006)
- [ ] T049 [P] [US5] Extend `tests/integration/test_discover.py` (fails first) with the US5 independent test on `tests/fixtures/projects/card-two-merge/`

### Implementation

- [ ] T050 [US5] Map `base_model_relation` in `_base_models` (`discover/model_card.py:102-119`) and remove `SEVERAL_BASE_MODELS` (`discover/candidate.py:20`) and its use (`model_card.py:108-109`), in `src/model_dependabot/discover/model_card.py` and `src/model_dependabot/discover/candidate.py`
- [ ] T051 [US5] Match every candidate against every parent of `Manifest.parents` in `src/model_dependabot/discover/compare.py` (`:149-169`)
- [ ] T052 [US5] Write commented `[[parents]]` blocks in `_block` of `src/model_dependabot/discover/propose.py` (`:161-172`)
- [x] T053 [US5] Add the `lineage` block to `audit_report` in `src/model_dependabot/assurance/audit.py` (`:227`), from `store.edges`, `store.all_edges` and `lineage.graph`, read-only
- [x] T054 [US5] Add the "Lineage" section to `audit_text` in `src/model_dependabot/reports.py` (`:322`)

**Checkpoint**: T045 to T049 pass.

---

## Phase 8: Polish & Cross-Cutting Concerns

- [ ] T055 [P] Extend `tests/integration/test_never_writes.py`: `inventory audit` on a store with edges, problems and unresolved references writes nothing (file hash unchanged), and never upgrades a pre-011 file
- [ ] T056 Update the shared documentation once the code is settled: `[[parents]]` in `specs/001-inventory-alerts/contracts/manifest.md` (beside `:23-25`), the six property rows in `specs/001-inventory-alerts/contracts/inventory-profile.md` (`:19-25`, FR-013) and the manifest and closure sections of `README.md` (`:165-175`); check every statement against the code
- [ ] T057 Run every scenario of `specs/011-typed-model-lineage/quickstart.md` and record what each printed in `specs/011-typed-model-lineage/validation.md`
- [ ] T058 Run `uv run pytest -q`, `uv run ruff check` and `uv run ruff format --check` with their real exit codes (no pipe) and record the counts against T005's baseline in `specs/011-typed-model-lineage/validation.md`
- [ ] T060 In each pull request that changes CLI text or JSON (Phases 3, 4, 5, 6 and 7: register and `inventory show` lineage, alert cause `edges`, `check` problems and inherited events, the audit section), re-record feature 010's FR-016 CLI baseline with 010's recorder in the same pull request, list every changed invocation and the requirement that changes it in `specs/011-typed-model-lineage/validation.md`, and confirm no exit code changed (owner's ruling C6, review R7)

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: starts after feature 010 has merged (owner, 2026-11-19). T001 needs the owner's
  yes on its wording and lands in the first pull request; T004 after T003 (both write `NOTES.md`); T005
  runs after T003 on the `main` 010 leaves, before any Phase 2 code.
- **Foundational (Phase 2)**: after Setup; blocks every story. T012 to T014 touch `store.py` in order.
- **US1 (Phase 3)**: after Phase 2. T020 before T021 and T022; T023 after T021 and T022; T024 after T023.
- **US2 (Phase 4)**: after US1 (exports need stored edges). T028 before T029 and T030; T031 after both.
- **US4 (Phase 5)**: after US1 and US2 (problems over manifest and imported edges).
- **US3 (Phase 6)**: after US4 (the walk uses `graph.resolve` and stops at cycles). T041 and T043 both
  edit `lifecycle.py`: T041 first. T059 (check problems, added in review) follows T035 in Phase 5.
- **T060**: at the end of every pull request from Phase 3 on that changes CLI text or JSON.
- **US5 (Phase 7)**: after Phase 2 for discovery (T045 to T047, T050 to T052); T048, T053 and T054 after
  US4.
- **Polish (Phase 8)**: after the stories it documents.

### Within each story

Tests first, run and seen to fail; then `lineage/` pure modules, then store, then lifecycle, then views
and CLI.

## Parallel Example: Phase 2 tests

```text
T008 tests/integration/test_migration_011.py
T009 tests/unit/test_store_lineage.py
T010 tests/integration/test_lineage_equivalence.py
T011 tests/contract/test_inventory_profile_ancestors.py
```

## Parallel Example: User Story 3 tests

```text
T036 tests/unit/test_lineage_matrix.py
T037 tests/unit/test_lineage_propagate.py
T038 tests/integration/test_lineage_propagation.py
T039 tests/contract/test_exit_codes_lineage.py
T040 tests/integration/test_lineage_versions.py
T061 tests/integration/test_lineage_pass_failure.py
```

## Implementation Strategy

### MVP first (User Story 1 only)

1. Phase 1 (with T001) and Phase 2.
2. Phase 3 (US1): typed parents and stored edges.
3. Stop and validate with quickstart scenarios 2 and 3 and the SC-001 equivalence test.

### Incremental delivery

The plan's pull requests, in phase order: Phases 1 to 3, then US2, then US4, then US3, then US5 with
Phase 8. Each keeps the full suite green and is shippable alone.

## Notes

- [P] means different files and no dependency on an unfinished task; tasks editing `lifecycle.py`,
  `store.py`, `cli.py`, `reports.py` or `manifest.py` are never [P] with each other, nor with feature
  010's tasks on the same files (plan.md, Overlap with feature 010).
- Commit after each task or logical group, only when the owner asks; outward actions wait for the
  owner's yes.
- Nothing here reads weight bytes, adapter configuration or model-card text as lineage.

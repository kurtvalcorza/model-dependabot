# Implementation Plan: Multi-parent, Typed Model Lineage

**Branch**: `plan/011-typed-model-lineage` | **Date**: 2026-11-19 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/011-typed-model-lineage/spec.md` (clarified 2026-11-19, no
markers left). Tracking: #9.

## Summary

Six increments on the existing command-line tool, in priority order.

1. **Constitution amendment (C4)**: the preamble's "the base model it was fine-tuned from" becomes "the
   models it was derived from (...)", version 1.0.3 to 1.1.0, in the first pull request (research L12).
2. **Typed parents in the manifest (US1, P1)**: a `[[parents]]` array of tables, each a hub repository
   and revision or a registered model id and version, plus one of four relationship types. Edges are
   stored in a new immutable table `lineage_edges`; hub parents keep producing `base_model` entries
   exactly as today, so a legacy `[base_model]` manifest registers with identical entries, gaps and cause
   keys and gains only an `unspecified` edge (research L1 to L3, L5).
3. **CycloneDX round trip (US2, P1)**: one ancestor per edge with documented `model-dependabot:`
   properties for type, origin, claimed origin and registered-model reference; import always gives
   origin `import`, state `unverified`, with any stated origin kept as claimed origin; at most 256
   ancestors read (research L4). Adds the multi-ancestor import test the spec found missing.
4. **Hub findings over several edges and propagation (US3, P2)**: hub findings keep their keys and name
   every edge that carries them (one alert per cause per child); findings of a registered parent travel
   by the closed FR-017 matrix as `lineage_inherited` watch events, direct or transitive with the path,
   in a lineage pass at the end of `check` (research L6, L7).
5. **Graph problems (US4, P2)**: cycles, duplicate parents, ambiguous relationships and unregistered
   references, computed by a pure graph module at registration, import, audit and check, resolving
   references afresh each time (research L8).
6. **Discovery and audit (US5, P3)**: one candidate per card base model with the card's relation mapped
   to a type; comparison against every manifest parent; `inventory audit` lists edges and problems
   (research L9, L10).

## Technical Context

**Language/Version**: Python 3.12, type hints throughout (as 001 to 004)

**Primary Dependencies**: existing `jsonschema` (CycloneDX validation, `inventory/cyclonedx.py:113-138`),
`tomllib` (manifest), `packaging`. No new runtime dependency

**Storage**: the existing SQLite database. One new table `lineage_edges` with update and delete triggers
(data-model.md), created by `CREATE TABLE IF NOT EXISTS` in `SCHEMA` (`store.py:127`), so an older
database gains it on open. One new watch kind `lineage_inherited`; `watch_events` is widened by the
existing `_widen_watch_kinds` (`store.py:815-822`). No column added to an existing table; nothing removed
or renamed. A version registered before this feature has no edge rows and reads synthesised
`unspecified` edges from its `base_model` entries

**Testing**: pytest, offline by default (`tests/conftest.py`). New fixtures in `tests/fixtures/lineage/`
(manifests and CycloneDX documents); hub answers reused from `tests/fixtures/hf_upstream/`; a pre-011
baseline (`tests/fixtures/equivalence/pre-011-baseline.json`) recorded once on `main` before any code for
SC-001 (research L11); a pre-011 schema fixture (`tests/fixtures/db/schema-pre-011.sql`) for the
migration; the official CycloneDX 1.7 schema as vendored for every export test

**Target Platform**: as 001 (Linux and macOS CI; Windows for local use)

**Project Type**: command-line tool (library plus CLI) in the existing single package

**Performance Goals**: no new source request. The graph walk visits each model version at most once per
check (FR-022) and reads one version's open alerts per visited parent; a store of hundreds of versions
stays bound by its source requests, as today. Import reads at most 256 ancestors

**Constraints**: legacy manifests and every exit code unchanged (FR-003, FR-027, SC-001, SC-007); no edge
ever `verified` (FR-008, enforced by a `CHECK`); trust never travels through a BOM (FR-007); the audit
stays read-only (`store.py:631`); nothing reads weights or model-card text as lineage

**Scale/Scope**: as 001: tens to hundreds of models; parents per version usually 1 to a few tens

No open NEEDS CLARIFICATION: the spec's three questions were answered on 2026-11-19. Three planning
choices (P1 table name, P2 import limit, P3 which parent alerts belong to a referenced version) carry a
recommendation for the owner's review (research, Planning choices).

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | How this plan meets it | Before research | After design |
| :-- | :-- | :-- | :-- |
| Preamble (watched scope) | The preamble names one parent of one type ("the base model it was fine-tuned from", `.specify/memory/constitution.md:3-6`). Several parents of four types are a material expansion: per Governance a **MINOR** amendment (owner, 2026-11-19). Proposed wording: "the models it was derived from (fine-tuned from, adapted for, merged from or quantised from)"; version 1.0.3 to **1.1.0**; made by T001 in the first pull request with its rationale and the owner's approval in the commit. Until T001 lands no code widens the scope | Pass, amendment proposed | Pass, amendment task T001 |
| I. Evidence on Every Alert | Every finding along an edge cites the edge's type, origin, revision and source key (FR-009); an inherited event links the parent alert's evidence and names its id. No alert is raised from an edge alone | Pass | Pass |
| II. Pinned Inventory, Open Standards | Edges stay in CycloneDX `pedigree.ancestors[]`; the type, origin, claimed origin and registered-model reference use `model-dependabot:` properties because 1.7 has no field for them, each documented (FR-010, FR-013, contracts/cyclonedx-lineage.md). Every parent keeps its own pinned revision or version | Pass | Pass |
| III. Advise, Never Act | Nothing changes a manifest or a model. Discovery proposes commented blocks only. Inherited findings are events; only the parent's owner closes the parent's alert | Pass | Pass |
| IV. Precision First | The FR-017 matrix is closed with "does not travel" as default; `unspecified` and ambiguous edges pass only the intersection; imported registered-model references carry nothing; an inherited finding is a watch event, never a second alert (C3); one cause opens at most one alert per child (FR-024) | Pass | Pass |
| V. Test-First with Offline Feed Tests | No new feed. Every test task precedes the code it tests and fails first, the SC-001 equivalence test included (it asserts the recorded pre-011 baseline and the new edge rows, so it fails until edges are written) | Pass | Pass |
| Neutral open source; privacy; polite to sources | Fixtures use `example-org/*` names; no request added; no personal data in edges | Pass | Pass |
| House style | British spelling ("quantised" in prose; the type value `quantized-from` is D5's identifier and matches the hub's `quantized`), no serial comma | Pass | Pass |
| Development workflow | Specified, clarified and planned before code; outward actions wait for the owner | Pass | Pass |

Result: **pass**, with one amendment task (T001) and the justified items in Complexity Tracking.

## Project Structure

### Documentation (this feature)

```text
specs/011-typed-model-lineage/
├── spec.md              # specification with clarifications
├── plan.md              # this file
├── research.md          # Phase 0: decisions L1-L12, planning choices P1-P3
├── data-model.md        # Phase 1: lineage_edges, ParentSpec, TRAVELS, lineage_inherited
├── quickstart.md        # Phase 1: validation scenarios
├── contracts/
│   ├── manifest-parents.md   # [[parents]] form, errors, register output
│   ├── cyclonedx-lineage.md  # ancestor forms, properties, import rules, round trips
│   └── edge-evidence.md      # edge view, alert cause edges, inherited event, audit
├── checklists/requirements.md
└── tasks.md             # Phase 2 (/speckit-tasks)
```

### Source Code (repository root)

```text
src/model_dependabot/
├── manifest.py                # changed: _TOP_KEYS gains parents (:21); ParentSpec beside BaseModelSpec
│                              #          (:46-49); Manifest.parents (:74); [[parents]] parsing beside the
│                              #          [base_model] block (:205-213)
├── lineage/
│   ├── __init__.py            # new: RELATIONSHIPS, UNSPECIFIED, edge identity
│   ├── edges.py               # new: edges from a manifest or imported ancestors; fold duplicates
│   ├── graph.py               # new: resolution, cycles, duplicates, ambiguity, unregistered (pure)
│   └── propagate.py           # new: TRAVELS matrix, bounded walk, inherited findings (pure)
├── inventory/build.py         # changed: build_entries makes one base_model entry per distinct hub
│                              #          parent (:565-566, _base_model :469-479); returns edges too
├── inventory/cyclonedx.py     # changed: properties (:57-80); export_bom(edges) (:272-298);
│                              #          _base_model_component (:224-236); import_bom ancestors
│                              #          (:463-486, :595-596) with the 256 limit
├── store.py                   # changed: lineage_edges in SCHEMA (:127), triggers (:440-443);
│                              #          lineage_inherited in WATCH_KINDS (:73-103); add_version writes
│                              #          edges (:1371-1412); edges(), all_edges(), version_exists();
│                              #          open_read_only reads an absent table as empty (:631)
├── lifecycle.py               # changed: cause.edges in the base model path (_apply_base_model :3140,
│                              #          _disabled_state :3185, _apply_moved_base_model :3212,
│                              #          _apply_licence :3419); lineage pass in run_check (:410-428)
├── cli.py                     # changed: _record passes edges (:439-475); register (:604-642) and
│                              #          import_inventory (:644-679) record edges and print lineage;
│                              #          _inventory_text lineage section (:416-427)
├── reports.py                 # changed: edge lines under hub causes (_cause_text :172); inherited
│                              #          event text (watch_view :93); audit lineage section (:322)
├── assurance/audit.py         # changed: audit_report lineage block (:227)
├── assurance/trust.py         # changed: EDGE_STATES = ("owner", "unverified") beside OWNER_VERSIONS (:25)
└── discover/
    ├── model_card.py          # changed: _base_models maps base_model_relation (:102-119)
    ├── candidate.py           # changed: SEVERAL_BASE_MODELS removed (:20)
    ├── compare.py             # changed: every candidate against every parent (:149-169)
    └── propose.py             # changed: commented [[parents]] blocks (:161-172)
tools/
└── record_lineage_baseline.py # new: records the SC-001 baseline once, on the pre-011 build
tests/
├── fixtures/lineage/          # new: manifests and CycloneDX documents of quickstart.md
├── fixtures/equivalence/pre-011-baseline.json
├── fixtures/db/schema-pre-011.sql
├── unit/                      # manifest parents; edges; graph; propagate matrix; discovery mapping
├── contract/                  # manifest errors; CycloneDX lineage profile; audit JSON; exit codes
└── integration/               # US1-US5 independent tests; SC-001 equivalence; migration; round trips
docs (outside specs/, by task T056 only)
├── specs/001-inventory-alerts/contracts/manifest.md          # [[parents]] (FR-013 sibling)
├── specs/001-inventory-alerts/contracts/inventory-profile.md # new property rows (FR-013)
└── README.md                                                 # manifest section and closure rules
```

**Structure Decision**: the existing single package. Lineage logic lives in a new `lineage/` package of
pure functions (edges, graph, propagation) so the matrix, the walk and cycle detection are tested without
a store or a check run; `cli.py`, `lifecycle.py` and `assurance/audit.py` call it. Edges are a table of
their own, not inventory entries, so legacy entries stay byte-identical (research L2).

## Overlap with feature 010 (actionable alert view, #7)

Feature 010 is planned in parallel on `plan/010-actionable-alert-view`. Its spec cites `reports.py`,
`store.py`, `lifecycle.py`, `cli.py`, `manifest.py`, `assurance/trust.py`, `rules.py` and
`matching/severity.py`. Files both features change: **`reports.py`, `store.py`, `lifecycle.py`,
`cli.py`, `manifest.py` and `assurance/trust.py`**. Neither spec depends on the other (011 spec,
Dependencies).

Ordering:

- **No shared pull request.** Each feature's pull requests are rebased on the other's merged work; tasks
  editing the shared files are never [P] across the two features.
- **Store first, one at a time.** If both add watch kinds, alert fields or tables, the later pull request
  rebases its `WATCH_KINDS` and `SCHEMA` edits onto the earlier one; `_rebuild_for_kinds` is idempotent
  (`store.py:833`), so the migration order does not matter, only the textual merge.
- **010's relationship field reads 011's edges.** If 011's Phase 3 lands first, 010 fills "the known
  relationship to the model" from `cause.edges` and `lineage_inherited` (contracts/edge-evidence.md). If
  010 lands first, 011's T044 (reports) adds edges to 010's view rather than beside it. Recommended order:
  011 Phases 1-3 (amendment, manifest, edges) before 010's view work, because 010 then has typed edges to
  show from its first release; 010's work that does not touch these files proceeds in parallel.
- **`manifest.py`**: 011 adds `[[parents]]`; if 010 adds a manifest key, the later one adds its key to
  `_TOP_KEYS` (`manifest.py:21`) on rebase.

## Delivery order

The order follows tasks.md's phases.

1. Constitution amendment (T001), setup and foundation (store table, migration, baseline) with US1. One
   pull request.
2. CycloneDX round trip (US2), with the multi-ancestor import test. One pull request.
3. Graph problems (US4), before propagation, because propagation stops at cycles. One pull request.
4. Hub findings over several edges and propagation (US3). One pull request.
5. Discovery and audit (US5), then the shared documentation (T056). One pull request.

Each increment is shippable alone and keeps the full suite green. The SC-001 equivalence test lands in
increment 1 and stays in the suite.

## Complexity Tracking

| Exception | Why needed | Simpler alternative rejected because |
| :-- | :-- | :-- |
| A second home for lineage (`lineage_edges`) beside the `base_model` inventory entries, with hub edges pointing at entries | Legacy entries must stay identical (FR-003), a registered-model edge has no hub item, and one hub entry can carry two typed edges (ambiguity) | Typed columns on `inventory_entries` cannot hold registered-model edges, and the immutable table cannot give old rows a type |
| Edges of versions registered before 011 are synthesised on read, not stored | Inventory and version rows are immutable (`store.py:440-443`); writing edge rows for old versions would invent a recorded time and source | A backfill migration would record edges nobody declared at that time |
| A lineage pass in `check` that is not a source | Propagation reads only the store; making it a `--source` would let a run skip it and change the overview, against FR-027 | A source would add an overview row to every check, a difference FR-003 does not allow |
| The constitution's preamble is amended (MINOR, 1.1.0) | The watched scope widens from one fine-tuned base model to several parents of four types (owner, 2026-11-19) | PATCH would understate a material expansion; an exception here would leave the constitution contradicting the code |

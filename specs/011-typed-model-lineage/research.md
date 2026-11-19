# Research: Multi-parent, Typed Model Lineage

**Feature**: [spec.md](spec.md) | **Plan**: [plan.md](plan.md) | **Date**: 2026-11-19

Each item records the decision, why it was made and what else was considered. Code references are to
`main` at `47ebfbe` (PR #27 merged). `src/` and `tests/` are unchanged since `aa32cd6`, the commit the
spec's Background cites (`git diff --stat aa32cd6 47ebfbe -- src tests` is empty), so the spec's line
numbers still hold except where an item below corrects one. Kurt ruled on 2026-11-19 that feature 010
lands before 011 (C6): implementation starts from the `main` 010 leaves, and every line reference here is
re-checked at that base by the first task that edits the file (010 changes only `cli.py`, `rules.py`,
`README.md` and `docs/rules/`).

## Decisions already made

| # | Question | Decided | By |
| :-- | :-- | :-- | :-- |
| C1 | Relationship of a legacy `[base_model]`; may it take a type key? | `unspecified`, never inferred; no type key | owner, 2026-11-19 (spec, Clarifications) |
| C2 | Which registered-parent findings travel on which edge type | The FR-017 matrix as written | owner, 2026-11-19 |
| C3 | Inherited finding: alert or watch event? | A watch event marked inherited, citing the parent's alert | owner, 2026-11-19 |
| C4 | Constitution preamble | MINOR amendment 1.0.3 to 1.1.0, proposed by this plan (L12), made by task T001; wording without a nested parenthesis (review R13) | owner, 2026-11-19 |
| C5 | Which of a registered parent's findings belong to the version a child references (replaces the plan's P3, review R6) | Decided by the referenced parent version's own stored inventory: an alert of the parent travels when the item it names is in `store.entries(parent, v)`, including an alert a later version fixed. A child pinning version 1 still inherits version 1's findings after version 2 fixes them (L7) | owner, 2026-11-19 |
| C6 | Order against feature 010 | 010 lands before 011; 011 records its SC-001 baseline on the `main` 010 leaves, with provenance, and re-records 010's FR-016 CLI baseline in each pull request that legitimately changes CLI text or JSON (L11, plan.md) | owner, 2026-11-19 |

## Planning choices for the owner's review

These are the plan's own choices (P3 was replaced by the owner's ruling C5). Each has a recommendation; the plan follows it unless the owner rules
otherwise at plan review.

| # | Question | Options | Recommended |
| :-- | :-- | :-- | :-- |
| P1 | Name of the manifest's parent list (L1) | (a) `[[parents]]`; (b) `[[base_models]]`; (c) `[[lineage]]` | **(a)**: it says what each table is; (b) reads as the legacy table pluralised and invites mixing the forms |
| P2 | Import limit on `pedigree.ancestors[]` (L4, spec edge case) | (a) 256; (b) 64; (c) 1024 | **(a)**: far above any real merge (merges of tens of parents exist), small enough to bound the graph walk |

## L1. The manifest's parent list

**Finding**: the manifest accepts one `[base_model]` table with keys `hub` and `revision`
(`src/model_dependabot/manifest.py:21`, `:25`), parsed at `manifest.py:205-213` into one optional
`BaseModelSpec` (`manifest.py:46-49`, field `Manifest.base_model` at `manifest.py:74`). Unknown keys are
an error (`manifest.py:78-84`), so a new table must be added to `_TOP_KEYS`.

**Decision**: an array of tables `[[parents]]` (P1), each with:

- `relationship` (required): one of `fine-tuned-from`, `adapter-for`, `merged-from`, `quantized-from`;
  `unspecified` and any other value are exit 1, naming the parent's index and the four types (FR-002).
- either `hub` (an `hf:` reference, as `[base_model]`) with an optional `revision`, or `model` (a
  registered model id) with an optional integer `version`; both or neither is exit 1 (spec edge case,
  FR-001). A missing `revision` is the gap "no revision", a non-commit one "revision is not a commit"
  (`inventory/build.py:38-39`, FR-005); a missing `version` is the new gap "no version" (FR-010a).

`[base_model]` and `[[parents]]` together are exit 1: "use either [base_model] or [[parents]], not both"
(FR-004). `[base_model]` is unchanged: keys `hub` and `revision` only, no `relationship` (C1).

The parsed form is a new `ParentSpec` tuple, `Manifest.parents`. A legacy `[base_model]` is also
represented there as one `ParentSpec` with `relationship = "unspecified"` and `form = "base_model"`, so
every reader downstream handles one shape; `Manifest.base_model` stays, so `discover/compare.py` keeps
working until T051 moves it to `parents`.

**Alternatives**: a `relationship` key inside `[base_model]` (refused by C1); an inline array
`parents = [...]` (harder to read, and no other manifest list is written that way).

## L2. Where edges are stored

**Finding**: inventory entries are immutable (`store.py:440-443` triggers) and keyed by kind
(`store.py:49`, `:153-178`); an entry has no field for a relationship, an origin or a second identity.
The pinned base model entry's identifier is its purl with the revision (`inventory/build.py:462-479`),
and every check reads base model entries from `inventory_entries` (`lifecycle.py:3524-3527`).

**Decision**: a new immutable table `lineage_edges` (data-model.md), one row per edge, with triggers
refusing update and delete, as `inventory_entries` has. Hub edges keep producing `base_model` inventory
entries exactly as today, one entry per distinct (repository, revision); the edge row names that entry's
identifier (`entry_identifier`). Registered-model edges have no inventory entry: they are not hub items,
and an entry for them would be watched on the hub by `_apply_upstream`.

Why this keeps FR-003: a legacy manifest produces the same `base_model` entry with the same identifier,
so entry identifiers, gaps, cause keys and every hub finding are produced by unchanged code; the edge row
is purely additive. A version registered before this feature has no edge rows; readers synthesise its
edges from its `base_model` entries (`relationship = "unspecified"`, origin from
`model_versions.origin`, `store.py:149`), never writing them back.

**Alternatives**: new columns on `inventory_entries` (cannot hold a registered-model edge or two types on
one entry; the table is immutable, so a legacy row could never gain them); edges only inside the stored
CycloneDX document (not queryable, and an imported claim would be indistinguishable from the owner's).

## L3. Edge identity, duplicates and ambiguity

**Decision**: edge identity is (parent identity, relationship) (FR-023), where the parent identity is
(`hub`, repository lower-cased, revision) or (`model`, model id, version). At registration and import the
builder folds edges with the same identity into one row and stores how many times it was declared
(`declared_count`), so the "duplicate parent" problem is reported again at every audit and check
(US4 AS2). Two edges with the same parent identity and different types are both kept; the problem
"ambiguous relationship" is computed on read (US4 AS3).

**An edge without a parent identity never folds** (review R2). An imported ancestor with neither a
`pkg:huggingface` purl nor `model-dependabot:parent-model` (today's gap "no Hugging Face purl",
`cyclonedx.py:467-468`), and the import-limit gap (L4), have no repository and no model id. Such an edge
is keyed by its `source_key` (`ancestors[i]`) instead, so two of them stay two edges, are never a
`duplicate_parent` or `ambiguous_relationship`, and re-export writes both, as today's two gap entries do.

**Entries**: on registration from a manifest, hub edges with the same repository and revision share one
`base_model` entry, so the hub is asked once and one finding names both edges (FR-024). On import, entries
stay as today (L4).

## L4. CycloneDX ancestors

**Finding (what the code does today)**: export writes one `pedigree.ancestors[]` component per
`base_model` entry with `bom-ref` `base-model:<index>`, the index being the entry's position in the
version's entry list (`inventory/cyclonedx.py:224-236`, `:277-284`); the root is `model:<id>@<version>`
(`:292-298`). Import makes **one `base_model` entry per ancestor, with no de-duplication**
(`:595-596`): two ancestors with one purl give two entries with the same identifier. `_import_base_model`
(`:463-486`) ignores every property but `model-dependabot:gap`; an ancestor without a `pkg:huggingface`
purl becomes a gap entry, its reason the ancestor's `model-dependabot:gap` or else "no Hugging Face purl"
(`:466-468`). The only test of ancestors covers one (`tests/contract/test_inventory_profile.py:129-134`).
Export is computed once, at registration, by `cli._record` (`cli.py:439-475`) and stored;
`inventory export` writes the stored document (`cli.py:691-700`).

**Decision, export**: `export_bom` gains an `edges` argument and writes one ancestor per edge, not per
entry. The k-th edge (0-based, stored order) gets `bom-ref` `base-model:<n + k>`, where n is the number of
weight-file and package entries. For a legacy version this is the index today's code gives its one base
model (entries are sorted weight files, packages, base model, datasets; `inventory/build.py:36`), so a
legacy ref is unchanged; refs stay unique for any number of edges because files, packages and datasets
use other prefixes (`cyclonedx.py:188`, `:214`). A gap edge (no revision, no purl, or the import limit)
is written as an ancestor carrying `model-dependabot:gap`, so every gap survives a round trip. New
properties (contracts/cyclonedx-lineage.md): `model-dependabot:relationship`,
`model-dependabot:edge-origin`, `model-dependabot:claimed-origin`, `model-dependabot:relationship-recorded`,
`model-dependabot:parent-model` and `model-dependabot:parent-version`. A registered-model edge is an
ancestor with no purl (FR-010a).

**Decision, import** (aligned with L2 and data-model.md, review R1):

- An ancestor carrying `model-dependabot:parent-model` produces an edge and **no entry**:
  `import_bom` skips it, so it is not turned into the gap entry "no Hugging Face purl". Only documents
  written by this feature carry the property, so no earlier import changes.
- Every other ancestor keeps today's entry, one per ancestor, **without de-duplication**: two ancestors
  with one purl still give two entries, so third-party imports keep their entries and gaps exactly (a
  behaviour change here was considered and rejected; the repository-keyed alerts already give one alert
  for both, L6). Their edges fold by identity (L3); an edge's `entry_identifier` is the purl both share.
- At most 256 ancestors are read (P2). The rest become one gap entry and one gap edge (no parent identity,
  `source_key` `ancestors[256+]`) with the reason "more than 256 ancestors; N not read"; export writes that
  edge as a gap ancestor, and a re-import reads it back as a gap through `model-dependabot:gap` (review
  R3), so the gap is never lost on import then export.
- Every imported edge is origin `import`, state `unverified`, and keeps the document's `edge-origin` value
  as `claimed_origin` (FR-007, FR-011, D6).

**Validation**: an ancestor without a purl validates against the vendored CycloneDX 1.7 schema
(components need `type` and `name` only); inferred, T025 asserts it against the official schema, as every
export test does (`cyclonedx.py:130`).

## L5. Origin, source location and verification state

**Decision**: origins `manifest`, `record` and `import` are stored; `discovery` exists only on
candidates (FR-006, FR-007). The source location is the input file's name and SHA-256 (the manifest's
`Manifest.sha256`, the registration record's `record_sha256` or the BOM's SHA-256 already computed at
`cli.py:670`) plus the table key (`parents[2]`, `base_model` or `ancestors[3]`). Verification state
is `owner` for `manifest` and `record` and `unverified` for `import` and for a legacy version whose
origin is null or `import`, reusing feature 003's states (`assurance/trust.py:10-14`; `OWNER_VERSIONS`
at `trust.py:25`). No code path can write `verified`: the column's `CHECK` allows only `owner` and
`unverified` (FR-008, SC-006).

## L6. Hub findings over several edges (FR-014, FR-024)

**Finding**: base model alerts are keyed by the repository without a revision (`base_model_repo`,
`lifecycle.py:2557-2563`; the unavailable key at `:3175`, `:3253` on the moved path and `:3378` in
`_apply_refusal`, the disabled key at `:3195`), and a base model's licence alert by its
hub scope (`lifecycle.py:3466`, `:3581`). `_apply_upstream` visits every pinned `base_model` entry
(`lifecycle.py:3524-3527`). `_upstream_alert` carries an open alert forward and replaces its cause with
the latest one (`lifecycle.py:2805`, `:2834-2840`).

**Decision**: keep the keys (FR-003, FR-023). Before the base model loop, build for the target a map
from repository to the edges that name it, and add `edges` (each with relationship, origin, revision and
source key) to the cause given to `_upstream_alert` for `base_model_disabled`, `base_model_unavailable`
and a base model's `licence_changed`. Because the map holds every edge of the repository, the cause
written by the last entry visited still lists them all, so two pins of one repository give one alert
naming both edges (SC-003). The watch events of feature 002 get the edges of their entry in their
detail. Nothing else about the hub path changes.

## L7. Propagation from registered parents (FR-015 to FR-020)

**Decision**: a new pure module `src/model_dependabot/lineage/propagate.py` and one lineage pass at the
**end of `_check`** (`lifecycle.py:457`), so it runs inside `run_check`'s `try` and the review-F7 handler
(`lifecycle.py:409-425`) finishes the run, records every source's status and stores the overview if the
pass raises (review R5). The pass is not a source: it adds no overview row, is not selectable with
`--source`, never touches `target.tally` or `target.held` (which feed `_store_overview`,
`lifecycle.py:432-454`) and only appends its event ids to `target.summary["watch_events"]` (FR-027).

For each target, a breadth-first walk over resolved, `owner`-state registered-model edges, with a set of
visited (model id, version) so each version is visited at most once per check (FR-022). An imported
(`unverified`) registered-model edge carries nothing (FR-010a).

**Which of a parent's findings belong to the referenced version (C5, replaces P3)**: at a parent version
v, a parent alert is a candidate when

1. its item is in v's own stored inventory, `store.entries(parent, v)`: the cause's entry identifier
   (file hash, purl, DOI, hub dataset) is an identifier of v's entries, or, for a repository-scoped cause
   (`_repository_scoped`, `lifecycle.py:3572`), v has an entry in that repository (`_repository_of` and
   `_in_repository`, `lifecycle.py:3586`, `:3614`); and
2. its state is `open`, or `fixed` by a version later than v (`closed_by_version > v`). An alert fixed by v
   itself or earlier, or `dismissed`, `cleared` or `withdrawn`, does not travel: the source or the parent's
   owner settled the cause.

So a child pinning version 1 still inherits version 1's findings after version 2 fixes them, and a cause
first seen while the parent was at version 3 still reaches a child pinning version 1 when version 1's
inventory holds the item. `opened_in_version` and `current_version` play no part: they record when a
check saw the cause, not which versions hold it (review R6, `store.py:256-276`).

A candidate then travels when its kind travels on every edge of the path, by the closed matrix of FR-017
(`TRAVELS` in data-model.md). An `unspecified` edge passes only the all-yes rows (FR-019); an ambiguous
pair passes the intersection of its two types (US4 AS3).

Each finding that reaches the child is one watch event of the new kind `lineage_inherited` on the child's
current version, with `entry_identifier` `model:<parent id>@<parent version>/<cause key>`, so one parent
alert gives one event however many paths carry it (`record_watch_event` keeps one row per version, entry
and kind, `store.py:2023-2033`). Its detail lists every path (each edge: child, parent, relationship,
origin), `reach` (`direct` for one edge, `transitive` for two or more, FR-018), the parent's alert id,
kind, cause key, severity and state, and `relationship_unspecified` when any edge on a path is
`unspecified`. It is never an alert (C3), so `--fail-on` is unchanged (FR-027).

The same pass computes the lineage problems of the checked versions (L8) and adds them to the check's
payload and text (`lineage.problems`; `_check_text`, `cli.py:481-490`), with no exit code change (FR-021,
US4 AS1, review R4).

**Why a watch event needs no closure rules**: an inherited finding is an event, not an alert, so a type
change or a dropped parent produces no inherited event at the next check and closes nothing. The spec's
"close as `fixed` with the type change as evidence" therefore applies only to the child's own alerts; hub
findings travel on every type (FR-014), so a type change alone never closes one. Recorded here so the
edge case is not re-litigated.

## L8. Resolution and graph problems (FR-021, FR-021a, FR-022)

**Decision**: a pure module `src/model_dependabot/lineage/graph.py` builds the graph of every stored
edge in the store, resolving each registered-model reference by (model id, version) against
`model_versions` at the time of the call. It is called at registration, import, audit (read-only, in
memory) and check; nothing is written by resolution, so a reference that starts or stops resolving
changes the next result with no migration. Problems:

- `cycle`: a path of resolved references back to the same (model id, version); a reference to the
  same id and version is a cycle of length 1; one to another version of the same id is an ordinary edge
  (US4 AS6). Found by an iterative depth-first search; each cycle reported once, as its members rotated
  to start at the smallest (id, version).
- `duplicate_parent`: an edge row with `declared_count > 1`.
- `ambiguous_relationship`: one parent identity under two or more types for one child version.
- `parent_not_registered`: a registered-model reference that does not resolve (also shown as the
  edge's gap, US4 AS4).
- `merge_with_one_parent` (a note, not a problem; spec edge case): a version whose only `merged-from`
  edge is one.

None of them changes an exit code or stops registration (FR-021).

## L9. Discovery (FR-028, FR-029)

**Finding**: `_base_models` gives each name of a multi-name `base_model` the gap
`SEVERAL_BASE_MODELS` (`discover/model_card.py:102-119`, `discover/candidate.py:20`) and keeps the card's
`base_model_relation` as `identity["relation"]`. `compare.py:149-169` matches candidates against the one
`manifest.base_model`; `propose.py:161-172` writes one commented `[base_model]` block per candidate.

**Decision**: drop `SEVERAL_BASE_MODELS` (the constant is removed, with its documentation in feature
003's research and data-model left as history); map `finetune`, `adapter`, `merge`, `quantized` to the
four types (spec Assumptions), anything else or nothing to `unspecified`, and keep the raw value in the
candidate's origin (`{"file": "README.md", "key": "base_model_relation", "value": ...}`). `compare.py`
matches every candidate against every hub parent of `manifest.parents`. `propose.py` writes a commented
`[[parents]]` block; for `unspecified` it writes `# relationship = "<fine-tuned-from|adapter-for|
merged-from|quantized-from>"` so an uncommented block is still invalid until the owner chooses (a manifest
cannot hold `unspecified`, FR-002). Candidate status stays `declared-but-unverified` (FR-008).

## L10. Audit (FR-030)

**Decision**: `audit_report` (`assurance/audit.py:227`) gains `lineage: {edges: [...], problems: [...]}`
and `audit_text` (`reports.py:322`) a "Lineage" section. Each edge shows relationship, parent reference,
origin, claimed origin, state (`owner` or `unverified`, never `verified`), gap and, for a resolved
imported registered-model reference, the note "resolved by id and version only" (FR-010a). The audit's
read-only open (`store.py:631`) reads an absent `lineage_edges` table as no stored edges and synthesises
legacy edges (L2).

## L11. Fixtures and the equivalence baseline (SC-001)

**Decision** (review R7, R8; ruling C6): reuse feature 004's harness, not a new tool.

- The `[base_model]` scenarios are written as functions in a new module
  `tests/fixtures/equivalence/lineage_scenarios.py` that imports `Scenario`, `snapshot` and `run` from
  `tests/fixtures/equivalence/scenarios.py` (`Scenario` at `:49`, `snapshot` at `:295`, `run` at `:325`)
  and adds to each snapshot SC-001's other fields: entry identifiers and gaps (from `inventory_entries`)
  and each command's exit code. The scenarios mirror `tests/integration/test_check_base_model.py`,
  `tests/unit/test_lifecycle_base_model.py`, `tests/unit/test_lifecycle_base_model_moved.py` and
  `tests/integration/test_register.py`, each as a function a runner can call, so the replay is
  executable.
- `tools/record_equivalence_baseline.py` gains `--scenarios MODULE`, `--out FILE` and
  `--expect-src-tree TREE`, keeping its defaults for 004. It already refuses a dirty `src/`
  (`git status --porcelain --untracked-files=no -- src` in `main()`); with `--expect-src-tree` it also
  refuses unless `git rev-parse HEAD:src` equals the given tree, and writes `recorded_from` and `src_tree`
  into the baseline, as 004's does.
- The baseline `tests/fixtures/equivalence/pre-011-baseline.json` is recorded on the `main` 010 leaves
  (the base of 011's first pull request), not on a fixed commit; `--expect-src-tree` is that base's
  `HEAD:src`, written into validation.md.
- 010's FR-016 CLI baseline compares text, JSON and exit codes byte for byte. Each 011 pull request that
  legitimately changes CLI text or JSON (register and `inventory show` lineage, alert cause `edges`,
  `check` problems and inherited events, the audit section) re-records it with 010's recorder in the same
  pull request and lists every changed invocation and why (T060).

Hub answers reuse `tests/fixtures/hf_upstream/`. New manifests live in `tests/fixtures/lineage/`.

## L12. The constitution amendment (C4)

**Current text** (`.specify/memory/constitution.md:3-6`): "It watches what a model depends on (the code
libraries in its runtime environment, its weight files, the base model it was fine-tuned from, its
training datasets and known weaknesses of its model family)".

**Proposed text**: "It watches what a model depends on (the code libraries in its runtime environment,
its weight files, the models it was derived from by fine-tuning, adaptation, merging or quantisation, its
training datasets and known weaknesses of its model family)". No parenthesis is nested inside the
preamble's list (review R13).

**Version**: 1.0.3 to **1.1.0** (MINOR: "a principle or section is added or materially expanded",
Governance, `constitution.md:84-85`), `Last Amended` set to the date of the amending commit. The amendment
is proposed with this rationale, approved by the owner and recorded in the commit that makes it
(Governance). It lands in the first implementation pull request (T001), before any code widens the
watched scope, so the constitution never lags the code.

## Deferred (not in this feature)

Further relationship types, dataset lineage, hub parents' own parents, a graph view, the release gate
(#8) and bytes-level lineage (spec, Out of scope).

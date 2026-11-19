# Feature Specification: Multi-parent, Typed Model Lineage

**Feature Branch**: `spec/011-typed-model-lineage`

**Created**: 2026-11-19

**Status**: Draft

**Input**: User description: "Roadmap phase 4 (#9, part of RFC #6): multi-parent, typed model lineage. A
backwards-compatible list of parent models in the manifest, each with its own pinned revision; existing single
`[base_model]` manifests keep working. CycloneDX export and import keep every edge on a round trip. Each edge
keeps its origin and evidence; model-card text alone is not verified lineage. Findings travel only along known,
relevant edges, with transitive and unknown edges marked. Cycles, duplicate identities and ambiguous edges are
detected, without duplicate alerts. First relationship types (decision D5): `fine-tuned-from`, `adapter-for`,
`merged-from` and `quantized-from`."

**Tracking**: #9 (split out of #6 by decision D1). **Decision record**: `specs/decisions/2026-11-04-rfc-5-6.md`,
D5 (first relationship types) and D6 (an imported claim is a claim, not a measurement). **Builds on**: feature 001
(manifest, inventory, CycloneDX profile), feature 002 (base model watch and alert identity), feature 003
(discovery and `inventory audit`), feature 004 (check overview and `--fail-on` gate) and the two earlier features
whose text lives inside `specs/001-inventory-alerts/`: feature 005 (registration from a record; version origin
`record`, `src/model_dependabot/store.py:96`, `:106`) and feature 006 (stable evidence identity and one alert per
alias group; `store.py:18`, `specs/001-inventory-alerts/data-model.md:120`).

**Numbering**: this is feature 011. Numbers 005-009 were used by earlier merged work and 010 by the actionable
alert view (#7).

## Background

What the code does today, at `main` `aa32cd6`:

- **One parent, untyped.** The manifest accepts a single `[base_model]` table with only `hub` and `revision`
  (`src/model_dependabot/manifest.py:21`, `:24`, `:205-213`), held as one optional `BaseModelSpec`
  (`manifest.py:46-49`, `:74`). Registration turns it into at most one `base_model` inventory entry
  (`src/model_dependabot/inventory/build.py:469-479`, `:565-566`). Nothing records how the model relates to its
  base model. The constitution's preamble (`.specify/memory/constitution.md:3-4`) describes the watched scope
  as "the base model it was fine-tuned from": one parent, of one type (see Constitution Check).
- **Import already accepts several, export writes no type.** Export writes each `base_model` entry as one
  `pedigree.ancestors[]` component (`src/model_dependabot/inventory/cyclonedx.py:224-236`, `:283-284`,
  `:297-298`) and import reads every ancestor back (`cyclonedx.py:595-596`). So a model imported from a BOM can
  hold several `base_model` entries while a manifest can declare only one, and neither direction carries a
  relationship type. Confirmed by running `import_bom` at `aa32cd6` on a CycloneDX 1.7 document with two
  `pkg:huggingface` ancestors: two pinned `base_model` entries. No test under `tests/` covers more than one
  ancestor, so the plan adds one.
- **Discovery flags the gap.** Feature 003 reads a model card's `base_model` list and `base_model_relation`
  (`src/model_dependabot/discover/model_card.py:102-119`), gives every entry of a list of more than one the gap
  "several base models; multi-parent lineage is #9" (`src/model_dependabot/discover/candidate.py:20`,
  `model_card.py:108-109`; documented at `specs/003-inventory-assurance/research.md:136-137` and
  `specs/003-inventory-assurance/data-model.md:112`) and lists multi-parent lineage as out of scope
  (`specs/003-inventory-assurance/spec.md:352-354`). Comparison with a manifest assumes one base model
  (`src/model_dependabot/discover/compare.py:149-169`), and a proposed manifest writes one commented
  `[base_model]` block per candidate (`src/model_dependabot/discover/propose.py:166-171`).
- **Base model findings are keyed by repository.** `base_model_disabled` and `base_model_unavailable` are keyed
  by the base model's purl without a revision (`src/model_dependabot/lifecycle.py:2557-2563`, `:3174-3176`,
  `:3195`), so two pins of the same repository share one alert, and every pinned `base_model` entry is watched in
  turn (`lifecycle.py:3524-3527`). Findings never travel between registered models: a model's alerts come only
  from its own entries.

The gap: fine-tuning, adapters, merges and quantisation can each depend on more than one upstream model, with a
different revision for each, and the kind of dependency decides which upstream findings matter to the deployed
artifact. Today the tool cannot represent this, and anything it showed would rest on untyped, possibly
unverified links.

## Clarifications

Open questions are marked [NEEDS CLARIFICATION] in the requirements (FR-003, FR-017, FR-020), each with a
recommended answer. They are to be settled with `/speckit.clarify` or by the owner before planning.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Declare several typed parents in the manifest (Priority: P1)

A maintainer of a merged model, or of an adapter trained on one base model and evaluated on a quantised copy of
another, lists every parent model in the manifest. Each parent names its hub repository, its own pinned
revision and one of the four relationship types. Registration records one lineage edge per parent; existing
manifests with a single `[base_model]` register exactly as before.

**Why this priority**: every other part of the feature reads these edges. On its own it already makes the
inventory truthful for multi-parent models and puts every parent under the existing base model watch.

**Independent Test**: register a manifest with three parents of different types and revisions; `inventory
show` lists three edges with their types, revisions and origin `manifest`; a check watches all three
repositories. Register an unchanged single-`[base_model]` manifest; its inventory and check output match the
pre-feature output.

**Acceptance Scenarios**:

1. **Given** a manifest with two `merged-from` parents in different repositories, each with a commit,
   **When** the owner registers it, **Then** the inventory has two pinned parent edges, each with its own
   revision and type `merged-from`, origin `manifest`.
2. **Given** a manifest with an `adapter-for` parent without a revision, **When** it is registered, **Then** the
   edge is recorded as a gap "no revision" and registration still succeeds (as feature 001 treats every gap).
3. **Given** an existing manifest with one `[base_model]` table and no other change, **When** it is registered
   after this feature ships, **Then** entry identifiers, gaps, cause keys, the number, states and severities of
   alerts, watch event kinds and exit codes are identical to those before the feature; only the new edge fields
   listed in FR-003 differ.
4. **Given** a manifest with a parent whose relationship is not one of the four types, **When** it is
   registered, **Then** registration fails with exit code 1 naming the parent and the allowed types, as for any
   invalid manifest value.
5. **Given** a manifest that has both a `[base_model]` table and the new parent list, **When** it is registered,
   **Then** registration fails with exit code 1 and says to use one form.

---

### User Story 2 - Keep every edge on a CycloneDX round trip (Priority: P1)

An owner exports a model version's inventory to CycloneDX, hands it to another tool and imports it again, or
imports a BOM a supplier wrote. Every parent edge survives with its parent reference, revision, relationship
type and gap. An imported edge is always origin `import` and unverified, whatever the BOM says; the origin the
BOM claims is kept as evidence. A BOM that carries no type for an ancestor is imported with the relationship
marked unspecified, not guessed.

**Why this priority**: the constitution requires open-standard inventories (principle II); an edge that is lost
or retyped on export makes the lineage unauditable.

**Independent Test**: export a version with four parents (one of each type), import the document, export again:
both inventories have the same parent references, revisions, types and gaps; every imported edge has origin
`import`, is unverified and records the exported origin (`manifest`) as its claimed origin. Import a third-party
BOM with two untyped ancestors: two edges with relationship `unspecified` and origin `import`.

**Acceptance Scenarios**:

1. **Given** a version with one parent of each of the four types, **When** it is exported and imported,
   **Then** the imported version has four edges with the same repositories, revisions and types, each with
   origin `import`, unverified and claimed origin `manifest`, and the export validates against the official
   CycloneDX 1.7 schema.
2. **Given** a third-party BOM whose `pedigree.ancestors[]` carry no relationship property, **When** it is
   imported, **Then** each ancestor becomes an edge with relationship `unspecified` and origin `import`, marked
   unverified (D6).
3. **Given** a BOM whose relationship property holds a value outside the four types, **When** it is imported,
   **Then** the edge is kept with relationship `unspecified`, and the unrecognised value is recorded on the edge
   as evidence, not dropped.
4. **Given** a third-party BOM whose ancestors claim origin `manifest`, **When** it is imported, **Then** the
   edges are origin `import` and unverified, the claim is recorded as claimed origin only, and nothing about
   them is shown as owner-declared (FR-007, D6).

---

### User Story 3 - Findings travel only along known, relevant edges (Priority: P2)

When a parent is disabled, withdrawn from public access or changes its licence, the maintainer of each child is
told, through the edge that links them, with the edge's type. A finding that does not matter for a type of edge
(for example a scan finding in a parent's weight file, which a quantised child does not load) does not reach
the child. A finding that reaches the child over one edge is direct; when a parent is itself a registered model
with parents of its own, findings that come from further up travel over two or more edges, are marked transitive
and name the path (FR-018).

**Why this priority**: this is where lineage changes what the owner sees. It depends on US1's edges and must not
weaken the precision-first rule (constitution IV).

**Independent Test**: with recorded hub answers, a disabled `merged-from` parent raises one `base_model_disabled`
alert on the child citing the edge; a scan finding in a registered parent's weight file reaches an `adapter-for`
child and does not reach a `quantized-from` child; a grandparent's finding reaches the grandchild marked
transitive with the full path.

**Acceptance Scenarios**:

1. **Given** a child with a `fine-tuned-from` parent that the hub reports disabled, **When** a check runs,
   **Then** one `base_model_disabled` alert opens for the child, citing the hub evidence and the edge (type,
   revision, origin).
2. **Given** a child with two parents pinned to different revisions of one repository, **When** the hub reports
   the repository disabled, **Then** exactly one alert opens for the child, naming both edges (FR-024).
3. **Given** a child linked to a registered parent model by an `adapter-for` edge, **When** the parent has an
   open weight-file finding, **Then** the child shows that finding through the edge, as FR-017 decides.
4. **Given** a child linked by a `quantized-from` edge to a registered parent with an open weight-file finding,
   **When** a check runs, **Then** nothing is raised for the child from that finding.
5. **Given** grandparent → parent → child, all registered and linked, **When** the grandparent has a finding of
   a kind that travels on both edges, **Then** the child shows it as transitive, with the path
   grandparent → parent → child and each edge's type.
6. **Given** an edge with relationship `unspecified`, **When** its parent has a finding, **Then** the child sees
   only the findings that travel on every type, marked "relationship unspecified" (FR-019).

---

### User Story 4 - Detect cycles, duplicates and ambiguous edges (Priority: P2)

The maintainer is told when the declared lineage cannot be right: a model that is its own ancestor, the same
parent listed twice, the same parent with two different types, or an edge that names a registered model that
does not exist. None of these stops registration, and none of them produces duplicate alerts.

**Why this priority**: the graph is built from owner input and untrusted BOMs; detection keeps a bad graph from
silently producing wrong or repeated findings.

**Independent Test**: register two models whose parent references point at each other; `inventory audit` on
either reports a cycle naming both; a check opens no alert twice and stops propagation at the cycle.

**Acceptance Scenarios**:

1. **Given** model A with parent B and model B with parent A (registered references), **When** either is audited
   or checked, **Then** a lineage problem "cycle" is reported naming every model in the cycle, and propagation
   along the cycle stops after each model has been visited once.
2. **Given** a manifest listing the same repository at the same revision twice with the same type, **When** it
   is registered, **Then** one edge is kept and a lineage problem "duplicate parent" is recorded.
3. **Given** the same repository and revision listed with two different types, **When** it is registered,
   **Then** both edges are kept, a lineage problem "ambiguous relationship" is recorded, and propagation uses
   only the findings that travel on both types.
4. **Given** a registered-model reference to a model or version that does not exist in the store, **When** it is
   registered, **Then** the edge is a gap "parent not registered" and no finding travels along it.
5. **Given** that gap, **When** the referenced model version is registered later and a check or audit runs,
   **Then** the reference resolves, the gap is gone, and findings travel along the edge from that run on
   (FR-021a). This is how the mutual pair of AS1 forms a cycle: the first model registers with a gap, which
   resolves once the second is registered.
6. **Given** version 2 of a model with a `fine-tuned-from` edge to version 1 of the same model id, **When** it is
   audited or checked, **Then** no lineage problem is reported: continued training of one model is not a
   cycle.

---

### User Story 5 - Discovery and audit show lineage without trusting the model card (Priority: P3)

Discovery (feature 003) proposes one parent block per base model named in the model card, with the card's
`base_model_relation` translated to a type where it maps, and never presents the card's claim as verified.
`inventory audit` lists each edge with its origin and verification state, and the lineage problems from US4.

**Why this priority**: it closes the gap feature 003 flags and makes lineage auditable, but the earlier stories
deliver value without it.

**Independent Test**: run discovery on a project whose model card lists two base models with
`base_model_relation: merge`; the proposal has two commented parent blocks typed `merged-from`, each with the gap
"no revision" and status declared-but-unverified, and no "several base models" gap.

**Acceptance Scenarios**:

1. **Given** a model card with `base_model` as a list of two names, **When** discovery runs, **Then** each is a
   candidate parent and the gap "several base models; multi-parent lineage is #9" no longer appears.
2. **Given** a `base_model_relation` value that maps to a type, **When** discovery runs, **Then** the candidate
   carries the mapped type and the card's own value as its origin; a value that does not map leaves the type
   `unspecified` with the card value recorded.
3. **Given** any registered model, **When** `inventory audit` runs, **Then** each edge is listed with its type,
   origin (`manifest`, `import` or `discovery`), verification state and any lineage problem, and no edge is
   shown as verified on the strength of model-card or BOM text alone.

### Edge Cases

- A manifest that lists a parent with no `hub` and no registered-model reference: exit code 1, as for a
  `[base_model]` without `hub` today (`manifest.py:209-210`).
- Two parents in different repositories that the hub later reports as one (a rename redirects A onto B): two
  alerts, one per pinned repository, each naming its own edge, plus a `base_model_moved` watch event for A.
  Feature 002 keys a moved base model's findings by the pinned repository
  (`src/model_dependabot/lifecycle.py:3221-3222`), and FR-023 keeps that keying; this feature does not merge
  alerts on a redirect target.
- A `merged-from` model with a single parent: allowed, recorded, and noted in the audit as "merge with one
  parent".
- An `adapter-for` model with more than one `adapter-for` parent: allowed (an adapter may target several base
  models) and not flagged.
- A new model version drops a parent: that parent's alerts close as `fixed` for the new version, as when a new
  version no longer pins an item today (`README.md:171`).
- A new version changes only an edge's type: the parent's open alerts carry forward; findings that no longer
  travel on the new type close as `fixed` with the type change as evidence.
- A long chain of registered parents: propagation is bounded by the number of registered model versions and
  visits each version at most once per check (FR-022).
- A BOM with hundreds of ancestors: import is bounded by a limit set during planning; edges beyond it are a recorded
  gap, never silently dropped.
- A parent reference to the model's own id and the same version: a cycle of length one. A reference to another
  version of the same model id is allowed and is not a cycle (US4 AS6).

## Requirements *(mandatory)*

### Functional Requirements

**Manifest and inventory (US1)**

- **FR-001**: The manifest MUST accept a list of parent models, each with a hub repository and revision, or a
  reference to a registered model id and version (FR-016), plus one relationship type. Each parent has its own
  revision.
- **FR-002**: The relationship type MUST be one of `fine-tuned-from`, `adapter-for`, `merged-from` and
  `quantized-from` (D5). Any other value in a manifest MUST be an error with exit code 1. The value
  `unspecified` is internal: it marks an edge whose type is not known and cannot be written in a manifest.
- **FR-003**: A manifest with a single `[base_model]` table MUST keep working unchanged: the same keys are
  accepted, and entry identifiers, gaps, cause keys, the number, states and severities of alerts, watch event
  kinds and exit codes MUST be unchanged. The only allowed differences are the new edge fields (FR-006:
  relationship, origin, source location, recorded time, verification state), the edge type and origin in finding
  evidence (FR-009) and the new `model-dependabot:` properties on exported ancestors (FR-010). The edge's
  relationship is [NEEDS CLARIFICATION: what relationship does a legacy `[base_model]` edge record, and may
  `[base_model]` carry a type? Recommended: `unspecified`, never inferred; the constitution's "fine-tuned from"
  wording is not treated as a declaration. On typing, two options: (A, recommended) no new key: an owner who wants
  a type moves to the parent list; (B) an optional `relation` key in `[base_model]`, in which case FR-004, FR-023
  and FR-025 treat a typed `[base_model]` as a one-element parent list. Either way a legacy edge is hub-only, so
  FR-014 applies whatever its type and behaviour is unchanged.]
- **FR-004**: A manifest MUST NOT contain both `[base_model]` and the parent list; this MUST be an error with exit
  code 1 that names both forms.
- **FR-005**: A parent without a revision, or with a revision that is not a commit, MUST be recorded as a gap
  with the existing reasons ("no revision", "revision is not a commit"; `inventory/build.py:38-39`).
- **FR-006**: Each edge MUST record its origin (`manifest`; `record` for a version registered from a
  registration record, feature 005; `import`; or `discovery`), the source location (the manifest, record or BOM
  file and its SHA-256, or the model card key), when it was recorded and its verification state. An imported edge
  also records its claimed origin, the origin the BOM states, if any (FR-011).

**Evidence and verification (US2, US5)**

- **FR-007**: An edge declared in the owner's manifest or registration record MUST be shown as owner-declared. An
  edge read from an imported BOM MUST have origin `import` and be shown as unverified (D6), whatever origin or
  state the BOM claims. An edge read from a model card MUST remain a proposal and MUST
  NOT be registered unless the owner writes it into a manifest.
- **FR-008**: No edge MAY carry the verification state `verified` in this feature: nothing it reads establishes
  lineage from bytes. The allowed states are `owner-declared`, `unverified` and, for discovery candidates,
  `declared-but-unverified` (feature 003).
- **FR-009**: An edge's relationship type and origin MUST be part of the evidence cited by any finding that
  travels along it (constitution I).

**CycloneDX (US2)**

- **FR-010**: Export MUST write every edge as a `pedigree.ancestors[]` component, as today, with the relationship
  type, the edge's origin and any claimed origin in documented `model-dependabot:` properties (constitution II:
  CycloneDX 1.7 has no field for a relationship type), and MUST validate against the official 1.7 schema.
- **FR-010a**: An edge to a registered model (FR-016) MUST be written as an ancestor of type
  `machine-learning-model` without a purl, with `bom-ref` `model:<id>@<version>` (the form export uses for a
  model version) and `model-dependabot:` properties for the parent's model id and version. Import MUST read these
  as a registered-model reference and resolve it in the importing store (FR-021a); an unresolvable one becomes the
  gap "parent not registered". An ancestor with neither a `pkg:huggingface` purl nor these properties keeps
  today's gap "no Hugging Face purl" (`src/model_dependabot/inventory/cyclonedx.py:467-468`).
- **FR-011**: Export followed by import MUST reproduce every edge's parent reference (repository and revision, or
  model id and version), type and gap, and MUST record the exported origin as the edge's claimed origin. The
  imported edge's origin is `import` and its state `unverified` (FR-007): trust does not travel through a BOM.
  Import followed by export MUST reproduce the ancestors and their properties.
- **FR-012**: An imported ancestor without a relationship property, or with an unrecognised value, MUST become an
  edge of type `unspecified`, keeping any unrecognised value as recorded evidence.
- **FR-013**: The inventory profile contract MUST list the new properties, completing the custom property table
  of feature 001.

**Propagation (US3)**

- **FR-014**: The existing hub findings for a parent repository (`base_model_disabled`, `base_model_unavailable`,
  a base model's `licence_changed`, and the watch events `base_model_new_revision`,
  `base_model_new_version_pointer`, `base_model_moved`) MUST apply to every direct parent edge of every type,
  `unspecified` included, exactly as they apply to `[base_model]` today.
- **FR-015**: Findings MUST travel only along recorded edges. A model with no edges, or whose parents are hub-only,
  MUST receive no finding from any other registered model.
- **FR-016**: A parent edge MAY reference a registered model id and version in the same store. Only such edges
  can carry findings from the parent's own inventory, and only they can form a multi-level graph.
- **FR-017**: Which findings of a registered parent's own inventory travel to a child MUST depend on the edge type:
  [NEEDS CLARIFICATION: confirm the relevance matrix below. Recommended as shown: `adapter-for` is the only type
  that loads the parent's weights, and the child's own lock is what is deployed.] The matrix is closed: any
  finding kind not listed, including any kind added later, does not travel until the matrix lists it
  (constitution IV).

  | Parent's finding (alert kinds of `src/model_dependabot/store.py:52-67`) | fine-tuned-from | adapter-for | merged-from | quantized-from |
  | :-- | :-- | :-- | :-- | :-- |
  | `package_advisory` | no | no | no | no |
  | `weight_file_scan`, `hub_scan`, `format_policy`, `globals_policy` | no | yes | no | no |
  | `dataset_retracted`, `paper_retracted`, `dataset_removed`, `dataset_not_findable` | yes | yes | yes | yes |
  | `licence_changed` (a parent's dataset or its own base model) | yes | yes | yes | yes |
  | `base_model_disabled`, `base_model_unavailable` (the parent's own parents) | yes | yes | yes | yes |
  | Any watch event of the parent (`store.py:73-103`) | no | no | no | no |
  | Model-family advisories (constitution preamble): no such kind exists in the store today | no | no | no | no |
- **FR-018**: A finding is direct when its path to the child is one edge, whether to a hub parent or to a
  registered parent, and transitive when its path is two or more edges. Several parallel one-edge paths (FR-024)
  are direct. A one-edge finding from a registered parent's own inventory is direct and labelled "inherited from
  parent", naming the parent and edge. A transitive finding MUST name the full path with each edge's type.
- **FR-019**: Along an `unspecified` edge only findings that travel on all four types MAY travel, marked
  "relationship unspecified".
- **FR-020**: A finding that reaches a child from a registered parent MUST appear as
  [NEEDS CLARIFICATION: an alert on the child or a watch event? Recommended: a watch event on the child, marked
  inherited (direct or transitive, FR-018) and citing the parent's alert, never a second alert: the parent's alert is the confirmed match
  (constitution IV) and the parent's owner closes it. Direct hub findings (FR-014) stay alerts, as today.]

**Graph problems (US4)**

- **FR-021**: Registration, import, audit and check MUST detect and report cycles, duplicate parents (same
  identity, same type), ambiguous relationships (same identity, different types) and references to models or
  versions that are not registered. None of these MAY stop registration.
- **FR-021a**: Registered-model references MUST be resolved at registration and again at each check and audit. A
  reference that resolves stops being a gap from that run on and findings travel along it; one that stops
  resolving becomes the gap again. Cycles are judged on resolved references.
- **FR-022**: A cycle is a path of resolved references that returns to the same model id and version. A reference
  from one version of a model to another version of the same model id is not a cycle. Propagation MUST visit each
  model version at most once per check, so a cycle or a shared ancestor
  never produces repeated findings or unbounded work.
- **FR-023**: Edge identity MUST be the parent's identity (hub repository and revision, or registered model id
  and version) plus the relationship type. A parent's identity across revisions for alert purposes MUST stay the
  repository, as feature 002 keys it (`lifecycle.py:2557-2563`).

**Alert identity and compatibility (US1, US3)**

- **FR-024**: One cause MUST open at most one alert per child model, however many edges carry it; the alert MUST
  list every edge that carries it.
- **FR-025**: Moving a parent from `[base_model]` to the parent list in a new version, with the same repository,
  MUST carry its open alerts forward, not close and reopen them.
- **FR-026**: The documented alert closure rules (`README.md:165-175`) MUST hold for every edge: a version that
  no longer has the parent closes its alerts as `fixed`; a gap never counts as a fix.
- **FR-027**: `check` exit codes and the `--fail-on` gate of feature 004 MUST be unchanged; an inherited watch
  event (FR-020) MUST NOT count for `--fail-on`.

**Discovery and audit (US5)**

- **FR-028**: Discovery MUST propose one parent per base model named in the model card, drop the gap "several base
  models; multi-parent lineage is #9", and map the card's `base_model_relation` to a type where it maps, keeping
  the card's value as origin. A value that does not map MUST leave the type `unspecified`. An absent
  `base_model_relation` MUST give `unspecified`: the Hub's own inference of a relation is not read. The card has
  one `base_model_relation` value for the whole `base_model` list, so that one value MUST apply to every listed
  parent.
- **FR-029**: Comparison with an existing manifest MUST match each candidate parent against every manifest parent,
  not only one.
- **FR-030**: `inventory audit` MUST list each edge with its type, origin, verification state and lineage
  problems, in text and JSON.

### Key Entities

- **Parent reference**: a hub repository and revision, or a registered model id and version.
- **Lineage edge**: a child model version, a parent reference, a relationship type (one of four, or
  `unspecified`), an origin, a source location, when recorded, a verification state and an optional gap.
- **Lineage graph**: the edges of all registered model versions in one store; hub-only parents are leaves.
- **Lineage problem**: a cycle, duplicate parent, ambiguous relationship or unregistered reference, with the
  models and edges involved.
- **Propagated finding**: a parent's finding shown on a child, with the path of edges it travelled, direct (one
  edge) or transitive (two or more, FR-018), and whether it is inherited from a registered parent's inventory.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Every existing recorded test manifest with a single `[base_model]` gives 0 differences before and
  after the feature in entry identifiers, gaps, cause keys, alert count, alert states and severities, watch event
  kinds and exit codes; any other difference is one of the fields FR-003 allows.
- **SC-002**: Export then import of versions with 0, 1, 2 and 4 parents (one of each type, one of them a
  registered-model reference) reproduces 100% of parent references, revisions, types and gaps, records the
  exported origin as claimed origin on 100% of edges, gives origin `import` and state `unverified` on 100% of
  imported edges, and every export validates against the CycloneDX 1.7 schema.
- **SC-003**: For a cause carried by N edges to one child (N = 1 to 4), exactly 1 alert opens for that child.
- **SC-004**: For each cell of the FR-017 relevance matrix, a test shows the finding travelling or not
  travelling, so 0 findings reach a child along an edge type that the matrix excludes.
- **SC-005**: Fixtures with a cycle of length 1, 2 and 3, a duplicate parent, an ambiguous relationship and an
  unregistered reference each report exactly one lineage problem of the right kind; a fixture where version 2
  of a model references version 1 of the same model reports 0; and each check finishes with each model version
  visited at most once.
- **SC-006**: 0 edges carry the verification state `verified` in any output (FR-008).
- **SC-007**: `check` without `--fail-on` returns the same exit code as before for every case in the exit code
  table.

## Dependencies

- Features 001-004 (merged): the manifest, inventory, CycloneDX profile, base model watch, alert identity,
  discovery, `inventory audit` and the check overview and gate.
- Features 005 and 006 (merged; text inside `specs/001-inventory-alerts/`): the registration record and version
  origin `record` (FR-006, FR-007), and stable evidence identity with one alert per alias group, on which
  FR-024's one-alert-per-cause rule and FR-009's evidence rely.
- Feature 010 (actionable alert view, #7, drafted in parallel): **not a dependency**. 011 adds edge type and
  path to a finding's evidence; 010's advisory view, which shows "the known relationship to the model", can
  read them once both land. If 010 lands first, its relationship field is filled from 011's edges; if 011
  lands first, 010 consumes them. Neither specification needs the other to be built.
- Decision D6 governs the trust of imported edges (FR-007).
- Release gate (#8, phase 3) is out of scope; FR-027 keeps the existing gate unchanged.

## Constitution Check (for the plan)

- The constitution's preamble (`.specify/memory/constitution.md:3-4`) names "the base model it was fine-tuned
  from" as what is watched. Several parents of four types widen that scope, and the constitution supersedes
  conflicting specifications (Governance). The plan MUST propose a PATCH amendment of the preamble (for example
  "the models it was derived from"), or a MINOR one if the owner judges the scope materially expanded, or record
  the exception in Complexity Tracking. **This is the owner's decision**; this specification does not change the
  constitution.
- Principle IV (precision first) is why the FR-017 matrix is closed with "does not travel" as its default and why
  FR-020 recommends watch events for inherited findings.

## Assumptions

- Lineage is declared by people or by BOMs. No step in this feature derives or proves lineage from weight bytes,
  adapter configuration files or model-card text.
- Hub parents are leaves: their own parents are not looked up, because the only source for them is model-card
  text, which this feature does not treat as lineage.
- Feature 003's `base_model_relation` values map as `finetune` → `fine-tuned-from`, `adapter` → `adapter-for`,
  `merge` → `merged-from` and `quantized` → `quantized-from`. The Hugging Face model card documentation
  ("Specifying a base model", https://huggingface.co/docs/hub/model-cards) lists exactly these four values and
  one value for the whole `base_model` list.
- The relationship types are read with the child as subject: "the child is fine-tuned from / an adapter for /
  merged from / quantised from the parent".
- Out of scope: further relationship types (for example distilled-from), lineage of datasets, looking up hub
  parents' own parents, any visual graph view, the release gate (#8), any automatic change to a manifest and
  linking edges to the deployed artifact (bytes-level lineage, which RFC #6 phase 4's user story mentions).

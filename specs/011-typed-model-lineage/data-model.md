# Data Model: Multi-parent, Typed Model Lineage

**Feature**: [spec.md](spec.md) | **Plan**: [plan.md](plan.md) | **Research**: [research.md](research.md)

Everything here is additive. No table, column or entry kind of features 001 to 006 is removed or renamed;
`[base_model]` and the `base_model` inventory entry keep their shape.

## Relationship (code, not stored as a table)

`RELATIONSHIPS = ("fine-tuned-from", "adapter-for", "merged-from", "quantized-from")` (D5) and
`UNSPECIFIED = "unspecified"`, in `src/model_dependabot/lineage/__init__.py`. A manifest accepts only
`RELATIONSHIPS`; an edge may hold either. The child is the subject: "the child is fine-tuned from the
parent".

## Parent spec (extends Manifest)

`ParentSpec` in `src/model_dependabot/manifest.py`, beside `BaseModelSpec` (`manifest.py:46-49`).

| Field | Type | Rule |
| :-- | :-- | :-- |
| `index` | int | position in `[[parents]]`, or 0 for `[base_model]` |
| `form` | `"parents"` or `"base_model"` | which table it came from |
| `repo` | str or null | `owner/name`, parsed by `_hub` (`manifest.py:102-107`) |
| `revision` | str or null | as `[base_model]` |
| `model_id` | str or null | a registered model id |
| `model_version` | int or null | that model's version, `>= 1` |
| `relationship` | str | one of `RELATIONSHIPS`; `unspecified` only when `form = "base_model"` |

Exactly one of `repo` and `model_id` is set. `Manifest.parents: tuple[ParentSpec, ...]` is added after
`Manifest.base_model` (`manifest.py:74`); `base_model` stays as is.

## Lineage edge (new table `lineage_edges`)

One row per edge identity of a model version. Created with `CREATE TABLE IF NOT EXISTS` in `SCHEMA`
(`store.py:127`), so an older database gains it on open; immutable, like `inventory_entries`
(`store.py:440-443`).

| Column | Type | Rule |
| :-- | :-- | :-- |
| `edge_id` | integer primary key | |
| `model_id`, `version` | text, integer | `REFERENCES model_versions (model_id, version)` |
| `position` | integer | order of first declaration, from 0; unique per version |
| `parent_kind` | text | `CHECK IN ('hub', 'model')` |
| `parent_repo`, `parent_revision` | text | set when `parent_kind = 'hub'` (revision may be null) |
| `parent_model_id`, `parent_version` | text, integer | set when `parent_kind = 'model'` (version may be null) |
| `relationship` | text | `CHECK IN` the four types and `unspecified` |
| `relationship_recorded` | text | an unrecognised imported value, kept as evidence (FR-012); else null |
| `origin` | text | `CHECK IN ('manifest', 'record', 'import')` |
| `claimed_origin` | text | the origin an imported document stated; null otherwise |
| `source_file`, `source_sha256`, `source_key` | text | the input file's name, its SHA-256 and the table key (`parents[1]`, `base_model`, `ancestors[0]`) |
| `recorded_at` | text | the registration time |
| `state` | text | `CHECK IN ('owner', 'unverified')` (FR-008: no `verified`) |
| `gap_reason` | text | `no revision`, `revision is not a commit`, `no version`, `no Hugging Face purl` or null |
| `entry_identifier` | text | the `base_model` entry this hub edge produced (the pinned purl), else null |
| `declared_count` | integer | `>= 1`; above 1 is the "duplicate parent" problem |

Edge identity (FR-023) is a unique index on `(model_id, version, parent_kind, COALESCE(parent_repo,
''), COALESCE(parent_revision, ''), COALESCE(parent_model_id, ''), COALESCE(parent_version, 0),
relationship, CASE WHEN parent_repo IS NULL AND parent_model_id IS NULL THEN source_key ELSE '' END)`.
The last term keeps edges **without a parent identity** distinct (review R2): an imported ancestor with
neither a `pkg:huggingface` purl nor `parent-model`, and the import-limit gap edge, are keyed by their
`source_key` (`ancestors[i]`), so two such ancestors stay two edges, never fold into `declared_count = 2`
and are never a `duplicate_parent` or `ambiguous_relationship` (research L3)

**Derived, not stored**: `resolved` (a `model` edge whose `(parent_model_id, parent_version)` exists in
`model_versions` at read time, FR-021a) and the gap `parent not registered` when it does not. A legacy
version (no rows) reads as one edge per `base_model` entry: `relationship = 'unspecified'`, origin from
`model_versions.origin` (`store.py:149`), state `owner` for `manifest`/`record` else `unverified`,
`source_key = 'base_model'`.

**Store methods** (new, `store.py`): `add_edges(model_id, version, edges)` (inside `add_version`'s
transaction, `store.py:1371-1412`, so a version and its edges are recorded all or nothing);
`edges(model_id, version)` (stored or synthesised); `all_edges()` (for the graph);
`version_exists(model_id, version)`.

## Base model entry (unchanged)

Kind `base_model` (`store.py:49`), identifier `pkg:huggingface/<owner>/<name>@<commit>`
(`inventory/build.py:462-479`).

- **Registered from a manifest or record**: one entry per distinct hub (repository, revision), whatever
  the number of edges naming it.
- **Imported**: one entry per ancestor, as today, without de-duplication (`inventory/cyclonedx.py:595-596`);
  a purl-less ancestor stays a gap entry (`:466-468`). The one change: an ancestor carrying
  `model-dependabot:parent-model` gives **no entry** (research L4, review R1).
- Beyond 256 imported ancestors: one gap entry and one gap edge, reason
  `more than 256 ancestors; <N> not read`, written back on export as a gap ancestor (review R3).
- A registered-model edge never produces an entry, on registration or import.

## Lineage problem (computed, not stored)

| Field | Meaning |
| :-- | :-- |
| `kind` | `cycle`, `duplicate_parent`, `ambiguous_relationship`, `parent_not_registered` |
| `models` | the (model id, version) pairs involved; for a cycle, in path order |
| `edges` | the edge ids (or synthetic positions) involved |
| `detail` | for `ambiguous_relationship` the types; for `duplicate_parent` the count |

A note `merge_with_one_parent` is listed beside problems in the audit, not counted as one.

## Relevance matrix (code: `TRAVELS` in `lineage/propagate.py`)

A closed mapping from parent alert kind (`store.py:52-67`) to the set of edge types it travels on. A kind
absent from the mapping travels on none (FR-017).

| Alert kind | Travels on |
| :-- | :-- |
| `package_advisory` | none |
| `weight_file_scan`, `hub_scan`, `format_policy`, `globals_policy` | `adapter-for` |
| `dataset_retracted`, `paper_retracted`, `dataset_removed`, `dataset_not_findable` | all four |
| `licence_changed` | all four |
| `base_model_disabled`, `base_model_unavailable` | all four |

Watch events of the parent never travel. `unspecified` passes only kinds that travel on all four
(FR-019). A path passes a kind only if every edge on it does; an ambiguous pair passes the intersection.

**Which parent alerts are candidates at a referenced version v** (owner's ruling C5, research L7): an
alert of the parent model whose item is in `store.entries(parent, v)` (by entry identifier, or, for a
repository-scoped cause, by an entry of v in that repository), and whose state is `open` or `fixed` with
`closed_by_version > v` (`store.py:256-276`). `opened_in_version` and `current_version` are not used. A
child pinning version 1 still inherits version 1's findings after version 2 fixes them.

## Inherited finding (new watch kind `lineage_inherited`)

Added to `WATCH_KINDS` (`store.py:73-103`); an older database's `watch_events` is rebuilt by the existing
`_widen_watch_kinds` (`store.py:815-822`, `_rebuild_for_kinds` at `:833`), which already runs on every
open (`store.py:684`).

| Field | Value |
| :-- | :-- |
| `model_id`, `version` | the child and its current version |
| `entry_identifier` | `model:<parent id>@<parent version>/<parent cause key>` |
| `detail.parent_alert` | `{alert_id, model_id, kind, cause_key, severity, state}`; `state` is `open` or `fixed` (fixed by a version later than the referenced one) |
| `detail.reach` | `direct` (one edge) or `transitive` (two or more) (FR-018) |
| `detail.paths` | list of paths; each a list of `{child, parent, relationship, origin, edge_id}` from child upward |
| `detail.relationship_unspecified` | true when any edge on a path is `unspecified` (FR-019) |
| evidence | the parent alert's evidence ids, linked as the event's evidence (constitution I) |

Never an alert, so it does not count for `--fail-on` (FR-027).

## Alert cause (extended)

`base_model_disabled`, `base_model_unavailable` and a base model's `licence_changed` gain
`cause.edges`: every edge of the version that names the repository, each
`{relationship, origin, revision, source_key}` (FR-009, FR-024). Cause keys are unchanged
(`lifecycle.py:2557-2563`; unavailable `:3175`, `:3253`, `:3378`; disabled `:3195`; licence `:3466`). The `base_model_*` watch events of feature
002 gain `detail.edges` for their entry.

## Discovery candidate (extended)

A `base_model` candidate (`discover/model_card.py:102-119`) gains `identity.relationship` (a type or
`unspecified`). Its `origin` stays `{file, key: "base_model"}`, where the name was read; when the card
has a `base_model_relation`, its value is kept as the origin of the type (FR-028) in
`identity.relationship_origin = {file, key: "base_model_relation", value}` and as the pre-011
`identity.relation` (owner's ruling on review R9, 2026-11-20). The
gap `several base models; multi-parent lineage is #9` is removed (`discover/candidate.py:20`). Status
stays `declared-but-unverified`.

## Audit report (extended)

`lineage.edges[]`: `{edge_id, relationship, relationship_recorded, parent, origin, claimed_origin, state,
gap, resolved, note}`; `lineage.problems[]`: lineage problems; `lineage.notes[]`. `note` is "resolved
by id and version only" for a resolved imported registered-model reference (FR-010a).

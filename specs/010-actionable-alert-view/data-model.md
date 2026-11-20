# Data Model: An Actionable Alert View for Model Maintainers

**Feature**: [spec.md](spec.md) | **Plan**: [plan.md](plan.md) | **Research**: [research.md](research.md)

Nothing in this feature is stored. Every entity below is computed at read time from the existing tables
(`alerts`, `alert_evidence`, `evidence`, `model_versions`, `inventory_entries`, `claim_checks`,
`watch_events`, `global_exceptions`) and from one new package data file, `rule-texts.toml`. No table,
column, index or migration is added (plan, Storage).

## Advisory view

One per alert; the value of the `advice` key (contracts/cli.md). Field order is the order below and is
part of the contract (FR-003).

| Field | Type | Rule |
| :-- | :-- | :-- |
| `schema` | text | `advice/2`; bumped when a field is added, renamed or removed (`advice/1` was feature 010 as merged; `advice/2` adds `places[].marker`, issue #28) |
| `alert_id` | integer | the alert's id, repeated so the object can be read alone |
| `severity` | object | `{value, origin, note}`: the stored `severity` and `severity_origin` unchanged (FR-004); `note` is one fixed text per origin, matching `matching/severity.py:90-103`: `policy` "fixed by the service for this alert kind"; `database_specific` "as published by the source"; `cvss_v3` and `cvss_v4` "band of the source's CVSS vector"; `unknown` "the source gave no severity". A test refuses any other origin. No score, weight or rank field exists |
| `entry` | object | Affected entry, below |
| `relationship` | object or null | Relationship, below; null when `entry.status` is `unresolved` |
| `runtime_use` | object | Runtime use, below |
| `established` | array | Statements of kind `established`, in `evidence_id` order |
| `not_established` | array | Statements of kind `not_established`; the first is always the impact question |
| `limitations` | array | Statements of kind `limitation`, from the rule's `limitations` text |
| `claims` | array | Claim states of the resolved entry (feature 003), in `claim_verification` order |
| `impact` | text | always `impact undetermined` (FR-012) |
| `owner_decision` | object or null | Owner decision, below |
| `review_steps` | array | Review steps, below |
| `rule_doc` | text | the rule page path, as `alert_view` gives it (`reports.py:75`) |

## Affected entry

| Field | Type | Rule |
| :-- | :-- | :-- |
| `status` | text | `resolved` or `unresolved` |
| `reason` | text or null | for `unresolved`: one of `no stored version holds this identifier`, `the alert's cause does not name an identifier`, `the alert's model has no stored version` (research R2) |
| `kind` | text or null | `weight_file`, `package`, `base_model` or `dataset` (`store.py:49`) |
| `identifier` | text | the alert's `cause.identifier`, unchanged, also when unresolved |
| `matched_by` | text or null | `identifier` or `repository` (research R2) |
| `in_current_version` | boolean or null | whether the model's latest version holds it |
| `last_held_in_version` | integer or null | the highest version that holds it; equal to the latest version when `in_current_version` |
| `opened_in_version` | integer | the alert's stored value |
| `closed_by_version` | integer or null | the alert's stored value (`reports.py:85`): the fixing version of a `fixed` alert (spec, Edge Cases) |
| `places` | array | one item per (version, entry) that holds it, version descending, then in the order `store.entries` returns (`entry_id` ascending); items carry no `entry_id` |

Each item of `places`: `{version, origin, section, location, revision, marker}` where `origin` is the version's
stored origin (`manifest`, `record`, `import` or `null` for a version registered before feature 003,
shown as `legacy` in text), `section` is the manifest section that declares it (table below) or null for
an `import` version, `location` is the local path or `hf:<repo>/<file>` (as `_where`,
`lifecycle.py:1269-1274`) or null, `revision` the pinned hub revision or package version, and `marker`
(added in `advice/2`, issue #28) null for an entry that is not a package, else `{state, expression}`
with `state` `set`, `none` or `not_recorded` (Issue #28, below).

| Entry kind | `section` |
| :-- | :-- |
| `weight_file` | `[[weights]]` |
| `package` | `[environment] lock` |
| `base_model` | `[base_model]` |
| `dataset` | `[[datasets]]` |

## Relationship

One value from a fixed table keyed by (entry kind, alert kind), held in `rules.py` beside the registry.
A test fails if any alert kind of `store.ALERT_KINDS` has no row (FR-005, SC-001).

| Alert kinds | Entry kind | `value` | `steps_from_model` |
| :-- | :-- | :-- | :-- |
| `weight_file_scan`, `hub_scan`, `format_policy`, `globals_policy` | `weight_file` | `weight file of this model` | 1 |
| `package_advisory` | `package` | `package pinned in this model's environment lock` | 1 |
| `base_model_disabled`, `base_model_unavailable`, `licence_changed` | `base_model` | `declared base model` | 1 |
| `dataset_retracted`, `dataset_removed`, `dataset_not_findable`, `licence_changed` | `dataset` | `declared dataset` | 1 |
| `paper_retracted` | `dataset` | `paper cited by a declared dataset` | 2 |

Fields: `{value, steps_from_model, basis}`; `basis` is `{declared_by, origin, section, version}` where
`declared_by` is `owner` for a `manifest` or `record` version and `imported` for an `import` version
(never shown as the owner's own, FR-005), `legacy` when the origin is null. `version` and `section` are
those of the first item of `places`. For a weight file `value` is followed in text by `(local)` or
`(hub)` and its location.

## Runtime use

| Field | Type | Rule |
| :-- | :-- | :-- |
| `state` | text | `declared`, `observed` or `unknown` (FR-007); `observed` has no producer in this feature |
| `polarity` | text or null | `used` or `not_used` when `declared`; this feature only produces `not_used` |
| `basis` | object | `declared`: `{by, at, note, alert_id}` from this alert's dismissal; `unknown`: `{why}` = `no source observes runtime use and the owner has not declared it for this alert` |
| `context` | array | for `unknown`: other alerts of the model on the same identifier dismissed `not_used_at_runtime`, by alert id: `{alert_id, by, at}` (FR-008) |

## Statement

| Field | Type | Rule |
| :-- | :-- | :-- |
| `kind` | text | `established`, `not_established` or `limitation` |
| `text` | text | the statement |
| `evidence_ids` | array of integers | `established` only, never empty; every id is one of the alert's evidence rows (FR-009) |
| `evidence` | array | `established` only: `{evidence_id, source, url, retrieved_at, matched_identifier, redacted_fields}` per cited row |

## Claim

`{field, value, origin, verification, reason}` as `trust.claim_verification` returns it
(`assurance/trust.py:126-152`), for the resolved entry in `places[0]`'s version. Never repeated as a
statement (FR-013).

## Owner decision

`null`, or `{type, items}`. `type` `dismissal`: one item `{by, at, reason, note}` from `dismissed_by`,
`closed_at`, `dismissal_reason`, `note`. `type` `exception`: one item per `cause.excepted` entry,
`{global, exception_id, by, at, expires_on, reason, evidence_id}`, `reason` read with
`store.get_exception` (`store.py:1222`). Ordered by `exception_id`.

## Review step

`{number, text}`, numbered from 1, the text of the rule's `steps` with placeholders filled from the
alert's stored fields (research R4). The last step is the rule's `closes` text, introduced as
`How this alert closes:` (FR-015).

## Advice summary (`alerts ID --advice` only)

`{alerts_listed, note}`: `alerts_listed` counts the advisory views in the payload (the `alerts` and
`excepted` lists, FR-003); `note` is the empty-listing note for the `--state` filter (contracts/cli.md) when `alerts_listed` is 0,
otherwise null.

## Rule texts file

`src/model_dependabot/rule_texts/rule-texts.toml`:

```toml
version = 1

[MDB201]
limitations = "It does not prove the vulnerable code is reachable from the model. ..."
closes = "It is fixed when a new version pins an unaffected package version, ..."
fix = "Upgrade to a fixed version and register the new inventory. ..."
not_established = [
  "whether this alert affects model {model_id}",
  "whether the affected part of {package} is used by the model's code",
]
steps = [
  "Read the advisories {advisory_ids}: their affected ranges and fixed versions (`model-dependabot alert show {alert_id}`).",
  "...",
]
```

Rules enforced by the loader (`rules.py`) and `tests/unit/test_rule_texts.py`: every rule ID of
`RULES` has a table and no other table exists; every field present and non-empty; `steps` has at
least two items; the first `not_established` item is the impact question; only the placeholders of
research R4; `version` is an integer and a recorded SHA-256 of the file per version fails the test when
the text changes without a new version (as `tests/unit/test_safe_globals.py` does for the safe list).

## Orders (FR-003)

- `alerts ID --advice`: the order of today's payload, the `alerts` list (by severity, then alert id,
  `reports.py:125-127`) then the `excepted` list, under the same `--state` filter
  (`reports.py:130-148`). Watch events: no view.
- Inside a view: `places` version descending, then `store.entries` order; `established` by `evidence_id`;
  `not_established` impact first, then the rule's list, then the conditional items in the order of
  research R6; `claims` as `claim_verification`; `owner_decision.items` by `exception_id`;
  `runtime_use.context` by alert id.

## As built (T040)

- `claims` items are `{field, value, origin, verification, reason}`: `trust.claim_verification`
  names the first key `claim`; the view renames it `field`, as this document says.
- `rule-texts.toml` `steps` holds the steps before the closing one; the view and the rendered rule
  pages add the last step, `How this alert closes: ` followed by `closes`, so `closes` is written
  once. `not_established` needs two or more items (the impact question and at least one of the
  rule's own).
- (Superseded by review round 1, M10-R2, below.) A withdrawn or cleared alert's extra established
  statement reads
  `the source withdrew the cause (<source> at <retrieved_at>)` or `the source cleared the cause (…)`,
  citing the alert's last evidence row that is not an exception's.
- Conditional not-established items, in order: `which inventory entry this alert is about: <reason>`
  (unresolved); `whether the imported declaration of <identifier> is accurate: it is not the owner's
  own` (import version); `what the file holds: no local scan read this file; the hub's own verdict is
  the source` (hub weight file); `whether the file's bytes match their record: the bytes were not
  read in this place` (`weight_file_absent`); `whether <package> is installed where the model runs`
  (every package alert, ruling Q1). The package marker limitation is a second `limitations` item.
- Issue #28 (lock markers): each item of `places` also has `marker`: null for an entry that is not a
  package, else `{state, expression}` with `state` `set` (and the normalised `expression`), `none` (the
  lock line has no marker) or `not_recorded` (stored as null: written before #28, or imported without
  a readable `model-dependabot:marker` property, issue #34). Text
  appends `, marker <expression>`, `, no marker` or `, marker not recorded` to the place line (an
  `import` place adds `, declared by the import` after the first two, issue #34). When
  `places[0]`'s marker is `set`, the package's not-established item reads `whether <package> is
  installed where the model runs: the lock installs it only where `<expression>` holds, and this view
  does not evaluate the marker`. The marker limitation is listed only when `places[0]`'s marker is
  `not_recorded` ("This entry was recorded before environment markers were stored, …", or for an
  `import` version "This entry was imported from an inventory that records no readable environment
  marker for it, …") or no entry resolved ("No inventory entry was resolved for this alert, …").
- Review round 1 (M10-R2): the closing rows of a withdrawn alert are its rows whose detail records
  `withdrawn` (one per advisory of an alias group); of a cleared alert, the rows of the latest check
  run among its rows (the last row when none has a run). They are not also listed as
  `<source> reported …`; one statement cites them all:
  `the source withdrew the cause (<sources>, retrieved <times>; withdrawn <dates>)` or
  `the source cleared the cause (<sources>, retrieved <times>)`.
- Review round 1 (M10-R6): for an alert that is not open (fixed, withdrawn, cleared or dismissed)
  the review steps leave out every step that runs `alert dismiss` and add, before the closing step,
  `This alert is <state>, and only an open alert can be dismissed: the steps above are for reference
  if the same cause is raised again.` An excepted alert is stored open and keeps every step.

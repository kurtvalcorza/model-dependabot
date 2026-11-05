# Data Model: Evidence-Backed Dependency Discovery and Inventory Assurance

**Feature**: [spec.md](spec.md) | **Research**: [research.md](research.md)

Additions to the entities of features 001 and 002. Every addition is a new column or table, added on open
to an existing database (as feature 005's `registration_record_sha256` was); nothing is removed or
renamed, and existing rows keep their meaning.

## Model version (extended)

| Field | Type | Notes |
| :-- | :-- | :-- |
| `origin` | `manifest` \| `record` \| `import` \| null | How the version was registered. Set by `register`, `register --from-record` and `import` from now on. On open, a row with `registration_record_sha256` and no origin becomes `record`; other old rows stay null (legacy, research A2) |

## Inventory entry (extended)

| Field | Type | Notes |
| :-- | :-- | :-- |
| `format_origin` | `bytes` \| `name` \| `record` \| `import` \| null | Weight files only: where `format` and `can_run_code` came from. `bytes`: classified from the local file's bytes (manifest local weights, and imported local weights present at import). `name`: classified by file name from the owner's manifest (hub weights). `record`: from a registration record. `import`: taken from an imported document. Null for other kinds and for legacy rows |

**Rule (FR-001, FR-002)**: a weight entry's code-free claim is *owner-trusted* when `format_origin` is
`bytes`, `name` or `record`. It *needs confirmation* when `format_origin` is `import`, or when it is null
and the version's `origin` is null (legacy) or `import`.

## Claim check (new)

One confirmation attempt of one entry's code-free claim in one check run (or at import).

| Field | Type | Notes |
| :-- | :-- | :-- |
| `claim_check_id` | integer | key |
| `model_id`, `version` | text, integer | the version checked |
| `entry_identifier` | text | the entry's pinned identifier (`sha256:…`) |
| `claim` | `code_free` \| `identity` | which claim was checked: the code-free format, or the pinned hash at the pinned revision |
| `run_id` | integer \| null | the check run; null when made at import |
| `outcome` | `confirmed` \| `contradicted` \| `unreadable` | see transitions |
| `measured_format` | text \| null | the class the bytes show (`safetensors`, `gguf`, `onnx`, `pickle`, `pytorch-zip`, `unknown`) |
| `measured_can_run_code` | boolean \| null | |
| `reason` | text | for `contradicted` and `unreadable`: what was seen or why it could not be read |
| `evidence_id` | integer | evidence row: the JSON summary of the read (research A4) |
| `checked_at` | timestamp | |

**State per entry** (latest row decides):

```text
needs confirmation ──(read, code-free)──────────────▶ confirmed     (final for the version)
needs confirmation ──(read, not code-free / hash ≠)─▶ contradicted  (final for the version)
needs confirmation ──(401/403/404, too large)───────▶ unreadable ──(next run)──▶ read again
needs confirmation ──(network or 5xx, cut off)──────▶ no row; the source fails (exit 2)
```

A final outcome is never read again for that version (FR-002b). A new version starts with no rows. A
weight entry can have one row sequence per `claim`.

**Rule (FR-004)**: an entry counts as a code-free file beside the others under the strict policy only if
it is pinned, `can_run_code` is false, and its claim is owner-trusted or its latest claim check is
`confirmed`.

## Check run (extended)

No new column. `format-check` is one more source name in `sources`, with status `ok`, `failed: reason` or
`skipped`, as for the existing sources.

## Watch event (extended)

| Kind | When | Detail |
| :-- | :-- | :-- |
| `format_claim_contradicted` | a claim check is `contradicted` | the claimed format and `can_run_code`, the measured class or the differing hash, the claim's origin, the evidence |
| `format_claim_unreadable` | a claim check is `unreadable` (once per version and reason) | the reason; the claim stays unverified |

## Alert (extended)

`format_policy` keeps its kind, cause key and severity. Its `cause` gains, when unverified or contradicted
claims exist in the version, `unconfirmed_claims`: a list of `{identifier, location, outcome, origin}`, and
`rule: "imported code-free claims count only once confirmed"` (FR-005). A `format_policy` alert closes as
`cleared` when a later run confirms a code-free file in the version, with the claim check's evidence.

## Audit report (new, output only, not stored)

| Field | Notes |
| :-- | :-- |
| `model_id`, `version`, `produced_at`, `stale_after_hours` | |
| `summary` | counts: `alerts_open`, `watch_events`, `entries`, `verified`, `declared_but_unverified`, `conflicting`, `unavailable`, `gaps`, `uncheckable`, `sources_failed`, `sources_stale`, `sources_not_checked`; and `checked` (boolean) |
| `findings` | `{state: "not_yet_checked" \| "checked", alerts: [...], watch_events: [...]}` in the shapes `alerts` already prints |
| `assurance.entries[]` | `{kind, identifier, location, status, gap_reason, claims: [{claim, value, origin, verification}]}`; `claim` is `format`, `can_run_code`, `sha256` or `revision`; `verification` is `owner`, `measured`, `confirmed`, `unverified` or `contradicted` |
| `assurance.undeclared_kinds[]` | kinds the inventory has none of: `environment`, `base_model`, `datasets`, `weights` |
| `coverage.sources[]` | `{source, relevant_entries: [identifier or location, …], last_run_id, last_finished_at, status, age_hours, stale}` |
| `coverage.uncheckable[]` | `{kind, identifier, location, reason}` |
| `statement` | fixed text: "No alerts is not evidence that the inventory is complete or the model is safe." |

**Entry status** (research A12): `verified`, `declared-but-unverified`, `conflicting` or `unavailable`.

The audit reads the database read-only and never upgrades it; on an older database the fields above that
this feature adds take their defaults (research A12, Read-only open).

## Candidate dependency (new, output only)

| Field | Notes |
| :-- | :-- |
| `kind` | `package`, `weight_file`, `base_model`, `dataset`, `licence`, `environment` |
| `identity` | per kind: `{name, version, hashes}`, `{path, sha256, size, format, can_run_code}`, `{hub_repo, revision}`, `{doi}` or `{hub_repo}`, `{licence, spdx}`, `{lock}` |
| `origin` | `{file, line}` or `{file, key}`; for upstream answers `{source, url, retrieved_at}` |
| `status` | `verified` (measured: a local file's hash and class), `declared-but-unverified`, `conflicting` or `unavailable` |
| `observed_at` | timestamp of the read |
| `gaps[]` | reasons: `no revision`, `not locked`, `no exact version`, `outside the project`, `several base models; multi-parent lineage is #9`, `not a registry package`, … |
| `manifest` | when `--manifest` is given: `matches`, `missing_from_manifest` or `conflicts` (with the manifest's value) |
| `proposed_revision` | upstream mode only: `{revision, observed_at, label: "head at observation time, not established as the training revision"}` |

## Discovery result (new, output only)

`{project, observed_at, upstream: bool, candidates[], declared_not_seen[], skipped[{path, reason}],
limits{...}, output: {path, written} | null, statement}`, where `declared_not_seen` lists manifest entries
discovery did not find and `statement` is the FR-023 text.

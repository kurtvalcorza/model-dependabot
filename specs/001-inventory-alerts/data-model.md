# Data Model: Model Inventory with Library and Weight-File Alerts

Entities from the spec's Key Entities, with fields, rules and state changes. Storage is SQLite
([research.md](research.md) R6); names below are logical.

## Model

| Field | Rule |
| :-- | :-- |
| `model_id` | Stable text identifier chosen by the owner, unique |
| `name`, `owner` | Free text |
| `created_at` | UTC timestamp |

Has many **Model versions**, numbered 1, 2, 3 in registration order.

## Model version

| Field | Rule |
| :-- | :-- |
| `model_id`, `version` | Together unique; `version` increases by 1 per registration |
| `registered_at` | UTC timestamp |
| `manifest_sha256` | Hash of the registration input (TOML manifest or imported inventory) |
| `inventory` | The CycloneDX 1.7 document, stored as recorded; never changed (FR-005) |

## Inventory entry

One dependency of one model version.

| Field | Rule |
| :-- | :-- |
| `kind` | `weight_file`, `package`, `base_model` or `dataset` |
| `identifier` | Exact identifier: file SHA-256; package `pkg:pypi/name@version`; base model `pkg:huggingface/owner/name@commit`; dataset DOI |
| `pinned` | True only if the identifier is exact (FR-003); false means a **gap** |
| `gap_reason` | Required when `pinned` is false (for example "no exact version", "no hash", "no revision") |
| weight file extras | `location` (path or hub URL), `size`, `format`, `can_run_code` (FR-002) |
| package extras | `name` (normalised), `version`, `hashes` |

Gaps are never matched against advisories or scanned.

## Advisory

A cached copy of a published record.

| Field | Rule |
| :-- | :-- |
| `advisory_id`, `aliases` | From the source (OSV `id`, `aliases`) |
| `source` | For example `osv.dev` |
| `modified`, `withdrawn` | From the source; `withdrawn` empty unless withdrawn |
| `severity`, `severity_origin` | Per research R3 |
| `affected` | Ranges and versions as published |
| `evidence_ref` | The stored raw response |

## Check run

| Field | Rule |
| :-- | :-- |
| `run_id`, `started_at`, `finished_at` | |
| `scope` | One model version, or all current versions |
| `sources` | Per source: `ok`, `failed` (with reason) or `skipped` |

A source that failed in a run cannot close or change any alert in that run (FR-016).

## Evidence

| Field | Rule |
| :-- | :-- |
| `source`, `url` | Where the fact came from |
| `retrieved_at` | UTC timestamp |
| `matched_identifier` | The exact inventory identifier matched (FR-019) |
| `body_sha256` | Hash of the stored raw response (content-addressed file) |
| `detail` | For example the local range recomputation, or the scanner's dangerous globals |

## Alert

| Field | Rule |
| :-- | :-- |
| `alert_id` | |
| `model_id`, `opened_in_version`, `current_version` | The version that first showed the cause, and the latest version still showing it |
| `kind` | `package_advisory`, `weight_file_scan` or `hub_scan` |
| `cause_key` | `kind` plus advisory id plus normalised package name, or `kind` plus file SHA-256 |
| `severity` | |
| `state` | `open`, `fixed`, `dismissed` or `withdrawn` |
| `closed_at`, `closed_by_version`, `dismissal_reason`, `dismissed_by`, `note` | As the state requires |
| `evidence` | One or more Evidence records; earlier evidence is kept when the advisory changes |

Rules:

- At most one `open` alert per `model_id` and `cause_key` (FR-010).
- An alert is raised only on a confirmed match: for packages, OSV's match and the local recomputation
  agree (research R2); for weight files, a `dangerous` scan result or an explicit hub "unsafe" verdict
  for the matching hash (R4, R5).

### State transitions

```text
            confirmed match
 (none) ───────────────────────▶ open
 open ── new version without the cause ─────────▶ fixed      (closed_by_version = that version)
 open ── advisory withdrawn ────────────────────▶ withdrawn  (withdrawal kept as evidence)
 open ── person dismisses with a listed reason ─▶ dismissed  (reason, person, time recorded)
 open ── new version still has the cause ───────▶ open       (current_version moves forward)
 fixed / dismissed / withdrawn ── cause found again in the current version ──▶ a new open alert
```

Dismissal reasons (fixed list): `not_used_at_runtime`, `risk_accepted`, `false_positive`,
`fix_not_available`, plus an optional note.

## Watch event

| Field | Rule |
| :-- | :-- |
| `model_id`, `version`, `entry identifier` | |
| `kind` | `pickle_format`, `scan_suspicious`, `hub_scan_unknown`, `advisory_unmatched`, `hash_mismatch` |
| `evidence` | As for alerts |
| `first_seen`, `last_seen` | One record per cause, updated on each run |

Watch events are shown to the owner; they never become alerts by repetition.

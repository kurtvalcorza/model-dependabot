# Data Model: Model Inventory with Library and Weight-File Alerts

Entities from the spec's Key Entities, with fields, rules and state changes. Storage is SQLite
([research.md](research.md) R6); names below are logical.

## Model

| Field | Rule |
| :-- | :-- |
| `model_id` | Stable text identifier chosen by the owner, unique |
| `name`, `owner` | Free text |
| `format_policy` | `default` or `strict` (FR-021); defaults to `default` |
| `format_policy_set_by`, `format_policy_set_at` | Who set the current policy and when (UTC); the evidence for a `format_policy` alert (constitution I) |
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
| weight file extras | `location` (path or hub URL), `size`, `format`, `can_run_code` (FR-002); a hub-hosted file also has `hub_repo`, `hub_revision` and `hub_file` ([inventory profile](contracts/inventory-profile.md)) |
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
| `detail` | For example the local range evaluation (and why a range could not be read), or the scanner's dangerous globals |

For a `format_policy` alert the owner's recorded policy is the primary source (constitution I): `source`
is `format-policy`, `url` is empty, `retrieved_at` is the check time, `matched_identifier` is the file's
SHA-256, `detail` holds the file's format, the policy value (`strict`), who set it and when
(`format_policy_set_by`, `format_policy_set_at`), and `body_sha256` is the hash of that record as stored.

## Alert

| Field | Rule |
| :-- | :-- |
| `alert_id` | |
| `model_id`, `opened_in_version`, `current_version` | The version that first showed the cause, and the latest version still showing it |
| `kind` | `package_advisory`, `weight_file_scan`, `hub_scan` or `format_policy` |
| `cause_key` | For `package_advisory`: `kind` plus advisory id plus normalised package name; for `weight_file_scan`, `hub_scan` and `format_policy`: `kind` plus file SHA-256 |
| `severity` | `package_advisory`: per research R3; `weight_file_scan`: `HIGH`; `hub_scan`: `HIGH`; `format_policy`: `MODERATE` |
| `severity_origin` | `package_advisory`: per research R3; `weight_file_scan`, `hub_scan` and `format_policy`: `policy` (a fixed rule of this service, not a value from the source) |
| `state` | `open`, `fixed`, `dismissed`, `withdrawn` or `cleared` |
| `closed_at`, `closed_by_version`, `dismissal_reason`, `dismissed_by`, `note` | As the state requires |
| `evidence` | One or more Evidence records; earlier evidence is kept when the advisory changes |

Rules:

- At most one `open` alert per `model_id` and `cause_key` (FR-010): one open alert per model, advisory
  and package, carried forward across versions.
- An alert is raised only on a confirmed match: for packages, OSV's match and the local consistency
  check on the same OSV record agree (research R2); for weight files, a `dangerous` scan result or an explicit hub "unsafe" verdict
  for the matching hash (R4, R5); under the `strict` format policy, a code-capable file with no
  code-free file beside it in the same version (FR-021), with the policy as evidence.
- An alert closes as `cleared` (FR-023) when the source itself no longer shows the cause, with that
  observation as evidence: an advisory whose affected ranges are narrowed so the pinned version is no
  longer affected (OSV's match and the local evaluation both agree it is unaffected), or a hub verdict
  for the matching hash that changes from unsafe to an explicit safe verdict, or the owner changing
  the model's format policy from strict to default, which clears its `format_policy` alerts at the
  next check with the recorded policy (who set it and when) as evidence (constitution 1.0.2). A missing, pending or
  unrecognised hub verdict changes nothing, and nor does a source that failed in the run (FR-016).
  `withdrawn` stays for withdrawn advisories.

### State transitions

```text
            confirmed match
 (none) ───────────────────────▶ open
 open ── new version without the cause ─────────▶ fixed      (closed_by_version = that version)
 open ── advisory withdrawn ────────────────────▶ withdrawn  (withdrawal kept as evidence)
 open ── advisory ranges narrowed past the pinned version (OSV and local agree) ──▶ cleared  (new response kept as evidence)
 open ── hub verdict for the matching hash changes from unsafe to explicit safe ──▶ cleared  (new verdict kept as evidence)
 open ── format policy changed from strict to default ──▶ cleared  (recorded policy kept as evidence)
 open ── person dismisses with a listed reason ─▶ dismissed  (reason, person, time recorded)
 open ── new version still has the cause ───────▶ open       (current_version moves forward)
 open ── new version names the item only in a gap ─▶ open, unchanged (a gap is not removal; FR-016)
 open ── advisory updated (severity, fixed version) ──▶ open (new values shown; earlier evidence kept)
 fixed / dismissed / withdrawn / cleared ── cause found again in the current version ──▶ a new open alert
```

Which identity each kind is compared at, and which source can clear or withdraw it, is in the
identity and clearance table of `specs/002-upstream-watch/data-model.md`. `withdrawn` needs explicit
withdrawal evidence (an OSV record marked withdrawn); a cause that is merely no longer listed is `cleared`.

Dismissal reasons (fixed list): `not_used_at_runtime`, `risk_accepted`, `false_positive`,
`fix_not_available`, plus an optional note.

## Watch event

| Field | Rule |
| :-- | :-- |
| `model_id`, `version`, `entry identifier` | |
| `kind` | `pickle_format`, `scan_suspicious`, `scan_incomplete`, `hub_scan_unknown`, `advisory_unmatched` or `hash_mismatch` |
| `evidence` | As for alerts; for `scan_incomplete`, `detail` holds the scanner and the byte position it reached (FR-022) |
| `first_seen`, `last_seen` | One record per cause, updated on each run |

Watch events are shown to the owner; they never become alerts by repetition.

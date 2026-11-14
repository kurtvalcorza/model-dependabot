# Data Model: Scan Exceptions, Strict Globals, Check Overview and an Opt-in Gate

**Feature**: [spec.md](spec.md) | **Research**: [research.md](research.md)

Additions to the entities of features 001 to 003. Every addition is a new table or column, added on open
to an existing database inside one transaction per step (research S2), except one rebuild of `alerts`
that widens its `kind` check and keeps every row and id. Nothing is removed or renamed, and existing
rows keep their meaning: every existing model reads globals policy `default`, every existing alert
reads not excepted.

## Global exception (new)

An owner's acceptance of one global in one exact file, wherever that file is registered (FR-001,
FR-002).

| Field | Type | Notes |
| :-- | :-- | :-- |
| `exception_id` | integer | key |
| `module`, `name` | text | the global exactly as the scanner reports it (research S9, D7); neither empty, no `*`, neither containing the lower-case string `unknown`, compared case-sensitively (research S14) |
| `sha256` | text | the file's SHA-256, 64 lower-case hexadecimal digits, without the `sha256:` prefix |
| `reason` | text | required, not blank |
| `accepted_by` | text | required, not blank |
| `recorded_at` | timestamp | |
| `expires_on` | date (`YYYY-MM-DD`) \| null | optional; not before today (UTC) when recorded |
| `revoked_at`, `revoked_by`, `revoke_reason` | timestamp, text, text \| null | all set together, once; reason and name required |
| `evidence_id` | integer | evidence row (source `exception`, URL `exception:<id>`): the record above as canonical JSON, the evidence linked to alerts it covers. A revocation adds a second evidence row with the same source and URL (the revocation as canonical JSON); a release links it to the alert |

**State** (derived at a time *t*, never stored):

```text
recorded ──(t on or before expires_on, or no expiry)──▶ active
active   ──(t after expires_on, 00:00Z the next day)──▶ expired   (final)
active   ──(exception revoke)─────────────────────────▶ revoked   (final)
```

**Rules**: a second exception for the same `module`, `name` and `sha256` is refused while one is
active. Rows are never deleted; a trigger refuses any update except setting the three revocation
fields from null. *Applies to*: the model versions with a pinned weight entry whose identifier is
`sha256:<sha256>`. *In use*: the latest file scan of that hash lists the global.

## Globals policy (extends Model)

| Field | Type | Notes |
| :-- | :-- | :-- |
| `globals_policy` | `default` \| `strict` | `NOT NULL DEFAULT 'default'`, separate from `format_policy` (FR-006) |
| `globals_policy_set_by` | text \| null | who set it; null until first set |
| `globals_policy_set_at` | timestamp \| null | |

## File scan (new)

What one applied static scan of a file's bytes saw, so exceptions and the strict policy can be applied
at any later check without reading the file (research S2, S11).

| Field | Type | Notes |
| :-- | :-- | :-- |
| `file_scan_id` | integer | key |
| `sha256` | text | the bytes scanned (the pinned identifier, which the scan's two hashes matched) |
| `scanner`, `scanner_version` | text | `picklescan`, `1.0.5` |
| `complete` | boolean | as `ScanReport.complete` |
| `globals` | JSON | `[{module, name, safety}]`, `safety` the scanner's label: `innocuous`, `suspicious` or `dangerous` |
| `scanned_at` | timestamp | the scan time (a recorded scan's own time for a registration record) |
| `run_id` | integer \| null | the check run; null for a scan recorded at registration |
| `evidence_id` | integer | the scan's evidence row (the report as JSON, source `picklescan`). Every applied scan has one, a clean scan included; the row of the hash's latest file scan is reused when the new scan is the same evidence (`same_evidence`: source, URL and content) |

The latest row per `sha256` (by `file_scan_id`) decides. A scan that stopped on a hash mismatch or a
read error writes no row.

## Safe list (file, not stored)

`src/model_dependabot/safe_globals/safe-globals.toml`:

| Field | Notes |
| :-- | :-- |
| `version` | integer, bumped on every change to `entries` |
| `[[entries]]` | `{module, name, why, added_in}`; exact, unique, no `*`, no module or name that contains the lower-case string `unknown` (compared case-sensitively, as the scanner does) (FR-009) |
| `[[changes]]` | `{version, date, summary}` |

The loader also computes the SHA-256 of the file as read, which alerts cite.

## Alert (extended)

| Change | Notes |
| :-- | :-- |
| kind `globals_policy` | new; severity `MODERATE`, `severity_origin: policy`; the `alerts` table is rebuilt once so its `kind` check accepts it; the rebuild recreates the partial unique index `one_open_alert_per_cause` (`WHERE state = 'open'`) in the same transaction |
| column `excepted_at` | timestamp \| null. Set when every global that raised a `weight_file_scan` alert is covered by an active exception; cleared when one stops being active. Stored `state` stays `open` (research S4) |
| view `state` | `excepted` when stored state is `open` and `excepted_at` is set; otherwise the stored state |
| view `rule_id`, `rule_doc` | from the rule registry, on every alert in every view (FR-014) |
| cause `reopens` | on an alert opened for a cause whose latest alert was dismissed, because the check brought new evidence: `{alert_id, dismissed_by, dismissal_reason, closed_at}` (FR-020, research S13) |
| `weight_file_scan` cause | gains `excepted: [{global, exception_id, accepted_by, recorded_at, expires_on}]` and, after a release, `released: [{global, exception_id, why: "revoked" \| "expired", at}]` |

**`globals_policy` cause** (key `globals_policy:sha256:<hex>`, built like every weight alert's key by `weight_cause_key`, research S7):

```json
{
  "identifier": "sha256:…",
  "location": "weights/pose.pt",
  "format": "pytorch-zip",
  "unlisted": ["model_dependabot_fixture.layers.CustomLayer", "os.system"],
  "excepted": [{"global": "…", "exception_id": 3, "accepted_by": "Owner",
                "recorded_at": "2026-11-13T09:00:00Z", "expires_on": null}],
  "safe_list_version": 1,
  "safe_list_sha256": "…",
  "policy": "strict",
  "set_by": "Owner",
  "set_at": "2026-11-13T09:00:00Z",
  "scan": {"scanner": "picklescan", "scanner_version": "1.0.5", "complete": true,
           "scanned_at": "2026-11-13T09:05:00Z"}
}
```

`unlisted` holds every global the scan reported, whatever the scanner's label, that is neither on the
safe list nor excepted, so a dangerous global is listed here and in its `weight_file_scan` alert (D3).
The alert's `globals-policy` evidence record carries the sorted `unlisted` and `excepted` lists, so a
change in either (an exception released, say) is new evidence for a dismissed alert (research S7, S13).
A global whose module or name contains the lower-case string `unknown` (compared case-sensitively, as the scanner does) is never excepted or safe-listed (research S14).

**Dismissed alerts of every kind** (FR-020). New evidence is an observation with no match among the
dismissed alert's evidence (same source, URL, matched identifier and matching key), or a higher
severity. The matching key (`store.matching_key`) is the canonical hash of the body after removing the
source's `VOLATILE_FIELDS`, dotted paths into the JSON object (research S13): `downloads`, `likes` and
`lastModified` for the hub's answers (stored sources `huggingface.co` and `hf-hub`), `stats` for Zenodo,
`message.indexed` and `message.is-referenced-by-count` for Crossref and eleven
`data.attributes.*Count` and `*OverTime` keys for DataCite. Stored evidence stays whole:

```text
dismissed ──(cause found again, no new evidence)──▶ dismissed, held (run summary dismissals_held)
dismissed ──(cause found again, new evidence)─────▶ dismissed; a new open alert with cause.reopens
```

**Transitions of a `globals_policy` alert**:

```text
(none) ──(strict, unlisted not empty)─────────────────▶ open
open   ──(strict, unlisted changed, still not empty)──▶ open, cause and evidence updated
open   ──(policy default)─────────────────────────────▶ cleared, note "cleared: policy"
open   ──(unlisted empty: safe list or exceptions)────▶ cleared, note "cleared: safe_list", "cleared: exception" or "cleared: safe_list and exception"
open   ──(new version without the file)───────────────▶ fixed (existing re-evaluation)
open   ──(owner dismisses)────────────────────────────▶ dismissed
```

**Transitions of an excepted `weight_file_scan` alert** (stored state in brackets):

```text
open [open]      ──(all its globals covered by active exceptions)──▶ excepted [open]
excepted [open]  ──(an exception revoked or expired)───────────────▶ open [open], release recorded
excepted [open]  ──(new version without the file)──────────────────▶ fixed
excepted [open]  ──(owner dismisses)───────────────────────────────▶ dismissed
```

## Rule (new, code, not stored)

`src/model_dependabot/rules.py`, one record per alert kind (research S1):

| Field | Notes |
| :-- | :-- |
| `rule_id` | `MDB` plus three digits; never reused (`tests/fixtures/rules/assigned.json`) |
| `kind` | an `ALERT_KINDS` value; exactly one rule per kind |
| `title` | one line |
| `page` | `docs/rules/<rule_id>.md`, with the four headings of FR-015 |
| `family` | `weight files`, `packages`, `datasets and papers`, `licences` or `base model`; read by the page index `docs/rules/README.md` (the overview tallies by the source passed into each raising call, research S6, not by rule) |
| `watch_kinds` | the watch kinds documented on its page; every watch kind on exactly one page |

## Check overview (new)

One row per check run, model and source asked, plus one row per source with a null model for the run
as a whole (FR-011, FR-013; research S6).

| Field | Type | Notes |
| :-- | :-- | :-- |
| `run_id` | integer | the check run |
| `model_id` | text, `NOT NULL` | the model; `''` for the run-wide row, shown as null in every view |
| `version` | integer \| null | the version checked; null for the run-wide row |
| `source` | text | a check source, or `policy` for the format rules and the globals policy |
| `state` | `passed` \| `alerted` \| `incomplete` \| `failed` | first match wins: failed, incomplete, alerted, passed |
| `reason` | text \| null | for `failed`: the source's reason; for a run-wide row with no entries: "no entry needed this source" |
| `entries` | integer | entries relevant to the source (`audit.relevant_sources`); for the `policy` row, the version's pinned code-capable weight files |
| `incomplete` | integer | entries the source could not finish in this run |
| `alerts_open` | integer | alerts tallied to the source, open and not excepted at the end of the run |
| `alerts_excepted` | integer | alerts tallied to the source, excepted at the end of the run |
| `watch_events` | integer | watch events the source recorded in this run |
| `dismissals_held` | integer | dismissed alerts whose cause the source found again with no new evidence (FR-020) |

Key `(run_id, model_id, source)`; the run-wide row is stored with `model_id = ''`, so the key holds for
it too.
Per model, the overview also reports `checked` (boolean) and, when false, the reason (FR-012); it is
computed from the rows, not stored.

## Check run (extended view)

No new column. Each model in the `check` payload gains `dismissals_held` (alert ids). The payload gains
`overview` (above) and, with `--fail-on`, `gate`:

| Field | Notes |
| :-- | :-- |
| `gate.fail_on` | the severity asked |
| `gate.tripped` | boolean |
| `gate.alerts` | `[{alert_id, model_id, rule_id, kind, severity}]` of the alerts that tripped it |
| `gate.incomplete` | `[{model_id, source}]`: overview rows in the `incomplete` state (FR-021) |
| `gate.unchecked` | `[model_id]`: models that read `checked: false` (FR-021) |
| `gate.empty_scope` | `true` when the scope matched no model (FR-021) |
| `gate.decided_exit` | `true` when the gate set the code (4, or 0 with `--fail-on`); `false` when exit 2 took precedence. Exit 3 prints no payload (research S5) |

## Audit report (extended)

`summary.alerts_open` excludes excepted alerts; `summary.alerts_excepted` counts them;
`findings.excepted` lists them in the shape `alerts` prints. When the database has overview rows for the
version, `coverage.sources[]` items gain `last_state` (the row's state in that source's latest run).

## As built (T065, 2026-11-14; review round 1)

- Review round 1: each model in the overview gains `uncheckable`, `[{kind, identifier, reason}]`, stored as
  one `check_run_overview` row with source `uncheckable` whose `reason` holds the list as JSON; it is not a
  source row, not coverage and not in the run-wide rows. The `policy` row is not coverage either.
- Review round 1: `VOLATILE_FIELDS` also holds `format-policy` and `globals-policy` (`set_by`, `set_at`;
  the latter also `unlisted` and `excepted`, compared apart: only a growing list is new) and `picklescan`
  (`file_name`, `scanned_at`, `verdict`); `picklescan` evidence matches without its URL.
- Review round 1: a carried-forward alert keeps `reopens` on every path.
- Review round 2: a held `globals_policy` dismissal compares the new list with the dismissed alert's
  `cause.unlisted`, and the scan's evidence row takes part in the comparison.
- Review round 2: at a check that asks no weight source, a `globals_policy` alert opens again, or gains a
  global, when that global's exception was revoked or has expired.
- Review round 3 (issue #18): every check that asks a weight source stores one `globals-snapshot` evidence
  row per local pickle file of the version, under either policy and even when nothing is unlisted (URL
  `globals-snapshot:<model_id>`, matched identifier the file's `sha256:<hex>`, linked to no alert). Its
  record is `{model_id, identifier, globals_policy, set_by, set_at, safe_list_version, safe_list_sha256,
  scan_evidence_id, unlisted, exception_ids}`: what that check applied. A check that asks no weight source
  reads the latest one by `evidence_id` (never by timestamp, so a policy change in the same second as a
  check does not tie) and adds to the file's alert, or opens it, only the globals of `exception_ids` that
  have been revoked or have expired since, skipping any such global an active exception covers now (a
  renewal never opens or extends an alert, the one exception to "a new exception waits"); the policy, the
  rest of the list and the other exceptions recorded since stay as they were. A `default` snapshot, or none (a database from before this row), opens nothing.
  The evidence table grows by one row per file per weight check; no schema change.

- The `globals-policy` evidence record is `{model_id, identifier, globals_policy, set_by, set_at,
  safe_list_version, safe_list_sha256, unlisted, excepted}`, with `unlisted` and `excepted` sorted global
  names; a `globals_policy` alert also links the scan's evidence row and the evidence of each exception
  that took a global off its list.
- An incomplete scan keeps a `globals_policy` alert open even when nothing is unlisted (`scan.complete:
  false` in its cause).
- A model whose every overview row is `failed` reads `checked: false` with the reason "every source that
  could check this model failed".
- The per-model summary of a check (`models[]`) always has `dismissals_held`, empty when nothing held.

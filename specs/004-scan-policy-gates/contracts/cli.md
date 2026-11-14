# Contract: command-line additions (feature 004)

Extends the CLI contracts of [001](../../001-inventory-alerts/contracts/cli.md),
[002](../../002-upstream-watch/contracts/cli.md) and [003](../../003-inventory-assurance/contracts/cli.md).
Every existing command, exit code and JSON field keeps its meaning; additions are new commands, new
options, one new exit code (only with `--fail-on`) and new JSON fields. Every command still takes
`--db PATH` and `--json`. Names follow the owner's rulings D1 and D5 (research).

## Changed commands

| Command | Change |
| :-- | :-- |
| `policy ID [--format (default\|strict)] [--globals (default\|strict)] --by NAME` | `--format` is no longer required on its own: at least one of `--format` and `--globals` is required (exit 1 otherwise), and both may be given. `--globals strict`: any global in a scanned pickle file of this model that is neither on the safe list nor excepted, dangerous ones included, raises one `globals_policy` alert per file; a dangerous global also keeps its HIGH `weight_file_scan` alert (research S7, D3). Takes effect at the next check that asks a weight source (`picklescan`, `hf-scan` or `format-check`) |
| `check (ID \| --all) [--scheduled] [--source ...] [--fail-on SEVERITY]` | Output ends with the check overview (below). `--fail-on` is one of `CRITICAL`, `HIGH`, `MODERATE`, `LOW` and `UNKNOWN`, case-insensitive; see Exit codes |
| `alerts ID [--state open\|excepted\|closed\|all]` | New state `excepted`. The default (`open`) lists open alerts that are not excepted, then the excepted alerts in their own list, then the watch events. Every alert carries `rule_id` |
| `alert show ALERT_ID`, `history ID`, `inventory audit ID` | Every alert carries `rule_id` and `rule_doc`; an excepted alert shows `state: "excepted"` with its exceptions as evidence; the audit's `summary.alerts_open` excludes excepted alerts, `summary.alerts_excepted` counts them and `findings.excepted` lists them; each `coverage.sources[]` item gains `last_state`, the overview state of that source in its latest run for the version, or null when no overview row exists |
| `alert dismiss ALERT_ID ...` | Also accepts an excepted alert (it is still stored open). The dismissal now holds: a later check that finds the same cause with no new evidence (research S13) opens no new alert and lists the alert id under the model's `dismissals_held`; new evidence opens a new alert whose cause names the dismissed one under `reopens` (FR-020) |

## New commands

| Command | What it does |
| :-- | :-- |
| `exception record --global GLOBAL --sha256 HEX --reason TEXT --by NAME [--expires YYYY-MM-DD]` | Records an exception for one global in files with exactly this SHA-256, wherever they are registered. `GLOBAL` is `MODULE.NAME` (split at the last dot) or `MODULE:NAME`; `HEX` is 64 hexadecimal digits, with or without `sha256:`. Refused (exit 1): no reason, no name, a malformed global or hash, a module or name that contains the lower-case string `unknown` (compared case-sensitively, as the scanner does), an expiry date before today (UTC) or an active exception for the same global and hash. Changes no inventory and no alert until the next check |
| `exception list [--all] [--sha256 HEX]` | Lists active exceptions (`--all`: also revoked and expired), each with who accepted it, when, why, its expiry, where it applies (models and versions pinning the hash) and whether it is in use (the latest scan of that hash contains the global) |
| `exception revoke EXCEPTION_ID --reason TEXT --by NAME` | Revokes an active exception, recording who, when and why. The finding returns at the next check. Refused (exit 1): unknown id, already revoked or expired, no reason or name |
| `run show RUN_ID` | Shows a stored run: scope, trigger, per-source statuses and its overview. Reads only |

`exception` commands and `run show` exit 0 on success and 1 on invalid input, like `alert dismiss`.

## The check overview

Text, at the end of `check` and in `run show` (one block per run, then per model):

```text
Overview of run 12 (all)
  source        state       entries  incomplete  alerts  excepted  held  watch events
  osv           passed           41           0       0         0     1             0
  picklescan    incomplete        3           1       1         1     0             3
  hf-scan       alerted           2           0       1         0     0             0
  crossref      failed            2           -       -         -     -             -   HTTP 503 after 3 tries
  policy        alerted           3           0       1         0     0             3
pose-detector v2: checked
  picklescan    incomplete        2           1       1         1     0             2
  policy        alerted           2           0       1         0     0             2
empty-model v1: not checked: no entry of this model can be checked by the sources asked
```

JSON (`check --json`, `run show --json`), added beside the existing fields:

```json
{
  "run_id": 12,
  "scope": "all",
  "trigger": "on_demand",
  "sources": {"osv": "ok", "picklescan": "ok", "hf-scan": "ok", "crossref": "failed: HTTP 503 after 3 tries"},
  "models": [{"model_id": "pose-detector", "version": 2, "opened": [7], "carried_forward": [5], "closed": [], "watch_events": [11, 12],
              "dismissals_held": [3]}],
  "overview": {
    "sources": [
      {"source": "picklescan", "state": "incomplete", "reason": null, "entries": 3, "incomplete": 1,
       "alerts_open": 1, "alerts_excepted": 1, "dismissals_held": 0, "watch_events": 3},
      {"source": "crossref", "state": "failed", "reason": "HTTP 503 after 3 tries", "entries": 2,
       "incomplete": null, "alerts_open": null, "alerts_excepted": null, "dismissals_held": null,
       "watch_events": null}
    ],
    "models": [
      {"model_id": "pose-detector", "version": 2, "checked": true, "reason": null,
       "sources": [{"source": "picklescan", "state": "incomplete", "entries": 2, "incomplete": 1,
                    "alerts_open": 1, "alerts_excepted": 1, "dismissals_held": 0, "watch_events": 2}]},
      {"model_id": "empty-model", "version": 1, "checked": false,
       "reason": "no entry of this model can be checked by the sources asked", "sources": []}
    ]
  },
  "gate": {"fail_on": "HIGH", "tripped": true, "decided_exit": false,
           "alerts": [{"alert_id": 7, "model_id": "pose-detector", "rule_id": "MDB102", "kind": "hub_scan", "severity": "HIGH"}],
           "incomplete": [{"model_id": "pose-detector", "source": "picklescan"}],
           "unchecked": ["empty-model"], "empty_scope": false}
}
```

For a failed source the counts are `null`: nothing it would have changed was changed (FR-016 of 001).
States, counts and the `policy` row are defined in [data-model.md](../data-model.md) (Check overview) and
research S6. A run whose scope matches no model has `"models": []` and the text line
`No models were checked`. The gate's text lines name each tripping alert, each incomplete source per
model, each unchecked model and an empty scope (FR-021).

## Alert additions (all views)

```json
{
  "alert_id": 5,
  "rule_id": "MDB101",
  "rule_doc": "docs/rules/MDB101.md",
  "kind": "weight_file_scan",
  "state": "excepted",
  "severity": "HIGH",
  "cause": {
    "identifier": "sha256:…",
    "dangerous": ["__builtin__.getattr"],
    "excepted": [{"global": "__builtin__.getattr", "exception_id": 3, "accepted_by": "Owner",
                  "recorded_at": "2026-11-13T09:00:00Z", "expires_on": null}]
  },
  "evidence": [{"source": "picklescan", "…": "…"}, {"source": "exception", "url": "exception:3", "…": "…"}]
}
```

Text: `  #5 MDB101 HIGH     excepted  …` (the rule ID after the alert id). The `alerts` payload gains
`"excepted": [...]`. The `alerts` array never holds an excepted alert: with `--state open` (the default) it
holds the open alerts that are not excepted, with `--state closed` the closed ones and with `--state all`
both; the excepted alerts are in `excepted` for `open`, `excepted` and `all`, and `excepted` is empty for
`closed`. `--state excepted` gives `"alerts": []` and the excepted alerts in `excepted` (owner's ruling,
2026-11-14).

`exception record --json` and `exception revoke --json` print one exception in the shape of an
`exception list` item below (after a revocation, `state` is `revoked` and `revoked` is set).

`exception list --json`:

```json
{
  "exceptions": [
    {"exception_id": 3, "global": "__builtin__.getattr", "module": "__builtin__", "name": "getattr",
     "sha256": "…", "reason": "reviewed: attribute lookup on layer classes only", "accepted_by": "Owner",
     "recorded_at": "2026-11-13T09:00:00Z", "expires_on": null, "state": "active",
     "revoked": null, "applies_to": [{"model_id": "pose-detector", "version": 2, "location": "weights/pose.pt"}],
     "in_use": true}
  ]
}
```

`state` is `active`, `expired` or `revoked`; `revoked` is `{at, by, reason}` or null.

`policy --json` gains `globals_policy`, `globals_set_by` and `globals_set_at` beside the existing format
policy fields.

## Exit codes

The full table for every command after this feature. Rows without a change are as in 001 to 003.

| Code | Meaning |
| :-- | :-- |
| 0 | Success. For `check`: the check completed, whether or not it found anything, unless `--fail-on` tripped (4) |
| 1 | Invalid input (manifest, inventory or arguments, including a `--fail-on` value that is not a severity and `policy` with neither `--format` nor `--globals`); for `inventory audit` also an unknown model or version or a database older than feature 002; for `discover` the cases in 003; for `exception` commands the refusals above; for `run show` an unknown run |
| 2 | `check` finished but at least one source failed; alerts that depend on it were left unchanged. Takes precedence over 4 |
| 3 | Unexpected error, including an interrupted run. Takes precedence over 2 and 4 |
| 4 | **New.** `check --fail-on SEVERITY` finished with no source failed, and at least one alert of a model in the run's scope is open, not excepted and at or above `SEVERITY` (whichever run raised it); or a model in scope has a source in the `incomplete` state; or a model was checked by no relevant source; or the scope matched no model (FR-021) |

Per command:

| Command | 0 | 1 | 2 | 3 | 4 |
| :-- | :-- | :-- | :-- | :-- | :-- |
| `check` without `--fail-on` | as before | as before | as before | as before | never |
| `check --fail-on S` | no source failed, no open, not excepted alert at or above `S` in scope, no `incomplete` row, no unchecked model and a scope that matched at least one model | as before, or `S` invalid | a source failed, whatever the gate found (`gate.decided_exit: false`) | as before | no source failed and the gate tripped |
| `policy` | policy recorded | unknown model, no `--by`, neither option | never | unexpected | never |
| `exception record`, `exception revoke` | recorded or revoked | refusals above | never | unexpected | never |
| `exception list`, `run show` | listed | bad arguments, unknown run | never | unexpected | never |
| every other command | as before | as before | as before | as before | never |

`check` without `--fail-on` still never exits non-zero just because alerts exist, so a scheduler does
not mistake findings for failures (SC-005).

## As built (T065, 2026-11-14; review round 1)

- Review round 1: `run show` opens the database read-only, as `inventory audit` does: a missing file exits
  1 ("no database at PATH") and creates nothing; an older database is read as it is, never upgraded.
- Review round 1: each model of the overview has `uncheckable` (`[{kind, identifier, reason}]`), shown in
  text as `  uncheckable: KIND IDENTIFIER: REASON`; such items never trip `--fail-on`.
- Review round 1: a model whose only rows are `policy` and failed sources reads `checked: false` and trips
  `--fail-on`.
- Review round 1: every `check` releases alerts whose exception was revoked or has expired, whatever the
  sources asked; recording an exception still takes effect only at a check that asks a weight source.
- Review round 2: the same holds for a `globals_policy` finding: a global whose exception lapsed returns at
  the next check of any sources. In text, a checked model is never followed by a "not checked" line, and
  its uncheckable items follow its rows.
- Review round 3 (issue #18): "lapsed" is judged against the file's latest `globals-snapshot` row, written
  by each check that asks a weight source; only those globals change, under the policy that check
  applied, and a file with no snapshot or a `default` one waits for the next weight check. A lapsed
  global that an active exception covers now (a renewal: revoked or expired, then recorded again) is
  skipped, so renewing never opens or extends an alert; this is the one exception to "a new exception
  waits for a weight check".

- `run show RUN_ID --json` prints `{run_id, scope, trigger, started_at, finished_at, sources, overview}`;
  its text is the run's header, each source's status, then the overview block. An unknown run exits 1
  with "no check run N".
- `check --fail-on` prints, after the overview, `Gate --fail-on HIGH: tripped` or `passed` (with "(a
  source failed: exit 2 decides)" when exit 2 decided), then one line per tripping alert
  (`  alert #7 MDB102 HIGH hub_scan (pose-detector)`), per incomplete source (`  incomplete: MODEL
  SOURCE`), per unchecked model (`  not checked: MODEL`) and `  the scope matched no model`.
- `--fail-on` with another value exits 1: "argument --fail-on: must be one of CRITICAL, HIGH, MODERATE,
  LOW, UNKNOWN".
- `policy` with neither option exits 1: "policy needs --format, --globals or both". Its text reads
  `ID: format policy P, globals policy G, set by NAME; takes effect at the next check that asks a weight
  source`.
- Refusals of `exception record` (exit 1): "an exception needs a reason", "an exception needs the name of
  who accepted it", "a global is MODULE.NAME or MODULE:NAME", "a SHA-256 is 64 hexadecimal digits", "...
  names an import the scanner could not resolve ('unknown'); it cannot be excepted", "the expiry date ...
  is in the past", "an active exception (N) already covers ...". Of `exception revoke`: "no exception
  N", "exception N is not active (it is revoked|expired)", "a revocation needs a reason" and "a
  revocation needs the name of who revoked it".
- A `globals_policy` alert closes as `cleared` with the note `cleared: policy`, `cleared: safe_list`,
  `cleared: exception` or `cleared: safe_list and exception`.

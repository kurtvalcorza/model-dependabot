# Research: Scan Exceptions, Strict Globals, Check Overview and an Opt-in Gate

**Feature**: [spec.md](spec.md) | **Plan**: [plan.md](plan.md) | **Date**: 2026-11-13

Each item records the decision, why it was made and what else was considered. Code references are to
`main` at `c07c14d` (PR #15 merged). picklescan references are to the installed 1.0.5
(the installed package's `picklescan/scanner.py`), the version pinned in `pyproject.toml:10`.

## Decisions on the plan's open questions

These changed what users see beyond the spec's first text, or were trade-offs reasonable people would
settle differently. The owner ruled on D1 to D7 in the plan review of 2026-11-13 and on D8 and D9 in the
review of the analysis that followed; the spec records each
under Clarifications, Session 2026-11-13 (plan review), and the sections below follow the rulings.

| # | Question | Options considered | Decided | By |
| :-- | :-- | :-- | :-- | :-- |
| D1 | Rule ID format and where the pages live (S1) | (a) `MDB` plus three digits by family, pages in `docs/rules/`; (b) the alert kind as the ID; (c) `MD` plus digits | **(a)**, as recommended. (b) ties the ID to an internal name; (c) collides with the Markdown linter's `MD001` rule names | owner, 2026-11-13 |
| D2 | Does safe list version 1 hold `_codecs.encode` and `numpy.core.multiarray.scalar`, seen in real checkpoints? (S3) | (a) neither; (b) `_codecs.encode` only; (c) both | **(c)**, against the plan's recommendation of (a). Trade-off recorded in S3: `_codecs.encode` can rebuild arbitrary bytes | owner, 2026-11-13 |
| D3 | Does the `globals_policy` alert also list globals the scanner calls dangerous? (S7) | (a) no, they already raise HIGH `weight_file_scan`; (b) yes, as FR-008 reads | **(b)**, against the plan's recommendation of (a). A dangerous global appears in both alerts; one exception covers both (S7, S8) | owner, 2026-11-13 |
| D4 | One overview state when a source both raised alerts and could not finish some entries (S6) | (a) `incomplete` wins; (b) `alerted` wins | **(a)**, as recommended | owner, 2026-11-13 |
| D5 | How a stored overview is shown again (FR-013) | (a) `run show RUN_ID`; (b) only inside `alerts` and `inventory audit` | **(a)**, as recommended | owner, 2026-11-13 |
| D6 | A dismissed alert is opened again by the next check (confirmed, S5); hold dismissals now or later? | (a) later, in a follow-up; (b) in this feature | **(b)**, against the plan's recommendation of (a). Every alert kind; only new evidence reopens (S13, FR-020) | owner, 2026-11-13 |
| D7 | Are `__builtin__.getattr` and `builtins.getattr` one global? | (a) distinct, matched exactly; (b) one | **(a)**, as recommended | owner, 2026-11-13 |
| D8 | Does `--fail-on` pass when coverage is missing (a source `incomplete`, a model not checked, an empty scope)? (S5) | (a) yes, only a failed source stops it; (b) no, it trips the gate | **(b)** "fail on incomplete too" (FR-021) | owner, 2026-11-13, analysis review |
| D9 | Can an exception or a safe list entry name a global the scanner could not resolve (`unknown`)? (S14) | (a) yes, exact match as any other; (b) no, refused | **(b)**, as recommended | owner, 2026-11-13, analysis review |

## S1. Rule IDs and one page per ID

**Finding**: alert kinds are strings in `store.ALERT_KINDS` (`store.py:46-57`, 11 kinds), checked by
the `alerts.kind` constraint (`store.py:246`). Severities are fixed per kind for weight files
(`lifecycle.py:145-149`) and upstream items (README, Upstream checks). The repository has no `docs/`
folder; user documentation is `README.md` and the per-feature contracts under `specs/`.

**Decision**: a registry module `src/model_dependabot/rules.py` holds one record per alert kind: rule ID,
kind, title, page path, its family (weight files, packages, datasets and papers, licences or base model; the
overview tallies by the source passed into each raising call, S6) and the watch kinds
documented on its page. IDs are `MDB` plus three digits, grouped by family, and never reused (D1):

| Rule ID | Alert kind | Family |
| :-- | :-- | :-- |
| `MDB101` | `weight_file_scan` | weight files |
| `MDB102` | `hub_scan` | weight files |
| `MDB103` | `format_policy` | weight files |
| `MDB104` | `globals_policy` (new, S7) | weight files |
| `MDB201` | `package_advisory` | packages |
| `MDB301` | `dataset_retracted` | datasets and papers |
| `MDB302` | `paper_retracted` | datasets and papers |
| `MDB303` | `dataset_removed` | datasets and papers |
| `MDB304` | `dataset_not_findable` | datasets and papers |
| `MDB401` | `licence_changed` | licences |
| `MDB501` | `base_model_disabled` | base model |
| `MDB502` | `base_model_unavailable` | base model |

Pages live in a new top-level `docs/rules/`, one file per ID (`docs/rules/MDB101.md`), each with exactly
the four headings FR-015 names (What raises it; What it does not prove; How it closes; How to fix or
accept it), plus `docs/rules/README.md` as the index. Each watch kind in `store.WATCH_KINDS`
(`store.py:61-91`) is listed on exactly one page. Alert JSON gains `rule_id` and `rule_doc` (the
repository-relative path); text output prefixes each alert line with its ID (`reports.alert_line`,
`reports.py:214`). `tests/fixtures/rules/assigned.json` records every ID ever assigned with its kind; a
unit test fails if a kind in `ALERT_KINDS` has no rule, a rule has no page or a page lacks a heading,
an ID appears twice, or an ID in `assigned.json` now names another kind or has gone (FR-016).

**Alternatives considered**: pages under `specs/` (specs record design history, not current
behaviour, and are not updated per release); pages in the package with a `rule show` command (useful,
but a new command the spec does not ask for; the registry keeps that open); the kind as the ID (D1).

## S2. Storage: exceptions, the globals policy, file scans and the check overview

**Finding**: the schema is created with `CREATE TABLE IF NOT EXISTS` on every open (`store.py:482`);
additions to existing tables are `ALTER TABLE ... ADD COLUMN` guarded by `columns()`, inside `_atomic`
(`store.py:540-553`) where more than one statement must land together (`_add_origins`,
`store.py:555-596`). A `CHECK` cannot be widened in place, so `_widen_watch_kinds` rebuilds
`watch_events` by the SQLite twelve-step procedure in one transaction, keeping every row and id
(`store.py:624-656`). One-off facts about the database go in `store_marks` (`store.py:323-326`). The
format policy is three columns on `models` (`store.py:116-124`), written by `set_format_policy`
(`store.py:767-783`). A check run's per-source statuses are one JSON column, `check_runs.sources`
(`store.py:165-172`, written by `finish_check_run`, `store.py:1191-1196`). The scanner's globals are
kept only inside evidence bodies, and only when a scan raised an alert or watch event
(`lifecycle.py:1289-1331`): a clean scan leaves no record of what it saw.

**Decision**:

- **`global_exceptions`** (new table): one row per exception, never deleted; only the revocation
  columns can be set, once, guarded by a trigger in the style of the version triggers
  (`store.py:343-350`). See [data-model.md](data-model.md).
- **`models.globals_policy`, `globals_policy_set_by`, `globals_policy_set_at`** (new columns, added
  with `ADD COLUMN ... NOT NULL DEFAULT 'default' CHECK (...)`), so every existing model reads
  `default` (FR-007). `set_globals_policy` mirrors `set_format_policy`.
- **`file_scans`** (new table): one row per applied scan report, keyed by file SHA-256, with the
  scanner, its version, whether the scan was complete, each global with the scanner's label and the
  evidence row. Written by `_apply_report` for both local scans in a check (`lifecycle.py:1231-1286`)
  and recorded scans at registration (`apply_recorded_scans`, `lifecycle.py:1334-1376`). The latest
  row per hash is what exceptions and the strict policy read, so a policy set after registration, or
  a version registered from a record whose bytes are elsewhere, is still judged on its scan.
- **`alerts.excepted_at`** (new column, null unless excepted; S4) and a one-time rebuild of `alerts`
  to widen `kind` for `globals_policy`, generalising `_widen_watch_kinds` to take the table name. The
  rebuild copies rows by explicit column list, because the rebuilt table also has `excepted_at`, and
  recreates the partial unique index `one_open_alert_per_cause` (`store.py:263-264`) inside the same
  transaction: dropping the old table drops the index, and `executescript(SCHEMA)` runs before the
  migrations on open (`store.py:482`), so nothing else would put it back in that open.
- **`check_run_overview`** (new table): one row per run, model and source, plus rows for the run as a
  whole, stored with `model_id = ''` (the column is `TEXT NOT NULL`; views show it as null) so the
  primary key `(run_id, model_id, source)` holds for them too (FR-011, FR-013). A table rather than a JSON column on `check_runs` so the
  audit and `run show` can read one model's rows directly, as `check_run_targets` does.

A database written before this feature gains all of it on its first read-write open, in one
`_atomic` block per step; the read-only open (`store.py:441-471`) reads absent tables and columns as
their defaults (no exceptions, policy `default`, no overview), as feature 003 did. A pre-004 schema
fixture (`tests/fixtures/db/schema-pre-004.sql`, built like `schema-pre-003.sql`) tests the upgrade
and an interrupted rebuild.

**Alternatives considered**: exceptions as a per-model table (FR-002 says they apply wherever the hash
is registered); the overview as JSON in `check_runs` (cannot be read per model without parsing every
run); not storing scans and re-reading globals from evidence bodies (a clean scan has no evidence, and
a record-registered file is never scanned again).

## S3. The starting safe list and its versioning

**Finding** (checked with `uv run python -c "import picklescan.scanner as s; ..."` on the installed
1.0.5): `_safe_globals` (`scanner.py:88-120`) holds six modules and 23 exact names, no wildcard:

- `collections.OrderedDict`
- `numpy.dtype`, `numpy.ndarray`
- `numpy.core.multiarray._reconstruct`, `numpy._core.multiarray._reconstruct`
- `torch._utils._rebuild_tensor_v2`
- 17 typed storages in `torch`: `BFloat16Storage`, `BoolStorage`, `ByteStorage`, `CharStorage`,
  `ComplexDoubleStorage`, `ComplexFloatStorage`, `DoubleStorage`, `FloatStorage`, `HalfStorage`,
  `IntStorage`, `LongStorage`, `QInt32Storage`, `QInt8Storage`, `QUInt2x4Storage`, `QUInt4x2Storage`,
  `QUInt8Storage`, `ShortStorage`.

A global is `dangerous` if it is in `_unsafe_globals` (`scanner.py:122`, 67 modules, several as `*`,
with parent-module wildcards applied) or names `unknown`, `innocuous` if in `_safe_globals`, and
otherwise `suspicious` (`scanner.py:404-452`). picklescan has its own `strict` flag that turns every
suspicious global into a dangerous one (`scanner.py:437`); `pickle_scan.py` does not pass it.

The two real checkpoints in the brief show what lies outside that list: a pose detection checkpoint
imports `__builtin__.getattr` (dangerous) and 25 suspicious globals, among them framework layer
classes, `__builtin__.set`, `torch.Size` and `torch._utils._rebuild_parameter`; a change-detection
checkpoint imports `getattr`, `_codecs.encode`, `numpy.core.multiarray.scalar` and a training
framework's logging class. Neither file was loaded or scanned here; the lists are the brief's.

**Decision**: `src/model_dependabot/safe_globals/safe-globals.toml`, version 1, holds exact entries
`{module, name, why, added_in}`:

1. the 23 globals of picklescan 1.0.5's `_safe_globals`, `why = "picklescan 1.0.5 innocuous list"`;
2. tensor rebuilding and plain containers common in PyTorch checkpoints: `torch._utils._rebuild_parameter`,
   `torch._utils._rebuild_parameter_with_state`, `torch.Size`, `builtins.set`, `__builtin__.set`
   (`builtins.frozenset` and `__builtin__.frozenset` were dropped by the owner on 2026-11-14: they are
   not on PyTorch's default list, see the check below);
3. by the owner's ruling (D2): `_codecs.encode` and `numpy.core.multiarray.scalar`, each with
   `why = "owner ruling 2026-11-13: common in real checkpoints"`.

That is 30 entries. Group 3's rationale: both appear in ordinary checkpoints (protocol-2 pickles rebuild
every `bytes` value through `_codecs.encode`, and numpy scalars such as a saved metric go through
`numpy.core.multiarray.scalar`), so leaving them off would make strict raise on nearly every such file
and push owners to except them file by file. The trade-off, recorded in the file's `why` and in the
safe list README: `_codecs.encode` can rebuild arbitrary bytes, so a file that lists it can carry any
byte string into whatever else it calls; `numpy.core.multiarray.scalar` with an object dtype can carry
an arbitrary object. Neither runs code on its own, and the call that would use the bytes or object is a
separate global that strict still judges, but the list no longer guarantees that a listed global is
inert in every combination. A later version can remove either; removal opens `globals_policy` alerts again at
the next check, citing that version.

Not on the list: any framework layer or class (`torch.nn.*` and the like: they import code, which is
what strict is for), nor anything picklescan calls dangerous. The entries in group 2 come from the
samples above and from PyTorch's restricted loader.

**Confirmed (T006, 2026-11-13)** against the default allow-list (`_get_allowed_globals` and
`_tensor_rebuild_functions`) in `torch/_weights_only_unpickler.py` of PyTorch **2.15.0**, the newest
release on the package index that day, read as text from the release tag's source and never imported
(SHA-256 `dd589755743adb7576bffe9190c4b4db463008afe85ff9211c626e25e44c244f`). The module renames
come from `IMPORT_MAPPING` in the same release's `torch/_utils.py` (SHA-256
`8a4260434d72035c4e8e2c7295f035842e7d82a1a8faca1bfa813470ae776c4f`), which maps `__builtin__` to
`builtins` before the allow-list is read. PyTorch 2.9.0's copy of the first file
(SHA-256 `76b2eafeda2078538987d5cf18e99d6371b2f747eb4f059a513fcf0ef81cf10e`) gives the same results.

| Entry | Group | In PyTorch 2.15.0's default allow-list |
| :-- | :-- | :-- |
| `torch._utils._rebuild_parameter` | 2 | yes (tensor rebuild functions) |
| `torch._utils._rebuild_parameter_with_state` | 2 | yes (tensor rebuild functions) |
| `torch.Size` | 2 | yes |
| `builtins.set` | 2 | yes |
| `__builtin__.set` | 2 | yes, read as `builtins.set` through `IMPORT_MAPPING` |
| `builtins.frozenset` | 2 | **no**: dropped from version 1 (owner, 2026-11-14) |
| `__builtin__.frozenset` | 2 | **no**: dropped from version 1 (owner, 2026-11-14) |
| `_codecs.encode` | 3 | yes |
| `numpy.core.multiarray.scalar` | 3 | **no**: PyTorch leaves every numpy global out of its default list; already the owner's ruling D2 |

**Owner's ruling (2026-11-14): drop.** `builtins.frozenset` and `__builtin__.frozenset` are not on
PyTorch's default list, so group 2's rationale ("from PyTorch's restricted loader") does not hold for
them; they rested only on the checkpoint samples. Version 1 holds neither, so it has 30 entries.

The file starts with `version = 1` and a `[[changes]]` table (version, date, what changed). Any change
to the entries bumps the version by one; a unit test holds the SHA-256 of the entries for each version
and fails if the entries change without a new version. The loader refuses an entry with a `*`, an
empty part, a duplicate or a module or name that contains the lower-case string `unknown` (compared case-sensitively, as the scanner does) (FR-009, S14). Each `globals_policy` alert cites the version and the file's
SHA-256. When a newer version lists a global, the next check removes it from open alerts' lists, with
the version as the recorded cause (spec, Edge Cases).

**Alternatives considered**: reading `_safe_globals` from picklescan at run time (the list would change
with a dependency bump, unreviewed and unversioned here); module prefixes (refused by the clarification
of 2026-11-13); semantic versions for the list (it has one kind of change, adding or removing an
entry, so a counter says enough).

## S4. How an excepted alert is represented

**Finding**: `alerts.state` is one of `ALERT_STATES` (`store.py:58`), enforced by a `CHECK`
(`store.py:251`); at most one open alert per model and cause is enforced by a partial unique index
`WHERE state = 'open'` (`store.py:263-264`). Every reader of `open`:

| Reader | What "open" means there |
| :-- | :-- |
| `store.py:264` unique index; `find_open_alert` (`store.py:1276-1281`); `update_open_alert` (`store.py:1283-1312`); `close_alert` (`store.py:1135-1163`); `_rekey_repository_alerts` (`store.py:679-718`) | a live record for the cause, to carry forward or close |
| `lifecycle.py` `find_open_alert` at 673, 924, 1041, 1495, 2026, 2112, 2311, 2370, 2403, 2448, 2599, 2663 | live record: carry forward instead of opening a second |
| `lifecycle.py` `alerts_for(..., ["open"])` at 329, 468, 1070, 1149, 1403, 1634 | live record: OSV ids to refetch, merge, clear, hub confirmation, version re-evaluation |
| `lifecycle.py:1716` `dismiss_alert` | only a live alert can be dismissed |
| `reports.py:41-45` `STATE_FILTERS`, `alerts_report` (`reports.py:107-120`) | **counted and listed as open** |
| `reports.py:30` `CLOSED_STATES`, `history_report` | closed history |
| `audit.py:315` and `summary.alerts_open` | **counted as open** |
| `cli.py:253` `alerts --state` choices | filter |

**Decision**: an excepted alert keeps the stored state `open` and carries `alerts.excepted_at` (the time
the exception was applied) with the exception linked as evidence. Lifecycle readers (the first three
rows) need no change: an excepted alert is still the live record for its cause, carried forward by
version re-evaluation and fixed when a new version drops the file. Counting readers change: views
present it as `state: "excepted"` (`alert_view`), the `alerts` payload lists it under a new
`excepted` array rather than `alerts`, `alerts --state` gains `excepted`, the audit's `alerts_open`
excludes it while a new `alerts_excepted` counts it; the overview and the gate count only alerts
with `excepted_at` null. `dismiss_alert` accepts an excepted alert (it is still open), which removes
it from the excepted list; the dismissal then holds as any other (S13).

An alert is excepted only when **every** global that raised it is covered by an active exception for
its file's hash. A `weight_file_scan` alert with two dangerous globals and one exception stays counted
as open; its cause lists the excepted global under `excepted` with the exception id (US1 scenario 3).
When an exception is revoked or expires, the next check clears `excepted_at`, records the revocation
or expiry as evidence and the alert counts as open again: same id, same history (FR-001, FR-004).

`globals_policy` alerts are not marked excepted: FR-008 and FR-010 say an excepted global leaves the
alert's list and the alert closes when the list is empty (S7).

**Alternatives considered**: a stored state `excepted` (Complexity Tracking: every live-record reader
above would need to accept it; a missed one opens a duplicate or never fixes the alert; a revoked
exception would need the alert reopened, which no state transition does today); closing the alert as
`dismissed` with a new reason (a dismissal is per model and per alert, while an exception is per hash
across models and must release the finding when revoked).

## S5. The gate's exit code and exit 2

**Finding**: exit codes are 0, 1, 2 and 3 (`cli.py:62-65`). `main` returns 2 when the handler's result
has `sources_failed` (`cli.py:322`), set from `CheckOutcome.failed`, any source status starting
`failed` (`lifecycle.py:156-166`); 1 and 3 come from exceptions before output (`cli.py:309-316`). The
README's table promises `check` never exits non-zero because alerts exist. Severities rank `CRITICAL`,
`HIGH`, `MODERATE`, `LOW`, `UNKNOWN` (`matching/severity.py:24`, `severity_rank` at 34).

Before this feature dismissal did not hold across checks (D6, fixed by S13): a probe in a scratch
database (register a model with a
crafted `os.system` pickle, `check --source picklescan`, `alert dismiss 1 --reason risk_accepted`,
check again) left alert 1 `dismissed` and opened alert 2 `open` for the same cause, because
`_weight_alert` looks only for an open alert (`lifecycle.py:924`) before inserting. OSV alerts take
the same path (`lifecycle.py:673`).

**Decision**: `check --fail-on SEVERITY` with `SEVERITY` one of the five names (case-insensitive on
input, printed upper case). After the run, the gate takes every alert of every model in the run's
scope with state `open`, `excepted_at` null and `severity_rank(severity) <= severity_rank(SEVERITY)`,
whatever source raised it and in whichever run. Any such alert trips the gate: exit **4**, with the
alerts listed in text and in the JSON `gate` object. Precedence, highest first: 3 (unexpected error,
including an interrupted run), 2 (a source failed), 4 (gate tripped), 0. Exit 1 happens before any run.
With exit 2 the gate is still evaluated and reported in the output, but it never decides the code
(FR-019).

Coverage also trips the gate (owner's ruling D8, "fail on incomplete too"; FR-021). With no source
failed, the gate trips when any model in scope has an overview row in the `incomplete` state, when a
model reads `checked: false` (no relevant source asked could check it, S6) or when the scope matched no
model (`check --all` on an empty database). The `gate` object names them in `incomplete`
(`[{model_id, source}]`), `unchecked` (`[model_id]`) and `empty_scope` (boolean), beside `alerts`. A
`--source` list that leaves sources out is the pipeline's choice: the gate judges only what was asked,
and a model none of whose relevant entries an asked source covers reads `checked: false` and trips it.
`gate.decided_exit` is true when the gate set the code (4, or 0 with `--fail-on`) and false when exit 2
took precedence; exit 3 prints no payload. Without `--fail-on`, the `gate` object is absent and every
code is as today (FR-018), which the contract test of every row in the exit-code table guards (SC-005).

**Alternatives considered**: counting only alerts the run itself opened or carried forward (a pipeline
asking `--source osv` would pass with an open HIGH weight alert); letting the gate win over 2 (a
pipeline would read "findings" when the truth is "not fully checked"); reusing 1 or 2 (a scheduler
cannot then tell a gate from a broken run).

## S6. Overview states from the run's per-source results

**Finding**: a run records per source only `ok`, `failed: reason` or `skipped` (`lifecycle.py:276-310`;
`skipped` is reachable only for a name the dispatcher does not know, which `cli._sources` refuses,
`cli.py:117-124`). Per model, `CheckOutcome.models` lists alert ids opened, carried forward and closed
and watch event ids, with no source (`lifecycle.py:242-262`). Feature 003's audit decides which sources
are relevant to which entry (`audit.relevant_sources`, `audit.py:123-146`) and reports each source's
latest status and age (`_coverage`, `audit.py:189-219`). Evidence rows name their source, but not in
the check-source vocabulary (`osv.dev` for `osv`, `format-policy` and `format-rule` for the format
rules), and identical evidence is reused across runs (`_store_observations`, `lifecycle.py:877-908`),
so evidence cannot attribute a carried-forward alert to a run.

**Decision**: tally in the run. The per-model summary gains, per check source, the alert ids opened or
carried forward, the alert ids closed, the watch event ids recorded and the entries that could not be
finished. The calls that raise alerts and watch events (`_weight_alert`, `_watch`, `_upstream_alert`,
`_upstream_watch` and the OSV path) are given the check source they are applying. Alerts and watch
events from the format rules and the globals policy, which rest on the inventory and the owner's
policy, are tallied under a row named `policy`. Then `assurance/overview.py` maps each (model, source):

| State | Rule, first match wins |
| :-- | :-- |
| `failed` | the source's status starts `failed` (the reason is shown), or is `skipped` |
| `incomplete` | at least one relevant entry could not be finished this run (D4) |
| `alerted` | at least one alert tallied to the source is open and not excepted at the end of the run |
| `passed` | otherwise |

Counts per row: `entries` (relevant entries, `audit.relevant_sources`; for the `policy` row, the version's
pinned code-capable weight files, which are what the format and globals policies judge), `incomplete`,
`alerts_open`,
`alerts_excepted`, `watch_events`. An entry could not be finished when its source recorded, in this
run, `scan_incomplete`, `hash_mismatch` or `weight_file_absent` (picklescan, `lifecycle.py:1255-1281`,
1331), `hub_scan_unknown` or `hash_mismatch` (hf-scan, 1490, 1527, 1532), `format_claim_unreadable`
(format-check, 1129), `dataset_unreachable`, `paper_not_found` or `base_model_refused` (the upstream
source that recorded it, 2163, 2223, 2289, 2612). A source with no relevant entry for a model has no
row for that model. A model none of whose entries is relevant to any source asked gets
`checked: false` with the reason "no entry of this model can be checked by the sources asked"
(FR-012); `checked: true` needs at least one row that is not `failed`. The rows with no model
aggregate each source over the run: the worst state across models (`failed` > `incomplete` >
`alerted` > `passed`) and summed counts; a source asked that no model needed is `passed` with
`entries: 0` and the note "no entry needed this source". The overview is written to
`check_run_overview` when the run finishes, and on an interrupted run with what was tallied.

**Alternatives considered**: deriving the overview afterwards from evidence (wrong for reused evidence
and a different source vocabulary); one state per source with no per-model rows (cannot answer SC-004);
attributing the format rules to every weight source asked (a `format_policy` alert would make
`picklescan` read `alerted` though it found nothing).

## S7. The `globals_policy` alert: key, update and close

**Finding**: weight alerts are keyed `kind:sha256` (`weight_cause_key`, `lifecycle.py:784-786`), opened
or carried forward by `_weight_alert` (`lifecycle.py:911-951`), which replaces the cause and links new
evidence. `format_policy` is evaluated in `_apply_format_rules` after every weight source whenever one
is asked (`lifecycle.py:312-314`, 989-1045), and cleared by `_clear_format_policy` with the owner's
policy record as evidence when the policy is no longer strict (`lifecycle.py:1142-1177`). Version
re-evaluation fixes any weight alert whose identifier the new version no longer pins
(the weight branch of `reevaluate_version`, `lifecycle.py:1667-1680`), whatever its kind.

**Decision**: a new kind `globals_policy`, severity MODERATE (spec, Assumptions), cause key
`globals_policy:<sha256>`, one per file per model (FR-008). A new `_apply_globals_rules` runs right
after `_apply_format_rules`, under the same condition. For each pinned code-capable local weight file
of the version, it reads the latest `file_scans` row for the hash, the model's globals policy, the safe
list and the active exceptions for the hash at the run's time, and computes `unlisted`: globals the
scanner reported, whatever its label (`dangerous`, `suspicious` or `innocuous`), that are neither on the
safe list nor excepted (D3, FR-008). A dangerous global is therefore in two alerts: the HIGH
`weight_file_scan` alert, as today, and this one. That is the owner's ruling: the `globals_policy` alert is the
complete list of what the owner has not accepted for the file, so it can be read, excepted and closed on
its own. One exception for (global, hash) removes the global from both (S8).

- **Open**: policy `strict`, `unlisted` not empty and no open alert: open it with cause
  `{identifier, location, format, unlisted, excepted, safe_list_version, safe_list_sha256, policy,
  set_by, set_at, scan: {scanner, scanner_version, complete, scanned_at}}`. Evidence: the scan's
  evidence row and a `globals-policy` record (the policy, the safe list version and hash plus the
  sorted `unlisted` and `excepted` lists, so a change in either is new evidence under S13), as the
  format policy does.
- **Update**: an open alert and `unlisted` not empty: carry it forward with the new cause, linking new
  evidence only when it changed (`_store_observations` reuse).
- **Close as `cleared`**: an open alert and `unlisted` empty, or the policy no longer `strict`. The
  note and evidence name the cause: `policy` (the policy record, as `_clear_format_policy`),
  `safe_list` (the version that lists the remaining globals) or `exception` (the exception rows).
  When several apply, all are named.
- A scan that did not complete is never clean (US2 scenario 5): the alert lists what was seen and
  `scan.complete: false`, and the existing `scan_incomplete` watch event still appears. A file with no
  scan row (a hub file, or a local file never scanned) raises nothing and is left to the overview.

A revoked or expired exception at the next check puts its global back in `unlisted`, opening the alert
again if it had closed; the new alert's cause names the released exception.

**Alternatives considered**: one alert per global (refused by the clarification of 2026-11-13); folding
strict globals into `format_policy` (S1); using picklescan's own `strict` flag (`scanner.py:437`),
which would turn suspicious globals into HIGH `weight_file_scan` alerts and change default-policy
output.

## S8. Applying exceptions in a check

**Decision**: exceptions take effect at the next check that asks a weight source, like the format
policy ("takes effect at the next check", README). `_apply_globals_rules` also marks `weight_file_scan`
alerts: for each open one, the dangerous globals in its cause are compared with the active exceptions
for its hash; when all are covered, `excepted_at` is set and an `exception` evidence row per exception
is linked (source `exception`, URL `exception:<id>`, body the exception record as canonical JSON); when
not all are, `excepted_at` is cleared and the cause's `excepted` list says which are. An exception is
active at time *t* when it is not revoked and *t* is before 00:00Z on the day after its expiry date (an
exception expiring `2027-01-31` covers that whole day in UTC). Recording one with a date before today
(UTC) is refused. So are one without a reason or a name (US1 scenario 5), one for a hash that is not 64
hexadecimal digits, one whose module or name contains the lower-case string `unknown` (compared case-sensitively, as the scanner does) (S14) and a second active one for the
same global and hash. Exceptions are global to the
database: `exception list` shows, per exception, the models and versions whose pinned entries carry
the hash ("applies to") and whether the latest scan of that hash contains the global ("in use";
spec, Edge Cases). One exception covers a global in both alerts that name it: it marks the `weight_file_scan` alert
excepted (once all its globals are covered) and removes the global from the `globals_policy` alert's
`unlisted`. Hub weight files are out of scope: no source reads their globals, so an exception recorded
for a hub file's hash is accepted but listed as not in use (spec, Edge Cases and Out of scope).

## S9. Spelling a global on the command line

**Decision**: `--global MODULE.NAME`, split at the last dot, as alerts print it (`Finding.global_name`,
`pickle_scan.py:44-46`); `--global MODULE:NAME` splits at the colon, for the rare name that itself
contains a dot. Stored as `module` and `name` separately. Matching is exact (D7).

## S10. Default-policy equivalence (SC-002, FR-007)

**Decision**: with `globals_policy = 'default'` and no exceptions, the only new writes in a check are
`file_scans` rows and the overview; `alerts` and `watch_events` must not change. A baseline is recorded
once from the pre-004 build (`main` at `c07c14d`): every weight-checking scenario of
`tests/integration/test_check_weights.py` and `tests/integration/test_register_from_record.py` is run
and its alerts and watch events are written, without ids and times, to
`tests/fixtures/equivalence/pre-004-baseline.json`. The test replays the same scenarios on the new build
and asserts both that the alerts and watch events equal the baseline row for row (ignoring the new
`rule_id` view field) and that a `file_scans` row exists for every scanned file. The second assertion
fails until `_apply_report` writes file scans, so the test fails first (constitution V); no switch to
disable the globals rules is added to production code.

## S11. Where the globals come from

**Decision**: only from picklescan reports applied by this tool: local scans in a check and recorded
scans at registration. The hub's own scan verdict (`hf-scan`) names no globals the tool can rely on, so
hub-hosted pickles are out of the strict policy and of exceptions in this feature (spec, Out of scope);
the overview shows them as covered by `hf-scan` only. Deferred below.

## S12. Fixtures and tests

**Decision**: `craft.py` gains `mixed()` (`collections.OrderedDict`, `model_dependabot_fixture.layers.CustomLayer`,
`os.system`) and `protocol2_getattr()` (`__builtin__.getattr`, `__builtin__.set`, `torch.Size`,
`model_dependabot_fixture.layers.CustomLayer`), `two_dangerous()` (`os.system`, `builtins.eval`) and
`unresolved()` (an import the scanner reports as `unknown`), all built into the test's temporary
directory like `dangerous()` (they import a dangerous global, `tests/fixtures/pickles/NOTES.md`), and
the committed `posix-path.pkl` (`pathlib.PosixPath`, suspicious). Tests in the order of the delivery
plan: migration from `schema-pre-004.sql` (including an interrupted `alerts` rebuild) and the SC-002
baseline; exception recording rules; excepted marking and release; strict
open, update and every close cause; overview states for the four-source case of US3; the exit-code
table with and without `--fail-on`.

## S13. Held dismissals (D6, FR-020)

**Finding**: every alert kind is opened through one of three insert paths, each of which looks only for
an open alert before inserting: OSV package alerts in `_raise_or_carry` (`find_open_alert` at
`lifecycle.py:673`, `insert_alert` at 698); weight-file alerts (`weight_file_scan`, `hub_scan`,
`format_policy` and the new `globals_policy`) in `_weight_alert` (924, insert at 927); and all seven
upstream kinds in `_upstream_alert` (2026, insert at 2028). The other `find_open_alert` call sites
(1041, 1495, 2112, 2311, 2370, 2403, 2448, 2599, 2663) only carry, clear or read an open alert and never
insert, so they need no change. Evidence equality already exists: `same_evidence` compares source, URL
and the content key, the canonical SHA-256 of a JSON body or else the raw SHA-256 (`store.py:420-429`).

**Definition of new evidence**: for a cause key whose most recent alert for the model is `dismissed`, a
check brings new evidence when at least one observation it would attach to the alert has no match among
the evidence already linked to the dismissed alert, where a match has the same `source`, the same `url`,
the same content key and the same `matched_identifier`; or when the severity it computes ranks above the
dismissed alert's severity. Retrieval time, run id and evidence id never count. So: the same scan report
of the same bytes, the same OSV record for the same pinned package, the same policy record or the same
refusal body again is not new; a scan of the same bytes by another scanner version that reports
differently, a modified OSV record, the advisory
matching a newly pinned package version (another `matched_identifier`), a policy set again (new
`set_at`) or a changed upstream answer is new.

**Volatile fields** (confirmed in `tests/fixtures/hf/eicar-security.json`): the hub's model
answer that `hf-scan` keeps as evidence (`_hub_observations`, `lifecycle.py:1443-1456`) carries
`downloads`, `likes` and `lastModified`, which move without any change to the scan verdict. For held
dismissals only, the content key of a JSON body is computed after removing the fields named for its
source in one table, `VOLATILE_FIELDS`, keyed by the evidence row's `source` exactly as stored (for the
hub's scan answers that is the host name `source_of` returns, not `hf-scan`); only top-level keys of a
JSON object are removed, never nested ones (to start: `downloads`, `likes` and `lastModified` for the hub
answers; any others found by the fixture survey of every folder whose answers become evidence, `hf/`
and `doi_ra/` included). The stored evidence and its `canonical_sha256` are unchanged; the table is
used only to decide whether evidence is new, so a dismissed `hub_scan` alert holds while only those
counters move.

**Fixture survey (T007, 2026-11-13)** of every JSON answer in `tests/fixtures/` `hf/`, `doi_ra/`,
`crossref/`, `datacite/`, `zenodo/`, `figshare/`, `hf_upstream/`, `hf_takedowns/` and `osv/`, for fields
that move on requests that change nothing else. The `VOLATILE_FIELDS` table to start with:

| Source (as the evidence row stores it) | Top-level fields | Seen in | Status |
| :-- | :-- | :-- | :-- |
| the hub's host (`huggingface.co`) | `downloads`, `likes`, `lastModified` | `hf/eicar-security.json`, `hf/gpt2-security.json`, `hf/gpt2-model-info.json`; `lastModified` also in `hf_upstream/model-*.json` | confirmed (the three named above) |

Proposals, **awaiting the owner's yes** (not in `VOLATILE_FIELDS`):

| Source | Field | Seen in | Note |
| :-- | :-- | :-- | :-- |
| Zenodo | `stats` (top level: `downloads`, `views`, `unique_*`, `version_*`) | `zenodo/record-3242074.json`, `zenodo/older-version.json` | usage counters, move on every read; a top-level key, so the S13 rule can remove it |
| Crossref | `message.indexed`, `message.is-referenced-by-count` | `crossref/*.json` | re-indexing time and citation count; **nested** under `message`, so the top-level-only rule cannot remove them |
| DataCite | `data.attributes.viewCount`, `viewsOverTime`, `downloadCount`, `downloadsOverTime`, `citationCount`, `citationsOverTime`, `referenceCount`, `partCount`, `partOfCount`, `versionCount`, `versionOfCount` | `datacite/findable.json`, `obsoleted.json`, `previous-version.json` | usage and link counters; **nested** under `data.attributes`, so the same limit applies |

Not volatile: OSV `modified` (changes only with the advisory, which is new evidence); Crossref
`created` and `deposited`, DataCite `created` and `updated`, Zenodo `created`, `modified` and
`updated`, and the hub's `createdAt` and per-file `lastCommit.date` (each changes only with the record
or the repository); `doi_ra/`, `figshare/` and `hf_takedowns/` carry no counters or request ids. The
two nested proposals would need the owner to allow a nested path in `VOLATILE_FIELDS`; until then a
dismissed Crossref or DataCite alert reopens when only those counters move.

**Decision**: a store method `latest_alert(model_id, cause_key)` returns the most recent alert for the
key in any state. In each insert path, when there is no open alert and that latest alert is `dismissed`,
the run's evidence for the cause is compared with the dismissed alert's linked evidence. The order
differs by path, as the code does today: `_weight_alert` receives observations and compares them
before any evidence row is stored; `_raise_or_carry` stores the OSV records as evidence before it
inserts (`lifecycle.py:681-685`) and `_upstream_alert` receives evidence ids already stored by
`_Observed` (`lifecycle.py:1987-1994`), so those two compare the stored rows, which are kept with their
run id like any other evidence. With no new evidence the dismissal holds. No alert is inserted and no
evidence is linked to any alert (on the weight path none is stored either); the alert id is added to
the run summary's new
`dismissals_held` list and the overview counts it under its source as `dismissals_held`; the alert
does not count as open anywhere, so `--fail-on` passes (US5 Independent Test, SC-006). With new evidence
a new alert opens as today, its cause gaining `reopens: {alert_id, dismissed_by, dismissal_reason,
closed_at}`, the new evidence linked. A latest alert in another closed state (`fixed`, `cleared`,
`withdrawn`) does not hold anything: the cause returned and opens a new alert, as today. The rule is
the same for every kind, so it lives in one helper the three paths call, with a unit test per path and
an integration test that repeats the probe of S5 and expects no new alert.

**Alternatives considered**: holding a dismissal for ever until a new version (hides a changed
advisory); comparing only the content key (a newly pinned version of the same package would stay
dismissed); storing the run's evidence and linking it to the dismissed alert (adds rows every run to a
closed alert, and makes "new" depend on the order of writes); moving the OSV and upstream comparisons
ahead of their evidence writes (a larger change to two read paths for no difference in outcome).

## S14. Imports the scanner could not resolve (D9)

**Finding**: picklescan marks an import it cannot resolve to a constant module and name with the
literal `unknown` and labels it dangerous; the test is a substring one, `"unknown" in g.module or
"unknown" in g.name` (installed `picklescan/scanner.py`, line 427).

**Decision**: refuse any exception and any safe list entry whose module or name contains the lower-case string `unknown` (compared case-sensitively, as the scanner does),
matching the scanner's own rule (FR-002, FR-009); `Unknown` or `UNKNOWN` is not refused, because the
scanner does not flag it either. Such a global can never be excepted or listed: its
`weight_file_scan` alert can never be fully excepted, and under strict it always stays in `unlisted`.
The owner's only way to close it is to dismiss it, with a reason, which then holds (S13). Reasoning: an
`unknown` pair names no import anybody identified, so accepting it by exact match would accept whatever
the pickle builds at load time. The cost is that a real module whose name contains `unknown` cannot be
excepted either; the scanner already calls it dangerous, so nothing that passes today is lost.

**Alternatives considered**: matching it exactly like any other global (accepts an unidentified import);
refusing only the exact strings `unknown` (narrower than the scanner's own rule).

## Deferred (not in this feature)

- The strict globals policy and exceptions for hub-hosted pickles (S11).
- A `rule show` command printing a rule's page.
- Rule IDs for watch kinds (spec, Assumptions).
- Exceptions scoped to one model, or to a global in every file (FR-002 forbids the second).

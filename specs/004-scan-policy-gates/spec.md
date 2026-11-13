# Feature Specification: Scan Exceptions, Strict Globals, Check Overview and an Opt-in Gate

**Feature Branch**: `004-scan-policy-gates`

**Created**: 2026-11-13

**Status**: Draft

**Input**: User description: "Feature 004 for model-dependabot, scope as in issue #14: (1) hash-scoped
exceptions for pickle globals, (2) owner-set strict globals policy `policy --globals default|strict`, (3) per-run
check overview per source (passed/alerted/incomplete/failed with counts), (4) stable rule IDs and one docs page per
alert kind, (5) opt-in `check --fail-on SEVERITY` gate with default exit codes unchanged. Out of scope:
architecture checks, storage-location checks, a non-public safe list. pathlib.PosixPath stays a watch event by
default."

**Tracking**: #14. **Builds on**: feature 001 (weight file scans, `policy --format`, dismissals) and feature 003
(check coverage in `inventory audit`).

## Background

A comparison with a commercial model scanner's report showed that model-dependabot finds the same pickle globals
but classifies them differently. `builtins.getattr` is dangerous here (a HIGH `weight_file_scan` alert) and only
suspicious there; `pathlib.PosixPath` is suspicious here (a `scan_suspicious` watch event) and blocking there. Real
checkpoints of common detection and change-detection models carry `getattr` and many other globals. Owners need:

- a way to accept a reviewed global in one exact file without hiding it anywhere else;
- an optional stricter policy for globals;
- a clear account of what each check run covered;
- stable names for every alert kind;
- a way for a pipeline to fail on findings without changing how scheduled runs report.

## Clarifications

### Session 2026-11-13

- Q: Does `pathlib.PosixPath` change classification? → A: No. It stays a `scan_suspicious` watch event under the
  default policy (owner ruling recorded in #14).
- Q: Can a per-hash exception cover a global the scanner calls dangerous, or only `globals_policy` findings? → A:
  Both. The alert stays visible as excepted, citing who accepted it and why, and stops counting as open or for
  `--fail-on` (FR-003). (Refined in the plan review: this is how a `weight_file_scan` alert behaves; a
  `globals_policy` alert drops the excepted global from its list instead.)
- Q: Under strict, one alert per unlisted global per file, or one per file? → A: One alert per file, naming every
  unlisted, unexcepted global in it; it closes when that list becomes empty (FR-008).
- Q: May safe list entries be module prefixes? → A: No. Every entry is one exact global (module and name); a new
  class under a trusted module is flagged until it is added (FR-009).
- Q: Do exceptions expire? → A: They last until revoked; the owner may set an optional expiry date, after which
  the finding returns at the next check citing the expired exception (FR-001, FR-004).

### Session 2026-11-13 (plan review)

Rulings by the owner on the plan's open decisions (research.md, Decisions on the plan's open questions).

- Q: Under strict, does the `globals_policy` alert also list globals the scanner calls dangerous? → A: Yes. It lists
  every global that is neither on the safe list nor excepted, dangerous ones included, so `getattr` appears
  in the HIGH `weight_file_scan` alert and in the `globals_policy` alert; one exception for (`getattr`, file hash)
  covers both (FR-008).
- Q: Does a dismissal hold at the next check? → A: Yes, in this feature. A dismissed alert is not opened
  again for the same cause unless the check brings new evidence (FR-020).
- Q: Does safe list version 1 hold `_codecs.encode` and `numpy.core.multiarray.scalar`? → A: Yes, both,
  accepting that `_codecs.encode` can rebuild arbitrary bytes (FR-009, Assumptions).
- Q: Rule ID format and where the pages live? → A: `MDB` plus three digits, grouped by family, with one
  page per ID in `docs/rules/` (FR-014, FR-015).
- Q: One overview state when a source both raised alerts and could not finish some entries? → A:
  `incomplete` wins over `alerted`; the counts still show the alerts (FR-011).
- Q: How is a stored overview shown again? → A: a new read-only command `run show RUN_ID` (FR-013).
- Q: Are `__builtin__.getattr` and `builtins.getattr` one global? → A: No. Globals match exactly as the
  scanner reports them (FR-002, FR-009).
- Q: How do exceptions act on the two alert kinds? → A: Two ways. A `weight_file_scan` alert stays open
  but is marked excepted once every global that raised it is excepted; a `globals_policy` alert loses the excepted
  global from its list and clears when the list is empty (FR-003, FR-008).
- Q: When does an exception close a `globals_policy` alert? → A: at the next check that asks a weight source, not
  when the exception is recorded (FR-010).
- Q: Do exceptions and the strict policy cover hub weight files? → A: No, not in this feature: no source
  reads the globals of a hub file (Out of scope).
- Q: Does the gate pass when a check could not cover what it was asked to? → A: No ("fail on incomplete
  too"). With `--fail-on`, the command also exits with the gate code when any model in scope has a source in
  the incomplete state, when no relevant source checked a model or when the scope matched no model. Without
  `--fail-on` nothing changes, and exit 2 still beats the gate code (FR-021).
- Q: Can an exception or a safe list entry accept an import the scanner could not resolve? → A: No. A global
  whose module or name contains the lower-case string `unknown` (compared case-sensitively), the scanner's mark
  for an unresolved import, can be neither excepted nor safe-listed (FR-002, FR-009).
- Q: What does `--fail-on` do for a model whose incomplete state never clears? → A: Document and test it; FR-021
  stays as it is. Such a model trips `--fail-on` on every run unless `--source` leaves that source out
  (Edge Cases).

### Session 2026-11-14 (implementation review)

- Q: Do `builtins.frozenset` and `__builtin__.frozenset` stay on safe list version 1? → A: No. They are not on
  PyTorch's default allow-list (research S3), so they are dropped and version 1 holds 30 entries.
- Q: Which fields are ignored when deciding whether evidence is new for a held dismissal? → A: The listed
  counters and re-indexing times of every source, nested ones included, given as dotted paths (research S13).
- Q: Where does an excepted alert appear in the `alerts` JSON? → A: Only in `excepted`; `alerts` never holds an
  excepted alert, and `--state excepted` gives `alerts: []` and the list (contracts/cli.md).

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Accept a reviewed global in one exact file (Priority: P1)

An owner has reviewed a checkpoint whose pickle imports a flagged global (for example `getattr` in a pose detection
checkpoint) and judges it acceptable for that file. They record an exception naming the global, the file's SHA-256,
a reason and who accepted it. From then on, the finding caused by that global in that file is shown as excepted,
with the exception as its evidence. The same bytes registered under another model or path stay excepted. A
different file with the same global, or a new release of the same model with different bytes, raises the finding
again.

**Why this priority**: without it, every model built on a common framework carries a permanent alert that owners
learn to ignore. It is also what makes a strict policy (US2) usable.

**Independent Test**: register two models whose weight files contain the same global but different bytes. Record
an exception for one file's hash and run a check: only the other file still raises the finding. Then register the
excepted bytes under a third model: it is excepted too.

**Acceptance Scenarios**:

1. **Given** an open finding for global X in a file with SHA-256 Y, **When** the owner records an exception for
   (X, Y) with a reason and their name, **Then** the next check shows the finding as excepted, cites the exception
   (who, when, reason) and no longer counts it as open.
2. **Given** an exception for (X, Y), **When** a file with SHA-256 Z ≠ Y containing X is checked, **Then** the
   finding is raised as normal.
3. **Given** an exception for (X, Y), **When** the file with SHA-256 Y also contains global W, **Then** the finding
   for W is unaffected.
4. **Given** an exception, **When** the owner revokes it with a reason, **Then** the next check raises the finding
   again and the revocation is recorded.
5. **Given** an exception is recorded without a reason or without who accepted it, **Then** it is refused.

---

### User Story 2 - A strict policy for globals (Priority: P1)

An owner who wants a tighter bar sets `policy --globals strict` for a model. Under strict, any global in a pickle
weight file that is not on the project's published safe list raises an alert, even if the scanner only calls it
suspicious. Under the default policy nothing changes from today. Exceptions from US1 apply under both policies.

**Why this priority**: owners with a supply-chain mandate need to treat unknown imports as findings, and the
exception mechanism makes that workable.

**Independent Test**: set strict on a model whose weight file contains one safe-listed global, one suspicious
global and one dangerous global. Confirm there is one HIGH alert for the dangerous global (as today) and one
`globals_policy` alert listing the dangerous and the suspicious global, and that the safe-listed global appears in
neither. Record one exception for (dangerous global, file hash) and check again: the HIGH alert is excepted and
the `globals_policy` alert lists only the suspicious global. Then set the policy back to default and confirm the
`globals_policy` alert closes with that change as its recorded cause.

**Acceptance Scenarios**:

1. **Given** the default globals policy, **When** a check runs, **Then** alerts and watch events are exactly as
   before this feature, apart from held dismissals (FR-020).
2. **Given** strict, **When** a pickle file contains globals outside the safe list, **Then** one alert is raised
   for the file that names each of those globals, dangerous ones included, the file's SHA-256, the safe list's
   version and the policy setting (who set it, when). A dangerous global also keeps its HIGH alert as today.
3. **Given** strict and an exception for (global, file hash), **Then** the `globals_policy` alert does not list that
   global, and a HIGH alert for the same global in the same file is excepted by the same exception.
4. **Given** strict is turned off, **When** the next check runs, **Then** open `globals_policy` alerts close with the
   policy change as the recorded cause.
5. **Given** strict, **When** a scan was incomplete, **Then** the file is not treated as clean and the incomplete
   scan is reported as today.

---

### User Story 3 - See what a check run covered (Priority: P2)

After `check`, the owner sees an overview of every source the run asked. Each source is in one of four states:

- **passed**: asked, and no alerts are open from it;
- **alerted**: asked, and alerts from it are open;
- **incomplete**: asked, but it could not finish for some entries;
- **failed**: it could not be asked or did not answer.

Each row gives counts of entries checked, alerts and watch events. A model with no findings can be told apart
from a model that was not checked.

**Why this priority**: "no alerts" must never read as "safe" (feature 003's principle), and a run summary is where
owners and schedulers look first.

**Independent Test**: run a check where one source succeeds with no findings, one raises an alert, one has an
incomplete scan and one is unreachable. Confirm the overview shows four distinct states with correct counts, in
both text and JSON output.

**Acceptance Scenarios**:

1. **Given** a check over several models, **When** it finishes, **Then** the output ends with one overview row per
   source asked, with its state and counts, overall and per model.
2. **Given** a source failed, **Then** its row says failed with the reason, and the existing exit code 2 behaviour
   is unchanged.
3. **Given** a model none of whose entries any source could check, **Then** the overview says so for that model.

---

### User Story 4 - Stable rule IDs with documentation (Priority: P2)

Every alert kind has a stable rule ID, shown with each alert in text and JSON output. Each ID has one
documentation page saying what raises it, what it does not prove, how it closes and how to fix or accept it.

**Why this priority**: owners and pipelines need a name that does not change between releases to filter, discuss
and document findings.

**Independent Test**: list every alert kind the tool can raise. Confirm each has exactly one rule ID, each ID has
a page, and every alert printed by a check carries its ID.

**Acceptance Scenarios**:

1. **Given** any alert, **When** shown in text or JSON, **Then** it includes its rule ID.
2. **Given** the documentation, **Then** there is one page per rule ID with the four required sections.
3. **Given** a future release, **Then** an existing rule ID is never reused for a different meaning.

---

### User Story 5 - An opt-in gate for pipelines (Priority: P3)

A pipeline runs `check --fail-on HIGH`. If, after the check, open alerts at or above HIGH exist for the models in
the run's scope, the command exits with a distinct non-zero code. Without `--fail-on`, exit codes are exactly as
today: `check` never exits non-zero just because alerts exist.

**Why this priority**: useful for release pipelines, but only once findings are trustworthy (US1 to US4).

**Independent Test**: with one open HIGH alert and every source complete, `check` exits 0,
`check --fail-on CRITICAL` exits 0 and `check --fail-on HIGH` exits with the gate code. Dismiss or except the
alert and confirm `--fail-on HIGH` exits 0. Make one scan incomplete and confirm `--fail-on CRITICAL` exits with
the gate code.

**Acceptance Scenarios**:

1. **Given** no `--fail-on`, **Then** exit codes match the current README table for every case.
2. **Given** `--fail-on SEVERITY` and an open alert at or above it in scope, **Then** the command exits with the
   gate code and says which alerts tripped it.
3. **Given** `--fail-on SEVERITY`, complete coverage (FR-021) and only dismissed, excepted or lower-severity
   alerts, **Then** it exits 0.
4. **Given** `--fail-on` and a failed source, **Then** the command exits 2. A source failure is reported ahead of
   the gate.
5. **Given** an alert the owner dismissed, **When** the next check finds the same cause with no new evidence,
   **Then** the alert stays dismissed, no new alert is opened and `--fail-on` does not count it. **When** the
   check brings new evidence for that cause, **Then** a new alert opens, citing the dismissed one and the new
   evidence (FR-020).
6. **Given** `--fail-on SEVERITY` and no source failed, **When** a source of a model in scope is
   incomplete, a model in scope was checked by no relevant source or the scope matched no model, **Then** the command
   exits with the gate code and names the incomplete sources, the unchecked models or the empty scope, whatever
   the alerts (FR-021). A gate never passes on a source asked that is incomplete, a model no asked source
   checked or an empty scope.

### Edge Cases

- An exception names a global the file does not contain: it is recorded but listed as not in use.
- The same file hash appears in several models: one exception covers all of them, and its listing shows where it
  applies.
- A hub weight file: no source reads its globals, so neither exceptions nor the strict globals policy apply to it
  in this feature. An exception recorded for its pinned SHA-256 is accepted but listed as not in use.
- The safe list changes in a release: `globals_policy` alerts are re-evaluated at the next check, and alerts for
  globals newly added to the list close with the list version as the cause.
- `--fail-on UNKNOWN`: alerts with unknown severity count, as UNKNOWN is the lowest in the scale.
- An exception's expiry date passes between checks: the next check raises the finding again and names the
  expired exception; an expiry date in the past is refused when recording.
- A check whose model scope matches nothing: the overview says no models were checked. Without `--fail-on` it
  exits 0; with `--fail-on` it exits with the gate code, since nothing was covered (FR-021).
- A model whose incomplete state never clears trips `--fail-on` on every run unless `--source` leaves that source
  out, which is the only remedy (FR-021 is unchanged). Confirmed: a version registered from a registration record
  whose bytes are absent gets `weight_file_absent` at every check that asks `picklescan`. Inferred to behave the
  same: a hub file whose verdict stays `hub_scan_unknown`, a gated base model refused on every run
  (`base_model_refused`) and a paper DOI that stays `paper_not_found`.
- `--fail-on` with `--source` leaving some sources out: the gate judges only the sources asked; a model whose
  relevant entries no asked source covers reads as not checked and trips the gate.

## Requirements *(mandatory)*

### Functional Requirements

**Exceptions (US1)**

- **FR-001**: Owners MUST be able to record an exception for a (global, file SHA-256) pair, with a required reason,
  a required name of who accepted it and an optional expiry date. The time is recorded. An exception lasts until
  it is revoked or its expiry date passes; after expiry the finding returns at the next check, citing the expired
  exception.
- **FR-002**: An exception MUST apply only to that exact global in a file with that exact SHA-256, wherever the file
  is registered, and to nothing else. An exception for a global whose module or name contains the lower-case string `unknown` (compared case-sensitively, as the scanner does), the
  scanner's mark for an import it could not resolve, MUST be refused.
- **FR-003**: An exception can cover both a global the scanner calls dangerous (for example `getattr`, a HIGH
  `weight_file_scan` alert) and a finding of the strict globals policy; one exception for a global covers it in
  both alerts. A `weight_file_scan` alert whose globals are all excepted MUST stay visible as excepted, citing the
  exception, and MUST NOT count as open for summaries or the gate. For a `globals_policy` alert see FR-008 and
  FR-010; its excepted globals stay visible in the alert while it is open and, once it closes, in its history and
  in the exception listing.
- **FR-004**: Owners MUST be able to list exceptions, with where each applies, whether it is in use, when it was
  recorded and when it expires, and revoke one with a reason. The revocation is recorded and the finding returns at the next check.
- **FR-005**: Exceptions, globals policies and stored overviews MUST NOT change any inventory, and the tool MUST
  NOT act on a model (constitution III).

**Strict globals policy (US2)**

- **FR-006**: Owners MUST be able to set `default` or `strict` for globals per model, recorded with who set it and
  when, separately from the existing format policy.
- **FR-007**: Under `default`, classification and alerts MUST be unchanged from before this feature, apart from
  held dismissals (FR-020), and `pathlib.PosixPath` remains a watch event.
- **FR-008**: Under `strict`, a scanned pickle file with any global that is neither on the safe list nor excepted,
  whatever the scanner's label (dangerous included), MUST raise one alert for that file, naming every such global, the file SHA-256, the safe list version and the
  policy setting. When globals are excepted or join the safe list, they leave the alert's list; the alert closes
  when the list is empty.
- **FR-009**: The safe list MUST be public and versioned in the repository, and each alert MUST name every global
  that raised it. Every entry MUST be one exact global (module and name); prefixes and wildcards are not allowed,
  nor is a global whose module or name contains the lower-case string `unknown` (compared case-sensitively, as the scanner does).
- **FR-010**: `globals_policy` alerts MUST close automatically, with the cause recorded, at the next check that asks
  a weight source after the policy returns to default, the remaining globals join the safe list or exceptions
  cover them. Recording an exception or a policy changes no alert by itself.

**Check overview (US3)**

- **FR-011**: Each `check` run MUST report, per source asked, one of passed, alerted, incomplete or failed, with
  counts of entries checked, open alerts and watch events, overall and per model, in text and JSON. One further
  row, `policy`, reports the findings of the owner's format and globals policies, which no source raises.
- **FR-012**: The overview MUST distinguish a model with no findings from a model with no entries any source could
  check.
- **FR-013**: The overview MUST be stored with the run so it can be shown again later.

**Rule IDs and documentation (US4)**

- **FR-014**: Every alert kind MUST have one stable rule ID, shown with each alert in text and JSON output.
- **FR-015**: Each rule ID MUST have one documentation page covering what raises it, what it does not prove, how it
  closes and how to fix or accept it.
- **FR-016**: A rule ID MUST never be reused for a different meaning, and a test MUST fail if an alert kind lacks an
  ID or a page.

**Gate (US5)**

- **FR-017**: `check --fail-on SEVERITY` MUST exit with a distinct code, documented in the exit code table, when
  open (not dismissed, not excepted) alerts at or above SEVERITY exist for models in the run's scope after the
  check, and MUST list those alerts.
- **FR-018**: Without `--fail-on`, every exit code MUST be unchanged.
- **FR-019**: When a source fails, exit code 2 MUST take precedence over the gate code; an unexpected error (exit 3)
  takes precedence over both.

**Dismissals (US5)**

- **FR-020**: A dismissal MUST hold at later checks: when a check finds the cause of a dismissed alert again and
  brings no new evidence for it (research S13), the alert MUST stay dismissed and no new alert MUST open. New
  evidence MUST open a new alert for the cause that cites the dismissed alert. This applies to every alert kind.

**Gate coverage (US5)**

- **FR-021**: With `--fail-on`, the command MUST also exit with the gate code, when no source failed, if any model in
  the run's scope has a source in the incomplete state, if no relevant source checked a model or if the scope
  matched no model, and MUST name each such source, model or the empty scope. Without `--fail-on` none of this
  changes any exit code.

### Key Entities

- **Global exception**: a global (module and name), a file SHA-256, a reason, who accepted it, when, an optional
  expiry date and an optional revocation (who, when, reason). It applies wherever that hash is registered.
- **Globals policy**: per model, `default` or `strict`, with who set it and when.
- **Safe list**: a public, versioned list of globals accepted under strict.
- **Check overview**: for each check run, a state and counts per source and per model.
- **Rule ID**: a stable identifier for an alert kind, with its documentation page.
- **Held dismissal**: a check that found a dismissed alert's cause again with no new evidence; recorded in the
  run, the alert unchanged.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: With one exception recorded, re-checking a model whose only finding is the excepted global leaves 0
  open alerts for it, while a model with the same global in different bytes still has 1.
- **SC-002**: Under the default globals policy, a check over the existing recorded test inventories produces the
  same alerts and watch events as before this feature (0 differences); no baseline scenario dismisses an alert,
  so held dismissals (FR-020) do not enter it.
- **SC-003**: 100% of alert kinds have a rule ID and a documentation page, enforced by a test.
- **SC-004**: From a single `check` output, without other commands, an owner can tell which sources covered each
  model and which did not.
- **SC-005**: For every case in the current exit code table, `check` without `--fail-on` returns the same code.
- **SC-006**: After an owner dismisses an alert, a repeat check with unchanged sources opens 0 new alerts for its
  cause, and `check --fail-on` at its severity exits 0 when coverage is complete (FR-021).

## Assumptions

- Exceptions key on the SHA-256 the inventory already pins, so files without a pinned SHA-256 cannot be excepted.
- The safe list starts from the scanner's own innocuous set, plus the standard tensor-rebuild and container
  globals found in common PyTorch checkpoints that PyTorch's own restricted loader accepts, plus `_codecs.encode` and `numpy.core.multiarray.scalar` (owner's
  ruling; `_codecs.encode` can rebuild arbitrary bytes, a trade-off recorded in research S3). It is reviewed and
  versioned in the repository.
- `globals_policy` alerts are MODERATE, matching the existing format policy alert.
- The gate code is a new exit code (4), added to the documented table.
- Rule IDs cover alert kinds. Watch event kinds are documented on the page of the rule they relate to and do not
  get IDs in this feature.
- Out of scope: checks on model architecture or framework operators, checks on approved storage locations, any
  safe list that is not public and exceptions or the strict globals policy for hub weight files (no source reads
  their globals).

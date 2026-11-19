# Feature Specification: An Actionable Alert View for Model Maintainers

**Feature Branch**: `005-actionable-alert-view`

**Created**: 2026-11-19

**Status**: Draft

**Input**: User description: "Feature 005 for model-dependabot, scope as in issue #7 (roadmap phase 2 of RFC #6,
decision D3: the first user is the model maintainer). For each finding, an optional advisory view that shows the
source's severity (or the owner's declared policy severity) unchanged; the affected inventory entry and how it
relates to the model, with runtime use or deployment marked as declared, observed or unknown; what is established
and what is inferred, with evidence links and limitations; fixed, type-specific review steps and an explicit
'impact undetermined' state. Out of scope: weighted risk scores and any claim that a retraction, licence change or
clean scan settles impact."

**Tracking**: #7, part of the roadmap #6. **Decisions**: D1 and D3 in `specs/decisions/2026-11-04-rfc-5-6.md`
(D6 governs how imported claims are shown). **Builds on**: feature 001 (alerts, evidence, dismissals), feature 002
(upstream alert kinds), feature 003 (claim verification) and feature 004 (rule IDs, rule pages, exceptions, held
dismissals).

## Background

Today an alert tells the maintainer what matched and on what evidence, but not what to do about it. `alert show`
prints one line (rule ID, severity, state, cause) and the evidence rows (`src/model_dependabot/cli.py:493-496`,
`src/model_dependabot/reports.py:241-244`). The JSON view carries the stored fields and nothing derived
(`src/model_dependabot/reports.py:70-90`). What is missing for a maintainer:

- **Which entry, and how it relates.** An alert's cause names an identifier (a package and version, a file, a
  repository, a DOI), but the view does not say which inventory entry that is, which manifest section declared it,
  or whether the entry is still in the current version (`opened_in_version` and `current_version` are shown as
  bare numbers, `src/model_dependabot/reports.py:81-82`).
- **Whether it is used at runtime.** Nothing records it. The manifest has no key for runtime use or deployment
  (`src/model_dependabot/manifest.py:21-27`; unknown keys are an error, `manifest.py:3-4`), and no source observes
  a deployed model. The only related record is the dismissal reason `not_used_at_runtime`
  (`src/model_dependabot/store.py:72`), which the owner gives after the fact.
- **What is known and what is not.** Each rule page says what the alert does not prove
  (`docs/rules/MDB*.md`, section "What it does not prove"), but the alert view does not.
- **What to do next.** Each rule page says how to fix or accept the alert ("How to fix or accept it"), in prose,
  away from the alert.

What exists and this feature reuses unchanged:

- Twelve alert kinds, each with one stable rule ID and one page (`src/model_dependabot/rules.py:28-118`,
  `src/model_dependabot/store.py:52-66`).
- Severity and its origin, stored with every alert (`store.py:264-265`): for package advisories the advisory's own
  severity or CVSS band (`database_specific`, `cvss_v3`, `cvss_v4` or `unknown`,
  `src/model_dependabot/matching/severity.py:1-7`); for the owner's policies and the upstream kinds, `policy`
  (`src/model_dependabot/lifecycle.py:173`). The scale is `CRITICAL`, `HIGH`, `MODERATE`, `LOW`, `UNKNOWN`
  (`severity.py:24`).
- Alert states `open`, `fixed`, `dismissed`, `withdrawn` and `cleared` (`store.py:67`), plus the derived view
  state `excepted` (`reports.py:56-63`).
- Four inventory entry kinds: `weight_file`, `package`, `base_model` and `dataset` (`store.py:48`), with the papers
  a dataset cites held on the dataset entry (`store.py:173`).
- The verification state of each security-relevant claim of an entry: `owner`, `measured`, `confirmed`,
  `unverified` or `contradicted` (`src/model_dependabot/assurance/trust.py:10-14`).

## Clarifications

No session yet. Three questions are open and marked [NEEDS CLARIFICATION] in FR-001, FR-008 and FR-012, each with
a recommended answer.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - See which entry an alert affects and how it relates to the model (Priority: P1)

A maintainer gets an alert and asks for its advisory view. Next to the unchanged alert, the view names the affected
inventory entry (kind, identifier, where the manifest declared it, the model version it is in), how that entry
relates to the model (for example "a package pinned in the model's environment lock" or "a paper the owner ties to
a declared dataset") and whether its use at runtime or in deployment is declared, observed or unknown. Where the
tool has no record, it says `unknown`; it never guesses.

**Why this priority**: the first question a maintainer asks is "is this mine, and where is it used?". Without it
every other part of the view lacks context.

**Independent Test**: register a model whose manifest pins a weight file, a locked package, a base model and a DOI
dataset with a paper DOI, and raise one alert of each family from recorded responses. Ask for the advisory view of
each: every one names the right entry and manifest section, a relationship from the fixed list and runtime use
`unknown`. Dismiss the package alert with `not_used_at_runtime` and confirm its view shows the owner's declaration,
attributed to who made it and when.

**Acceptance Scenarios**:

1. **Given** an open alert, **When** the maintainer asks for its advisory view, **Then** the view names the
   affected entry (entry kind, identifier, manifest section, model version) and one relationship from the fixed
   list (FR-005).
2. **Given** no record of runtime use for the entry, **Then** runtime use reads `unknown` and the view says that
   no source observes runtime use.
3. **Given** the alert's entry is no longer in the model's current version, **Then** the view says so and names
   the version that last held it.
4. **Given** an alert whose identifier matches no inventory entry of the model (for example a repository-wide
   alert rekeyed by repository, `store.py:16`), **Then** the entry reads `unresolved` with the reason; the view
   picks no entry by similarity.
5. **Given** the entry is held in several versions or under several locations, **Then** the view lists each place,
   in a fixed order.

---

### User Story 2 - Tell what is established from what is not (Priority: P1)

The view separates three kinds of statement. **Established**: facts the alert's evidence shows, each citing the
evidence row it rests on (source, retrieval time, exact identifier matched). **Not established**: the questions
the evidence does not answer, always including whether the model is affected. **Limitations**: what the check that
raised the alert cannot see. Impact is always shown as `impact undetermined` unless the owner has recorded a
conclusion, which is shown as the owner's, never as the tool's.

**Why this priority**: issue #7 and RFC #6 (acceptance criterion 3) require severity, relationship, unknown impact
and review actions to be represented separately. A view that blends a match with an impact claim would break
constitution principle I (no alert from inference).

**Independent Test**: for one alert of every rule ID, render the view and confirm: every established statement
cites at least one evidence row that belongs to the alert; the not-established list includes the impact question;
the limitations match the rule's "What it does not prove" text; impact reads `impact undetermined`. Then confirm
that no view contains any phrase on the fixed list of impact verdicts (FR-011).

**Acceptance Scenarios**:

1. **Given** any alert, **Then** each established statement cites one or more of the alert's evidence rows, and
   nothing without evidence appears as established.
2. **Given** a `paper_retracted` alert, **Then** the view does not say the dataset or the model is compromised; it
   lists "whether the retraction affects the data this model was trained or evaluated on" as not established.
3. **Given** a `licence_changed` alert, **Then** the view does not say the model's rights are lost or kept; it
   lists the effect on the licence the model was obtained under as not established and as a matter for the owner's
   own review.
4. **Given** an entry whose claim is imported and `unverified` or `contradicted` (feature 003, decision D6),
   **Then** the view shows that state with the claim and never lists the claim as established.
5. **Given** an excepted or dismissed alert, **Then** the view shows the exception or the dismissal (who, when,
   reason, note) as the owner's recorded decision, separate from what the tool established.
6. **Given** the model has no open alerts, **Then** the view says that no alert is open and does not say the model
   is safe or its inventory complete.

---

### User Story 3 - Follow fixed review steps for the alert's kind (Priority: P2)

The view ends with numbered review steps fixed for the alert's rule ID: what to check, in what order, and how
the alert can close (by a new version, by its source or by a recorded dismissal or exception). The steps are the
same for every alert of a rule ID, filled in only with that alert's own identifiers, so two maintainers looking at
the same alert see the same steps.

**Why this priority**: steps make the alert actionable, but they are only trustworthy once the entry (US1) and
the evidence split (US2) are right.

**Independent Test**: confirm every rule ID in `rules.py` has a step list and that a test fails for a rule ID
without one. Render the view for two alerts of the same rule ID on different entries: the steps differ only in the
substituted identifiers.

**Acceptance Scenarios**:

1. **Given** any alert, **Then** the view shows the review steps of its rule ID, numbered, with the alert's
   identifiers substituted and the link to the rule page.
2. **Given** a new alert kind is added in a later feature, **When** it has no step list, **Then** a test fails
   (as feature 004's FR-016 test does for a missing rule page).
3. **Given** the steps of a rule ID, **Then** none of them is an action the tool takes; each is something the
   maintainer does (constitution III).

---

### User Story 4 - Keep today's output and exit codes unchanged (Priority: P3)

A pipeline or script that reads `alerts`, `alert show` or `check` today keeps getting exactly the same output and
exit codes. The advisory view appears only when asked for.

**Why this priority**: the view is additive; scheduled runs and the feature 004 gate must not notice it.

**Independent Test**: run the recorded fixture suite's `alerts`, `alert show`, `history`, `run show` and `check`
invocations before and after the feature, without the new option; compare text and JSON byte for byte.

**Acceptance Scenarios**:

1. **Given** no advisory option, **Then** every command's text, JSON and exit code is unchanged.
2. **Given** the advisory option, **Then** the exit code is the same as without it.
3. **Given** `check --fail-on`, **Then** the gate counts exactly the alerts it counts today; nothing in the view
   changes what is open, excepted or dismissed.

### Edge Cases

- An alert opened in version 1 and still open in version 3: the view uses the entry as it stands in the current
  version and names the version the alert was opened in.
- A `fixed` alert: its entry is not in the version that fixed it; the view shows the entry from the last version
  that held it and the fixing version.
- A `withdrawn` or `cleared` alert: the view shows the source's withdrawal or clearance as established, with its
  evidence, and does not say the model was never affected.
- A package alert for an alias group (several advisory ids, `lifecycle.py:858-880`): one view, listing every id;
  severity is the alert's stored severity, unchanged.
- A package locked with an environment marker (`src/model_dependabot/lockfile.py:4`): the view names the marker
  and lists "whether the marker holds where the model runs" as not established.
- A hub weight file (no local bytes): the view says no local scan read it and the hub's own scan verdict is the
  source.
- A weight file registered from a registration record whose bytes are absent (`weight_file_absent`): the view says
  the bytes were not read in this place.
- An alert whose evidence rows have been redacted: the view links the stored evidence and says which fields were
  removed, as `alert show` does today (README "Commands").
- An alert from a database created before this feature: the view works from the stored rows; no migration is
  needed for reading.
- A model with a base model and an alert on that base model: the relationship is the single declared base model;
  multi-parent lineage is #9 and out of scope.

## Requirements *(mandatory)*

### Functional Requirements

**The view (all stories)**

- **FR-001**: Maintainers MUST be able to ask for the advisory view of one alert and of every alert of a model in
  one command, as an option the existing output does not show by default.
  [NEEDS CLARIFICATION: interface. Recommended: an opt-in flag on the existing commands, `alert show ALERT_ID
  --advice` and `alerts ID --advice`, so the view sits next to the alert it explains and no new command name is
  needed; the alternative is a separate read-only command `alert advise ALERT_ID`.]
- **FR-002**: The view MUST be read-only: it MUST NOT write to the store, change an alert's state, open or close an
  alert, record a run or reach any network source. It is computed from stored rows at read time.
- **FR-003**: The view MUST be deterministic: the same stored rows give byte-identical JSON and text, with lists
  in a documented fixed order. Alerts are listed in the order `alerts` lists them today (`reports.py:125-127`).
- **FR-004**: The view MUST show the alert's severity and severity origin exactly as stored. It MUST NOT compute,
  show or sort by any score, weight or adjusted severity.

**Entry and relationship (US1)**

- **FR-005**: The view MUST name the affected inventory entry (entry kind, identifier, manifest section, model
  version) and one relationship from a fixed list keyed by entry kind and alert kind. The initial list:
  `weight file of this model` (local or hub, with its location), `package pinned in this model's environment
  lock`, `declared base model`, `declared dataset` and `paper cited by a declared dataset` (two steps from the
  model). The list is versioned with the code; a test MUST fail if an alert kind has no relationship.
- **FR-006**: When the alert's identifier matches no entry of the model, the entry MUST read `unresolved` with the
  reason. The view MUST NOT choose an entry by similarity, name or partial match.
- **FR-007**: Runtime use or deployment of the entry MUST read one of `declared`, `observed` or `unknown`, with
  its basis: who declared it and when, or which source observed it, or why it is unknown.
- **FR-008**: The basis of a `declared` runtime-use state MUST be a record the owner made.
  [NEEDS CLARIFICATION: where a declaration comes from in this feature. Recommended: no new input in 005. The
  state is `declared not used` only where the owner dismissed the alert with `not_used_at_runtime`, attributed to
  who dismissed it and when; otherwise `unknown`. `observed` is defined but no source in 005 produces it. A
  manifest key for runtime use is left to a later feature, because adding one makes manifests unreadable by
  earlier releases (`manifest.py:3-4`); the alternative is an optional per-entry manifest key now.]

**Established, not established, limitations (US2)**

- **FR-009**: The view MUST list established statements, each citing one or more evidence rows of the alert by
  evidence id (source, URL, retrieval time, matched identifier). A statement with no evidence row MUST NOT be
  listed as established.
- **FR-010**: The view MUST list what is not established, always including the impact on this model, and the
  limitations of the check that raised the alert. Limitations MUST come from one source of text per rule ID that
  the rule page's "What it does not prove" section also uses, so the two cannot drift.
- **FR-011**: The view MUST NOT state or imply that a retraction compromises a model, that a licence change
  removes or keeps rights, that a clean or excepted scan makes a file safe, that a withdrawn or cleared alert
  proves the model was never affected or that no open alert means the model or its inventory is complete. A test
  MUST check every rule ID's view against a fixed list of such verdict phrases.
- **FR-012**: Impact MUST read `impact undetermined` unless the owner has recorded a conclusion, which the view
  shows as the owner's, with who, when and the reason, never as the tool's.
  [NEEDS CLARIFICATION: whether 005 lets the owner record an impact conclusion. Recommended: no; 005 stays
  read-only. The existing dismissal (reason, note, who, when) and the feature 004 exception are the only owner
  conclusions the view shows; impact stays `impact undetermined` for every other alert. The alternative is a new
  write command such as `alert assess ALERT_ID --impact affected|not-affected --reason TEXT --by NAME`.]
- **FR-013**: A claim the inventory holds as `unverified` or `contradicted` (feature 003, decision D6) MUST be
  shown with that state and MUST NOT appear as established.

**Review steps (US3)**

- **FR-014**: Every rule ID MUST have a fixed, numbered list of review steps, versioned in the repository, with
  placeholders filled only from the alert's own stored fields. The rule page's "How to fix or accept it" section
  and the view MUST come from the same text. A test MUST fail if a rule ID has no step list.
- **FR-015**: Every step MUST be an action for the maintainer, never one the tool takes (constitution III), and
  the last step MUST say how the alert can close: by a new version, by its source, or by a recorded dismissal or
  exception.

**Compatibility (US4)**

- **FR-016**: Without the advisory option, the text, JSON and exit code of every command MUST be unchanged, byte
  for byte, against the recorded fixtures.
- **FR-017**: The advisory option MUST NOT change any exit code, and nothing in the view MUST change what
  `check --fail-on` counts (feature 004, FR-017 to FR-021).
- **FR-018**: The JSON shape of the view MUST be documented in this feature's CLI contract, kept apart from the
  existing alert fields so a reader of today's fields is unaffected.

### Initial review steps (content to be fixed in the plan)

One step list per rule ID (`rules.py:28-118`). The themes below set the scope; the plan fixes the wording and the
order.

| Rule | Kind | Steps cover |
| :-- | :-- | :-- |
| MDB101 | `weight_file_scan` | which global raised it; where the file came from; load only in an isolated place if at all; convert to a code-free format, or record an exception for the exact hash |
| MDB102 | `hub_scan` | the hub's verdict and its date; whether the pinned revision is the one deployed; move to a revision or file the hub calls safe, or dismiss with a reason |
| MDB103 | `format_policy` | which file is code-capable; whether a pinned, confirmed code-free file can replace it; register a version with it, or set the policy back with a recorded reason |
| MDB104 | `globals_policy` | each listed global; whether it belongs to the framework the model uses; record an exception per global and hash, or convert the file |
| MDB201 | `package_advisory` | the advisory's affected ranges and fixed versions; whether the affected part of the package is used by the model's code; lock a fixed version and register it, or dismiss with a reason |
| MDB301 | `dataset_retracted` | the retraction notice; whether the model was trained or evaluated on this version of the data; decide with the dataset's maintainers; register a version without it, or dismiss |
| MDB302 | `paper_retracted` | the retraction notice and its stated reason; whether that reason touches the data the model used; dismiss or move dataset |
| MDB303 | `dataset_removed` | the removal record; whether a local copy with the pinned hash exists; whether the terms allow continued use, for the owner's own review |
| MDB304 | `dataset_not_findable` | the failed lookups; whether the DOI moved; re-pin, or dismiss |
| MDB401 | `licence_changed` | the recorded and the new licence; which licence the model was obtained under; a review by whoever decides licensing for the owner |
| MDB501 | `base_model_disabled` | the hub's status; whether the pinned revision is still held locally; a new base model or a recorded dismissal |
| MDB502 | `base_model_unavailable` | how it became unavailable (gated, removed); whether the pinned revision is held locally; the same |

### Key Entities

- **Advisory view**: per alert, the alert unchanged plus the affected entry, its relationship, runtime use,
  established statements, not-established statements, limitations, impact and review steps. Derived at read time;
  never stored.
- **Affected entry**: an inventory entry (kind, identifier, manifest section, versions and locations) or
  `unresolved` with a reason.
- **Relationship**: one value from a fixed, versioned list per entry kind and alert kind.
- **Runtime use**: `declared`, `observed` or `unknown`, with its basis.
- **Statement**: text, its kind (`established`, `not established` or `limitation`) and, for an established one,
  the evidence ids it cites.
- **Impact**: `impact undetermined`, or an owner's recorded conclusion with who, when and why.
- **Review step list**: per rule ID, numbered steps with placeholders, shared with the rule page.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 100% of rule IDs (12 today) have a relationship, a limitations text and a review step list, enforced
  by a test that fails for a rule ID missing any of them.
- **SC-002**: Without the advisory option, the recorded fixture invocations of `alerts`, `alert show`, `history`,
  `run show` and `check` give 0 differences in text, JSON and exit code.
- **SC-003**: In views rendered for one alert of every rule ID, 100% of established statements cite at least one
  evidence row of that alert, and 0 views contain a phrase from the fixed verdict list (FR-011).
- **SC-004**: Rendering the view twice from the same store gives byte-identical output, and rendering it makes 0
  network requests and 0 store writes.
- **SC-005**: From one advisory view, without another command, a maintainer can answer four questions: which entry
  is affected, how it relates to the model, what is established and what to do next. Checked against a scripted
  walkthrough of one alert per rule family (weight files, packages, datasets and papers, licences, base model).

## Assumptions

- The first user is the model maintainer (D3). Views for a security reviewer or a release engineer can follow and
  are out of scope.
- Relationships use the manifest as it is: one `[base_model]`, datasets without a stated purpose (training or
  evaluation). Multi-parent lineage (#9, D5) extends the relationship list later.
- Watch events keep their current view; the advisory view covers alerts, including excepted, dismissed and closed
  ones.
- The text of limitations and review steps moves from the rule pages into one shared source; the rule pages keep
  their four sections (feature 004, FR-015) and are generated from, or checked against, that source.
- Out of scope: any risk score or weighted ranking; any statement that settles impact; new sources; a stored
  snapshot of the view; automatic action of any kind; the release gate (#8, D4); changes to `check`.

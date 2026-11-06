# Feature Specification: Evidence-Backed Dependency Discovery and Inventory Assurance

**Feature Branch**: `ccr-0b4da713-ncfv4q` (spec directory `003-inventory-assurance`)

**Created**: 2026-11-04

**Status**: Draft

**Input**: User description: "Evidence-backed dependency discovery and inventory assurance (RFC #5, roadmap #6 phase 1). Two read-only commands: `discover` proposes candidate dependencies for a model project from Python lockfiles/dependency files, local model assets and explicit Hugging Face model-card references (base model, datasets, revision, licence), each with origin, verification status (verified / declared-but-unverified / conflicting / unavailable), observation time, identity/hash and gap reasons; `inventory audit MODEL_ID` reports findings, inventory assurance and check coverage/source failures as separate results so "no alerts" never reads as complete or safe. Neither command changes an existing manifest or inventory; a proposed manifest/BOM is written only to an explicitly named output path. Static and offline by default; upstream lookups need an explicit mode. Never executes project code, imports model code, deserialises weights, follows arbitrary model-card URLs or reads outside the project boundary. Includes the SEC-01 trust rule (decision D6): a third-party BOM's code-free claim is checked against the file's bytes or pinned authoritative metadata when available, otherwise marked unverified; an unverified code-free claim never suppresses an alert, never stands in as a code-free sibling for the deployed artifact under strict format policy and never satisfies a future gate. Existing `check` semantics and read-only defaults stay backwards compatible. Decisions are recorded in specs/decisions/2026-11-04-rfc-5-6.md."

**Decisions this spec builds on**: [`specs/decisions/2026-11-04-rfc-5-6.md`](../decisions/2026-11-04-rfc-5-6.md)
(D2 phase 1 shape, D6 trust of imported code-free claims). Tracking: #5, #6.

## Clarifications

### Session 2026-11-04

- Q: What happens to versions imported before this feature whose code-free claims silence strict-policy
  alerts? → A: Their claims are re-marked unverified at the next check, so strict-policy alerts may newly
  appear; each such alert says it follows the new trust rule (FR-005).
- Q: When does a confirmed code-free file suppress the strict-policy alert? → A: As today: any confirmed
  code-free file in the same version. Naming the deployed artifact is left to a later feature (FR-006).

### Session 2026-11-05

- Q: How can an imported code-free claim for a hub-hosted weight file be confirmed, given the tool never
  downloads weight files? → A: At check time, read only a bounded header of the hub file at its pinned
  revision and classify its format from that header (FR-002a).
- Q: When does a check read hub file headers? → A: As its own check source that runs with every check
  like the others and can be left out with `--source`; it reads only imported claims that are still
  unverified, and a file confirmed for a version is not read again (FR-002b).
- Q: How do unconfirmed candidates appear in the proposed manifest? → A: As TOML comments carrying their
  status and origin; only entries registration can measure or pin itself are written as active entries.
  The manifest format is unchanged (FR-022).

### Session 2026-11-05 (after analysis)

- Q: What does the audit do on a database created before this feature? → A: Opens it read-only and never
  upgrades it; missing fields are read as their defaults, so the file stays byte-identical (FR-013).
- Q: Which claims need a recorded origin? → A: All four: format, ability to run code, hash and revision.
  Imported hash and revision claims are unverified until a check confirms them (FR-001).
- Q: Is a hub refusal (401, 403 or 404) of a header read a source failure? → A: No. Refusals and headers
  over the limit leave the claim unverified with a watch event and exit 0; only network errors and server
  errors after retries fail the source (FR-002b).

## User Scenarios & Testing *(mandatory)*

### User Story 1 - An imported code-free claim cannot hide a code-capable weight file (Priority: P1)

A model owner who sets the strict weight-format policy relies on it to raise an alert when a weight file
that can run code is not accompanied by a code-free alternative. Today, an inventory imported from someone
else can declare a file code-free by its name or metadata alone, and that declaration is enough to silence
the alert. The owner needs every code-free claim that came from an imported inventory to be either
confirmed or marked unverified, and needs unverified claims to count for nothing.

**Why this priority**: it closes a known way for a third-party inventory to defeat the strict policy
(SEC-01). It is small, has the highest security impact and must be settled before any release gate is
built (decision D4).

**Independent Test**: import an inventory whose only code-free entry is a pickle mislabelled as a
code-free format, set the strict policy and check; the policy alert is raised and the entry is shown as
unverified. Import a second inventory whose code-free entry is confirmed by its bytes; no policy alert.

**Acceptance Scenarios**:

1. **Given** an imported inventory that declares a weight file code-free, and the file's bytes are
   available to the check, **When** a check runs, **Then** the format is judged from the bytes; if they
   show a code-capable format the entry is code-capable and the claim is recorded as contradicted.
2. **Given** an imported code-free claim that neither the bytes nor pinned authoritative metadata can
   confirm, **When** the inventory is shown, **Then** the entry is marked "code-free claimed, unverified"
   with the claim's origin.
3. **Given** a model under the strict policy whose only code-free entry is unverified, **When** a check
   runs, **Then** the format-policy alert is raised for each code-capable file, as if no code-free file
   were present.
4. **Given** a model registered from its own manifest (not imported), **When** a check runs, **Then**
   alerts and watch events are exactly as before this feature.
5. **Given** a version imported before this feature whose code-free claim silenced the strict-policy
   alert, **When** its next check cannot confirm the claim, **Then** the alert is raised and says that it
   follows the new trust rule.

---

### User Story 2 - Audit what a clean check does and does not establish (Priority: P1)

A model maintainer about to rely on a model asks for an audit of a registered model. They get three
separate answers: what was found (open alerts and watch events), how well the inventory is established
(which entries are pinned and verified, which are gaps, unverified or contradicted and what is known to
be missing) and how well the checks covered it (which sources ran, when, which failed or were never
asked, and which entries no source could check). "No alerts" is never presented as "complete" or "safe".

**Why this priority**: it fixes the most likely misreading of the tool today using data the tool already
holds, without new sources, so it delivers value on its own.

**Independent Test**: register a model with a mix of pinned entries, gaps and an imported unverified
claim; run a check in which one source fails; run the audit; the three sections report each of those
facts separately, and a model with no alerts still shows its gaps and the failed source.

**Acceptance Scenarios**:

1. **Given** a model with no open alerts but two gaps, **When** the audit runs, **Then** findings show
   none, assurance shows the two gaps with their reasons and the summary does not say the model is clean,
   complete or safe.
2. **Given** a model whose last check had a failed source, **When** the audit runs, **Then** coverage
   names the source, the time of the failure and the entries that source would have checked.
3. **Given** a model that has never been checked, **When** the audit runs, **Then** coverage says no
   check has run and findings are reported as "not yet checked", not as none.
4. **Given** an entry no enabled source can check (for example a dataset with neither a DOI nor a hub
   identity), **When** the audit runs, **Then** coverage lists it as uncheckable with the reason.
5. **Given** a model's latest check is older than the freshness threshold, **When** the audit runs,
   **Then** coverage reports how old each source's latest result is.

---

### User Story 3 - Discover candidate dependencies from a project, offline (Priority: P2)

A maintainer points the tool at a model project folder. Without contacting any service, the tool proposes
the dependencies it can see: Python packages from lock and dependency files, local weight files and the
base model, datasets, revision and licence that the project's own model card explicitly names. Each
candidate shows where it was seen, how sure the tool is and what is missing. If the maintainer names an
output path, a proposed manifest is written there for them to review; nothing else is written.

**Why this priority**: it turns "the inventory is whatever someone remembered to declare" into a list the
maintainer can review, but it needs the vocabulary of User Story 2 to be useful, so it follows it.

**Independent Test**: run discovery over a fixture project holding a hash-locked requirements file, an
unpinned requirements file, two weight files (one a mislabelled pickle) and a model card naming a base
model and a dataset; the result lists each candidate with origin, status and gaps; the project and any
existing manifest are byte-for-byte unchanged; no network request is made.

**Acceptance Scenarios**:

1. **Given** a hash-locked requirements file, **When** discovery runs, **Then** each package is a candidate
   with its exact version and hashes, an origin naming the lock file and line, and status
   declared-but-unverified.
2. **Given** a dependency declared without an exact version, **When** discovery runs, **Then** it is a
   candidate with a gap "no exact version", never a guessed version.
3. **Given** a local weight file, **When** discovery runs, **Then** the candidate carries the file's
   SHA-256 and the format read from its bytes, with status verified for those two facts.
4. **Given** a model card that names a base model without a revision, **When** discovery runs, **Then**
   the base model is a candidate with a gap "no revision".
5. **Given** an existing manifest for the project and a model card that names a different base model,
   **When** discovery runs with that manifest, **Then** the base model candidate is marked conflicting and
   both sources are shown.
6. **Given** an output path, **When** discovery runs, **Then** a proposed manifest is written to that path
   only, the path's previous contents are not silently replaced, local weight files and the hash-locked
   requirements file are active entries and every other candidate is a comment showing its status and
   origin; registering the file as written registers only the active entries.

---

### User Story 4 - Confirm hub references during discovery (Priority: P3)

With an explicit option, discovery may look up the base model and datasets named in the model card on the
model hub, to confirm that they exist, to read their declared licence and to propose an exact revision.

**Why this priority**: useful, but it needs network access and adds a way to be misled (the hub's current
revision is not necessarily the one the model was trained on), so it comes after offline discovery.

**Independent Test**: with recorded hub responses, run discovery with the upstream option; existing
references are marked confirmed with the retrieval time, a missing one is marked unavailable, and any
proposed revision is labelled as observed at that time rather than as the training revision.

**Acceptance Scenarios**:

1. **Given** the upstream option is off (the default), **When** discovery runs, **Then** no network request
   is made.
2. **Given** the upstream option is on and the hub knows the base model, **When** discovery runs, **Then**
   the candidate records the hub's answer, its retrieval time and its current revision as a proposal
   labelled "head at observation time, not established as the training revision".
3. **Given** the upstream option is on and the hub refuses or cannot be reached, **When** discovery runs,
   **Then** the candidate is marked unavailable with the reason, and discovery still completes.

---

### Edge Cases

- A symbolic link inside the project points outside it, or a path in a dependency file or model card uses
  `..` or an absolute path: the target is not read and the candidate is recorded as a gap "outside the
  project".
- A model card links to a web page, a paper or a dataset by URL rather than by hub identity or DOI: the URL
  is recorded as text and not followed.
- A model card's front matter is malformed or uses unknown keys: discovery reports the card as unreadable
  or the keys as unrecognised and continues with the other sources.
- A very large project, or a very large or deeply nested file: discovery stops reading at published size
  and depth limits and reports what it skipped, rather than running out of memory or time.
- The same package appears in two dependency files at different versions, or the same weight file appears
  under two names: both are shown and marked conflicting; neither is chosen silently.
- A weight file whose name suggests a code-free format but whose bytes show a pickle: the bytes win and
  the candidate is code-capable, with the contradiction recorded.
- An imported inventory declares a hash for a file whose bytes are available and differ: the entry is
  contradicted and cannot count as verified.
- An imported code-free claim for a hub file at a pinned revision: the check reads the file's header at
  that revision; if the header shows a code-free format the claim counts as verified with the retrieval
  time as evidence, and if it shows a code-capable format the claim is contradicted.
- An imported code-free claim for a hub file with no pinned revision: its header is not read (the bytes
  could change) and the claim stays unverified.
- The hub refuses the header read, times out or returns more than the byte limit allows: the claim stays
  unverified and the reason is shown; the source is not counted as clean.
- The audit is asked for a model or version that does not exist: invalid input, as for other commands.
- Discovery is pointed at a folder that holds no recognisable dependencies: it reports zero candidates and
  says what it looked for; it does not report the project as dependency-free.

## Requirements *(mandatory)*

### Functional Requirements

#### Trust of imported claims (User Story 1)

- **FR-001**: Every inventory entry MUST carry the origin of each security-relevant claim about it
  (format, ability to run code, hash, revision): declared by the owner's manifest, measured from local
  bytes, read from an authoritative source at a pinned revision, or imported from a third-party inventory.
  Hash and revision claims made by an imported inventory MUST be shown as unverified until a check confirms
  them (a weight file's hash from its local bytes or from the hub's file list at the pinned revision); kinds
  no source can confirm stay unverified and say so.
- **FR-002**: A claim imported from a third-party inventory that a weight file cannot run code MUST be
  recorded as unverified until it is confirmed by the file's bytes or by authoritative metadata for the
  exact pinned revision.
- **FR-002a**: For a hub-hosted weight file pinned to an exact revision, a check MUST be able to confirm
  or contradict an imported code-free claim by reading only a bounded header of the file at that revision
  (a published byte limit, never the whole file) and classifying its format from that header with the
  same rules used for local files. The read MUST be anonymous, read-only, rate-limited and recorded as
  evidence with its retrieval time. A header that cannot be read or classified leaves the claim
  unverified, never confirmed.
- **FR-002b**: The header read MUST be a separate check source (name provisional) that runs with every
  check by default, scheduled or on demand, and can be selected or left out with `--source` like the
  existing sources. It MUST touch only weight files whose imported claims are still unverified: their hash
  is confirmed from the hub's file list (or local bytes) and, only for a code-free claim, their header is
  read. Once a claim is confirmed or contradicted for a version, it MUST NOT be checked again for it. A
  refusal (401, 403, 404) or a header over the limit leaves the claim unverified with a watch event and is
  not a failure; a network error or server error after retries fails the source like any other (exit code
  2). A version with no such claims MUST cause no requests.
- **FR-003**: When the file's bytes are available to a check, the format and ability to run code MUST be
  judged from the bytes; an imported claim they contradict MUST be recorded as contradicted, with both the
  claim and the measurement as evidence.
- **FR-004**: Under the strict weight-format policy, only a confirmed code-free entry MAY suppress the
  format-policy alert. An unverified or contradicted code-free claim MUST count as absent.
- **FR-005**: Versions imported before this feature MUST have their imported code-free claims re-marked
  as unverified at their next check, unless that check confirms them as FR-002 allows. A strict-policy
  alert that appears for this reason MUST say that it follows the new trust rule and name the unverified
  claim, so the owner can tell it from a new problem in the model.
- **FR-006**: Under the strict policy, a confirmed code-free entry MUST suppress the alert for any
  code-capable file in the same version, as today. Naming the deployed artifact so that only it is judged
  is out of scope for this feature.
- **FR-007**: For models registered from their own manifest or registration record after this feature is
  installed, alert and watch-event outcomes MUST be unchanged by it. Versions registered before it are
  treated as described under Assumptions.

#### Inventory audit (User Story 2)

- **FR-008**: The tool MUST provide a read-only audit of one registered model version (the latest by
  default) that reports three separate sections: findings, inventory assurance and check coverage.
- **FR-009**: Findings MUST list open alerts and watch events as the tool already records them, or state
  "not yet checked" when no check has run.
- **FR-010**: Inventory assurance MUST classify every entry as verified, declared-but-unverified,
  conflicting or unavailable, and MUST list gaps with their reasons, unverified and contradicted claims
  with their origins, and dependency kinds the inventory does not declare at all (for example no
  environment, no base model, no datasets).
- **FR-011**: Check coverage MUST list, for each source relevant to the version's entries, when it last
  answered successfully, whether it last failed and why, the entries it covers, and which entries no
  source can check.
- **FR-012**: The audit MUST never present the absence of alerts as completeness or safety. Its summary
  MUST state the number of unverified, conflicting and unavailable entries, gaps and failed or stale
  sources alongside the number of findings.
- **FR-013**: The audit MUST NOT contact any source, run a check, change any alert or write anything other
  than its own output. It MUST open the database read-only and never upgrade it; on a database created by
  an earlier version, fields this feature adds are read as their defaults.
- **FR-014**: The audit MUST exit successfully whenever it completes, whatever it reports, consistent with
  `check` (findings and weak assurance are not failures); machine-readable output MUST carry every count
  and classification.

#### Discovery (User Stories 3 and 4)

- **FR-015**: The tool MUST provide a discovery command that reads a project folder and proposes candidate
  dependencies, each with: kind, identity (name and version, file path and SHA-256, hub identity and
  revision, DOI), origin (file and location where it was seen), verification status, observation time and
  gap reasons.
- **FR-016**: Discovery MUST read Python dependency declarations from hash-locked requirements files (the
  format registration already accepts) and report other dependency declarations in the project's
  requirements and project metadata files as candidates with the gap "not locked".
- **FR-017**: Discovery MUST hash local weight files and read their format from their bytes without
  loading or deserialising them, using the same classification registration uses.
- **FR-018**: Discovery MUST read the project's model card front matter for an explicitly named base model,
  datasets, revisions and licence, and MUST NOT infer any of them from free text.
- **FR-019**: Given an existing manifest, discovery MUST compare each candidate with it and mark
  candidates missing from the manifest, entries the manifest declares that discovery did not see and
  conflicts between the two.
- **FR-020**: Discovery MUST NOT execute project code, import model code, deserialise weights, follow URLs
  found in files, read outside the project folder (including through symbolic links) or read beyond
  published size and file-count limits; anything skipped MUST be reported with the reason.
- **FR-021**: Discovery MUST make no network request unless the upstream option is given. With it,
  discovery MAY query the model hub only for hub identities named explicitly in the project, using the
  existing read-only, rate-limited and redacted access; a proposed revision from the hub MUST be labelled
  as observed at retrieval time, not as the training revision.
- **FR-022**: Discovery MUST NOT change any existing file or the tool's database. It MUST write a proposed
  manifest only to an output path the user names and MUST refuse to replace an existing file unless the
  user asks explicitly. The proposed manifest MUST use the existing manifest format unchanged. Only entries
  that registration measures or pins itself (local weight files, a hash-locked requirements file) are
  written as active entries; every other candidate (a base model, dataset or licence read from the model
  card, a conflicting entry, a gap) MUST be written as a comment that shows its status, origin and gaps,
  so that registering the file as written registers none of them.
- **FR-023**: Discovery output MUST state that it proposes dependencies from the evidence available and
  cannot establish complete training provenance.

#### Compatibility and evaluation

- **FR-024**: Existing commands, their exit codes and their JSON output MUST remain backwards compatible;
  any new field is additive. Read-only defaults remain.
- **FR-025**: Tests MUST cover a forged code-free claim (a pickle labelled code-free), an unavailable
  weight file, conflicting identities, an interrupted source read, a path that escapes the project, a
  symbolic link out of the project and an unchanged alert lifecycle for manifest-registered models.
- **FR-026**: Discovery quality MUST be evaluated per candidate kind on a held-out set of projects,
  reporting found, missed and wrongly proposed candidates separately; no pooled accuracy figure.

### Key Entities

- **Claim**: one statement about an inventory entry (format, ability to run code, hash, revision, licence,
  relationship), with its origin, the evidence for it and its verification status.
- **Origin**: where a claim came from: owner's manifest, local bytes, authoritative source at a pinned
  revision, imported inventory, project file seen by discovery, or hub lookup.
- **Verification status**: verified, declared-but-unverified, conflicting (contradicted) or unavailable.
- **Candidate dependency**: a dependency proposed by discovery: kind, identity, origin, status, observation
  time and gaps. It is not an inventory entry until the owner registers it.
- **Audit report**: one model version's findings, inventory assurance and check coverage, with a summary of
  counts and the time it was produced.
- **Coverage record**: for each relevant source, its latest successful answer, latest failure and the
  entries it could and could not check.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: In the hostile test set, no forged, unverified or contradicted code-free claim suppresses a
  strict-policy alert (0 of all cases).
- **SC-002**: For every model registered from its own manifest in the existing test suite, alerts and watch
  events are identical before and after this feature (100%).
- **SC-003**: For every audited model with no open alerts, the audit still shows every gap, unverified
  claim, failed source and uncheckable entry the model has (100% in the test set); none is reported as clean.
- **SC-004**: Every discovered candidate carries an origin, a verification status and an observation time
  (100%).
- **SC-005**: Discovery without the upstream option makes zero network requests, and discovery and the
  audit leave every pre-existing project file and the tool's database byte-for-byte unchanged (verified by
  hashes and modification times).
- **SC-006**: In the hostile path set (symbolic links out, `..` paths, absolute paths, oversized files),
  zero files outside the project are read and every skip is reported.
- **SC-007**: A maintainer reading the audit can say in under two minutes which entries are unverified and
  which sources failed, without opening any other output (checked in a walkthrough of the quickstart).
- **SC-008**: Discovery on the held-out projects is reported per candidate kind with found, missed and
  wrongly proposed counts.

## Assumptions

- Phase 1 covers Python environments, local weight files and Hugging Face references, as RFC #5 proposes.
  Other package ecosystems, registries, deployment integrations and multi-parent lineage (#9) are out of
  scope.
- The model card is the project's `README.md` front matter in the Hugging Face model card format.
- "Authoritative metadata at a pinned revision" means the file's own header bytes read from the hub at that
  exact revision (FR-002a). Other hub metadata (such as its scan result) does not confirm a format unless
  planning shows it establishes one. The header byte limit is set during planning and published.
- The audit reads stored check results and does not refresh them; the freshness threshold for coverage
  defaults to the daily schedule the project recommends (24 hours) and can be changed.
- Command names (`discover`, `inventory audit`) stay provisional until the CLI contract is reviewed
  (decision D2).
- Size and file-count limits for discovery are set during planning and published in the CLI contract.
- Naming the deployed weight file, so that the strict policy judges only it, is a later feature (FR-006).
- The database does not record how versions registered before this feature were made, so all of them are
  treated like imports under FR-005; FR-007 applies to versions registered after it (plan, Complexity
  Tracking).
- No release gate is built here (decision D4); FR-004's rule is written so a later gate can rely on it.

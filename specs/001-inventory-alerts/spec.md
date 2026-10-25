# Feature Specification: Model Inventory with Library and Weight-File Alerts

**Feature Branch**: `001-inventory-alerts`

**Created**: 2026-10-23

**Status**: Draft

**Input**: User description: "Model inventory with library and weight-file alerts. A model owner registers a trained model; the service builds or imports the model's inventory (an AI bill of materials): weight files with hashes and formats, the base model and its exact revision, training datasets by DOI and the locked packages of the runtime environment. The service checks the locked packages against published security advisories and the weight files for unsafe serialisation, raises evidenced alerts, records uncertain signals as watch events, never changes a model and closes alerts when a newer model version removes the cause."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Register a model and see its inventory (Priority: P1)

A model owner registers a trained model by pointing the service at its files and runtime environment: the weight files, the hash-locked list of packages the model runs with, the base model it was fine-tuned from (a model repository and exact revision) and the datasets it was trained on (by DOI). The service records a complete, pinned inventory and shows it to the owner, with anything it could not pin listed as a gap.

**Why this priority**: every alert depends on the inventory; without it there is nothing to match. On its own it already tells an owner exactly what their model depends on.

**Independent Test**: register the worked example (a fine-tuned object detector with a hash-locked package list, a pinned base-model revision, a dataset DOI with a SHA-256 hash, PyTorch checkpoint files and ONNX files) and confirm that every item appears in the inventory with its identifier, and that the inventory can be exported in an open standard format and read back unchanged.

**Acceptance Scenarios**:

1. **Given** a model with weight files, a hash-locked package list, a base-model revision and a dataset DOI, **When** the owner registers it, **Then** the inventory lists each weight file with its hash and format, each package with its exact version, the base model with its revision and each dataset with its DOI.
2. **Given** a package list without exact versions or hashes, **When** the owner registers the model, **Then** the service registers it but lists the unpinned packages as gaps and does not check them for advisories.
3. **Given** a registered model, **When** the owner exports its inventory, **Then** the export is a valid document in the open standard and importing it again yields the same inventory.

---

### User Story 2 - Alerts for vulnerable packages (Priority: P1)

The service checks every pinned package in a model's inventory against published security advisories, on a schedule and when the owner asks. When an advisory affects a package version the model uses, the owner sees an alert with the advisory, its severity, the version that fixes it and the evidence: which source, when it was retrieved and which package and version matched.

**Why this priority**: this is the "Dependabot for models" core and uses the most mature, machine-readable advisory sources.

**Independent Test**: register a model whose package list includes a version with a known, published advisory and confirm one alert appears with the advisory identifier, severity, fixed version and evidence; register a model with only unaffected versions and confirm no alert.

**Acceptance Scenarios**:

1. **Given** a model that uses a package version named in a published advisory, **When** a check runs, **Then** an open alert shows the advisory identifier, severity, the fixed version (or that none exists yet) and the evidence.
2. **Given** an open alert, **When** the advisory is later withdrawn by its publisher, **Then** the alert closes as withdrawn, with the withdrawal recorded as its evidence.
3. **Given** an advisory that names the package but whose affected versions cannot be matched to the model's exact version, **When** a check runs, **Then** the service records a watch event, not an alert.
4. **Given** the same advisory affects the same package in several registered models, **When** a check runs, **Then** each model gets its own alert and no model gets duplicates.

---

### User Story 3 - Alerts for unsafe weight files (Priority: P2)

The service checks each weight file in a model's inventory for unsafe serialisation: formats that can run code when the file is loaded (pickle-based formats such as `.pt`, `.bin` and `.ckpt`). For files hosted on a model hub that publishes its own security scan, the service also reads that scan's verdict.

**Why this priority**: loading a malicious weight file can run code on the user's machine, but the risk depends on the file's source and how it is loaded, so it matters slightly less than known package vulnerabilities.

**Independent Test**: register a model with one pickle-based checkpoint and one file in a format that cannot run code, and confirm the service treats them differently; register a hub-hosted file that the hub's scan flags and confirm an alert with the hub's verdict as evidence.

**Acceptance Scenarios**:

1. **Given** a weight file in a pickle-based format that no scan flags, **When** a check runs, **Then** the service records a watch event with the file's hash, format and the reason (the format can run code when loaded), and suggests a format that cannot.
2. **Given** a pickle-based weight file in which a scan of its contents finds instructions that would run code beyond rebuilding the model (for example calls to the operating system or the network), **When** a check runs, **Then** an alert shows what the scan found, the scanner, the retrieval time and the file's hash.
3. **Given** a hub-hosted weight file whose hub scan reports it unsafe, **When** a check runs, **Then** an alert shows the hub's verdict, the scanners named by the hub, the retrieval time and the file's hash.
4. **Given** a hub-hosted file whose scan result is missing, pending or unreadable, **When** a check runs, **Then** the service records a watch event, not an alert.
5. **Given** a model whose owner has chosen the strict format policy, and a pickle-based weight file with no file in a format that cannot run code beside it in the same model version, **When** a check runs, **Then** an alert names the policy, the file's hash and format, and suggests a format that cannot run code; with such a file beside it, only the watch event of scenario 1 is recorded.
6. **Given** a code-capable file that the scanner cannot read to the end (for example a joblib file with raw array data between its instructions), **When** a check runs, **Then** the service records a watch event saying the scan was incomplete, and never treats the file as clean.

---

### User Story 4 - Alerts close when a new model version fixes the cause (Priority: P2)

When the owner registers a newer version of a model whose inventory no longer contains an alert's cause (the package is upgraded past the fixed version, or the weights are re-exported to a safe format), the alert closes automatically as fixed, naming the version that fixed it. Otherwise a person can dismiss an alert with a reason from the list, and the tool records the name they give.

**Why this priority**: without automatic closure, alerts pile up and owners stop reading them.

**Independent Test**: take a model with an open package alert, register a new version with the package upgraded past the fixed version and confirm the alert closes as fixed by that version; dismiss another alert and confirm the reason and the person are recorded.

**Acceptance Scenarios**:

1. **Given** an open alert on version 1 of a model, **When** the owner registers version 2 whose inventory no longer contains the cause, **Then** the alert closes as fixed and names version 2.
2. **Given** an open alert, **When** a person dismisses it, **Then** the dismissal requires a reason from a fixed list (for example "not used at runtime", "risk accepted", "false positive") plus an optional note, and records who dismissed it and when.
3. **Given** a closed alert, **When** a later check finds the same cause in the current version again, **Then** a new alert opens and the history shows both.

---

### User Story 5 - See a model's alerts, watch events and history (Priority: P3)

For each model, the owner sees open alerts ordered by severity, watch events and the closed history with how each item ended (fixed, dismissed, withdrawn, cleared).

**Why this priority**: it presents what the earlier stories produce; useful, but the stories above deliver value without a polished view.

**Independent Test**: for a model with open, closed and watch items, confirm each appears in the right list with its evidence reachable in one step.

**Acceptance Scenarios**:

1. **Given** a model with alerts and watch events, **When** the owner opens it, **Then** open alerts appear by severity and watch events separately, and each item shows its evidence.
2. **Given** a model with closed alerts, **When** the owner opens its history, **Then** each closed alert shows how it closed, when and on what evidence.

---

### Edge Cases

- An advisory source is unreachable during a check: the check is recorded as incomplete for that source, existing alerts stay as they were and nothing closes because of missing data.
- An advisory changes after an alert was raised (new severity or new fixed version): the alert shows the update and keeps the earlier evidence.
- A weight file's hash no longer matches what is hosted at its recorded location: recorded as a watch event; the service does not decide which copy is correct.
- A package appears under different names (for example different capitalisation or separators): matching uses the source's normalised package name.
- The same file appears in several registered models: each model's inventory references it and each model gets its own alerts.
- An inventory imported from another tool contains entries without exact versions or hashes: they are kept as gaps, not checked.
- A model has no base-model or dataset information: registration succeeds; those entries are listed as gaps (they are not checked in this feature).

## Requirements *(mandatory)*

### Functional Requirements

**Inventory**

- **FR-001**: The service MUST let an owner register a model from its weight files, a hash-locked package list, a base-model identifier with revision and dataset DOIs, and MUST record each as an inventory entry with its exact identifier.
- **FR-002**: The service MUST record each weight file's SHA-256 hash, size and format, and whether the format can run code when loaded.
- **FR-003**: The service MUST mark any entry it cannot pin exactly (no version, no hash, no revision) as a gap, show gaps to the owner and exclude gaps from advisory matching.
- **FR-004**: The service MUST export each inventory as a valid document in an open AI bill-of-materials standard and MUST import such documents, preserving every pinned identifier (round trip without loss).
- **FR-005**: The service MUST keep each registered model version's inventory unchanged once recorded; a change is a new model version.

**Package advisories**

- **FR-006**: The service MUST check every pinned package against published security advisories on a schedule and on the owner's request.
- **FR-007**: The service MUST raise an alert only when an advisory's affected range is confirmed to include the model's exact package version; otherwise it MUST record a watch event.
- **FR-008**: Each package alert MUST include the advisory identifier and aliases, severity, affected range, fixed version (or that none is published), source, retrieval time and the matched package name and version.
- **FR-009**: When an advisory is withdrawn by its publisher, the service MUST close the related alerts as withdrawn and record the withdrawal as evidence.
- **FR-010**: The service MUST NOT hold more than one open alert per model, advisory and package; an open alert is carried forward to each newer version that still has the cause rather than raised again.
- **FR-023**: When the source itself no longer shows an alert's cause, the service MUST close the alert as cleared and record that observation as evidence: an advisory whose affected ranges are narrowed so that the pinned version is no longer affected (the source no longer matches and the local consistency check on the same record agrees), a hub verdict for the matching hash that changes from unsafe to an explicit safe verdict, or the owner changing the model's format policy from strict to default, which closes its `format_policy` alerts with the recorded policy (who set it and when) as evidence. A missing, pending or unrecognised verdict MUST NOT close an alert.

**Weight files**

- **FR-011**: The service MUST identify weight files in formats that can run code when loaded and record each as a watch event with the file's hash, format and reason. It MUST scan the contents of such files and raise an alert only when the scan finds instructions that would run code beyond rebuilding the model; the alert names what was found and the scanner.
- **FR-012**: For hub-hosted files whose hub publishes a security scan, the service MUST read the scan verdict and raise an alert only for a verdict that reports the file unsafe; missing, pending or unreadable verdicts MUST be watch events.
- **FR-013**: Each weight-file alert MUST include the file's hash, its location, the verdict or rule that triggered it, the source and the retrieval time.
- **FR-021**: The service MUST let an owner choose a format policy per model: `default` (the format alone is a watch event, FR-011) or `strict`. Under `strict`, a code-capable weight file with no code-free file beside it in the same model version MUST raise an alert naming the policy. The policy MUST default to `default`.
- **FR-022**: When a scanner stops before the end of a code-capable file, the service MUST record a watch event that the scan was incomplete, with the scanner and the position it reached, and MUST NOT count the file as scanned clean.

**Lifecycle**

- **FR-014**: The service MUST close an alert as fixed, naming the fixing version, when the owner registers a newer version of the model whose inventory no longer contains the alert's cause. This closure happens at registration by comparing the two inventories and consults no source.
- **FR-015**: The service MUST let a person dismiss an alert only with a reason from a fixed list and MUST record who (the name given), when and why; the service does not authenticate people, so access to the database is the access control.
- **FR-016**: The service MUST NOT close any alert because a source was unreachable or returned no data. An answer that cannot be read in the shape the source documents counts as no data (a failed read). An inventory entry that names the same dependency but lacks its pin (a gap) MUST NOT count as removal of the cause.
- **FR-017**: The service MUST NOT change, delete, retrain, re-export or unpublish any model or file, and MUST NOT write to any model's repository.

**Visibility and evidence**

- **FR-018**: The service MUST show, per model, open alerts by severity, watch events and closed history with each item's outcome.
- **FR-019**: Every alert and watch event MUST link to its stored evidence: source, retrieval time and the exact identifier matched.
- **FR-020**: The service MUST NOT send personal data to external sources and MUST respect each source's published rate limits.

### Key Entities

- **Model**: a trained model an owner registers; has one or more versions.
- **Model version**: one registered state of a model with its fixed inventory; newer versions can fix alerts.
- **Inventory entry**: one dependency of a model version (weight file, package, base model or dataset) with its exact identifier, or a gap if it cannot be pinned.
- **Advisory**: a published security record from an advisory source, with identifier, aliases, affected ranges, fixed versions, severity and withdrawal state.
- **Alert**: a confirmed match between an inventory entry and an advisory, an unsafe-file verdict or the owner's strict format policy; open, fixed, dismissed, withdrawn or cleared; carries evidence.
- **Watch event**: an uncertain signal about an inventory entry, shown to the owner but not raised as an alert.
- **Evidence**: the source, retrieval time and exact identifier behind an alert or watch event.
- **Check run**: one pass over a model's inventory against the sources, with which sources succeeded or failed.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: An owner can register the worked example and see its complete inventory, with every pinned item and every gap, in under 5 minutes.
- **SC-002**: On the recorded fixture cases of package versions inside a published advisory's affected range and versions outside it, every affected version raises an alert and no unaffected version does.
- **SC-003**: 100% of alerts show their source, retrieval time and the exact identifier matched; an owner can reach the evidence in one step.
- **SC-004**: When a newer model version removes an alert's cause, the alert shows as fixed as soon as that version is registered, with no manual step and no check needed.
- **SC-005**: An inventory exported and re-imported is identical in every pinned identifier (0 differences).
- **SC-006**: A newly published advisory that affects a registered model appears as an alert within one scheduled check interval.
- **SC-007**: When a source is unavailable, 0 alerts change state because of it.

The criteria above that count alerts over recorded cases are met by the fixture suite: they show deterministic behaviour on recorded and derived source answers, which makes them contract tests, not estimates of accuracy in use. Detection and false-alert rates in the field will be reported from the held-out corpus (`research/heldout/`, being prepared); no such rate is claimed here.

## Assumptions

- One organisation runs the service for its own models; multi-tenant accounts and fine-grained permissions are out of scope. "Authorised person" means anyone the running organisation allows to dismiss alerts.
- Scheduled checks run daily by default; owners can also start a check at any time.
- Package advisories come from open, machine-readable advisory sources in the OSV format; the research (research/landscape.md) confirmed these sources and their withdrawal fields.
- The hub scan verdict used for hub-hosted files is read from an interface the hub does not document; if it changes or disappears, those files fall back to watch events rather than failing the check.
- Python packages are the runtime ecosystem covered in this feature; other ecosystems can follow.
- Out of scope for this feature: alerts on base-model or dataset changes, model-level weakness databases and integration with any specific platform (the first platform connects later through an adapter).

## Clarifications

### Session 2026-10-23

- Q: How should a pickle-based weight file be treated? → A: The format alone is a watch event; an alert only when a scan (the hub's or a scan of the file's contents) flags dangerous content (precision first, constitution principle IV).
- Q: Can an owner whose own publishing rules forbid pickle-only weights get an alert for them? → A: Yes, by opting in to the `strict` format policy per model (FR-021); the default stays precision first. Added 2026-10-23 after a third-party scanner rejected pickle-only files by format alone.
- Q: What if a scanner cannot read a file to the end? → A: A watch event that the scan was incomplete, never "clean" (FR-022). Found 2026-10-23: picklescan 1.0.5 stops at the raw array data inside joblib files.

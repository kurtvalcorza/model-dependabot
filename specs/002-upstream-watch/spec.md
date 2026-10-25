# Feature Specification: Upstream Watch for Base Models and Training Datasets

**Feature Branch**: `002-upstream-watch`

**Created**: 2026-10-23

**Status**: Draft

**Input**: User description: "Upstream watch for base models and training datasets. Using the inventory from feature 001, the service checks on a schedule and on demand whether a model's base model and training datasets have changed or disappeared: alerts for a retracted dataset, a removed dataset, a changed licence and a base model that is disabled or no longer publicly available; watch events for new versions, obsoletion, gating changes and other card changes. Anonymous access only; polling, not webhooks."

## Clarifications

### Session 2026-10-23

- Q: Which severity should each new alert type carry? → A: Retraction and removal High; licence change High; base model disabled Medium (recorded as feature 001's `MODERATE`, research U9); base model no longer publicly available Low.
- Q: Which dataset repositories should be checked for removal records? → A: Zenodo, Figshare and Hugging Face are in scope; the Figshare and Hugging Face removal feeds are researched before planning, and until verified they raise no alerts.
- Q: Which Hugging Face HTTP responses count as "the hub refuses access"? → A: 401, 403 and 404 all count as refusal.
- Q: Which reference list decides whether two licence names mean the same licence? → A: The SPDX licence list.

### Session 2026-10-24

- Q: After the removal-feed research, what can FR-005 promise for each repository? → A: Zenodo: removal alerts with date and reason. Hugging Face: an alert when the hub disables the dataset, with the takedown-notice date when listed; a namespace move is a watch event. Figshare: no removal alerts; an item no longer found is a watch event.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Alert when a training dataset is retracted or removed (Priority: P1)

A model owner whose model was trained on a published dataset is told when that dataset is retracted, or removed from the repository that published it, so they can decide whether the model is still fit to use. The alert names the dataset, the notice that confirmed it (a retraction record or the repository's removal record with its stated reason) and when it was retrieved.

**Why this priority**: a retracted or withdrawn dataset can invalidate the model built on it, and today nothing tells the owner. Published retraction and removal records make this the most confirmable of the upstream signals.

**Independent Test**: register a model whose inventory lists a dataset DOI that appears in recorded retraction data, and one whose dataset appears in recorded removal data; confirm one alert each with the notice as evidence; a dataset with neither gets no alert.

**Acceptance Scenarios**:

1. **Given** a model whose dataset DOI is the subject of a published retraction notice, **When** a check runs, **Then** an alert shows the dataset, the retraction notice's identifier and source and the retrieval time.
2. **Given** a dataset whose paper DOI (declared in the inventory as tied to the dataset) is retracted, **When** a check runs, **Then** an alert shows that the related paper was retracted, naming both identifiers.
3. **Given** a dataset record that the publishing repository lists as removed, **When** a check runs, **Then** an alert shows the removal date and the stated removal reason.
4. **Given** a dataset DOI that the DOI registry no longer lists as findable, **When** a check runs, **Then** an alert shows the registry's state as evidence.
5. **Given** a hub-hosted dataset that the hub marks as disabled, **When** a check runs, **Then** an alert shows the disabled state and, if the dataset is in the hub's takedown-notice log, the notice date labelled as a notice date.

---

### User Story 2 - Alert when a licence changes (Priority: P1)

The owner is told when the declared licence of the base model or of a training dataset differs from the licence recorded in the model's inventory, because a licence change can change what the owner may do with the model.

**Why this priority**: a licence change has legal consequences and no source announces it; only comparing the declared licence over time finds it.

**Independent Test**: register a model with a base model and a dataset pinned with their licences; replay recorded responses in which one declared licence differs; confirm one alert showing the old and new licence.

**Acceptance Scenarios**:

1. **Given** a base model recorded with one licence, **When** a check finds its card now declares a different licence, **Then** an alert shows the recorded licence, the newly declared licence and the evidence.
2. **Given** a dataset recorded with one licence, **When** its DOI record or repository record now declares a different licence, **Then** an alert shows both licences and the evidence.
3. **Given** a licence written differently but meaning the same (for example a different letter case or a known alias of the same licence identifier), **When** a check runs, **Then** no alert is raised.
4. **Given** a source that declares no licence where one was recorded, **When** a check runs, **Then** a watch event is recorded, not an alert.

---

### User Story 3 - Alert when the base model is disabled or no longer publicly available (Priority: P2)

The owner is told when the base model their model was fine-tuned from is disabled by the hub, or can no longer be reached publicly, because the model can then no longer be reproduced from public sources.

**Why this priority**: it affects reproducibility rather than safety, and without an account the service cannot tell a deleted base model from one made private, so the alert must state only what is confirmed.

**Independent Test**: replay recorded hub responses: one marking the base model disabled (alert at once); one where the base model is unreachable on two consecutive scheduled checks at least 24 hours apart (alert on the second); one unreachable once and reachable the next day (no alert).

**Acceptance Scenarios**:

1. **Given** a base model the hub reports as disabled, **When** a check runs, **Then** an alert shows that the base model is disabled, with the hub's response as evidence.
2. **Given** a base model that cannot be reached publicly on two consecutive scheduled checks at least 24 hours apart, **When** the second check runs, **Then** an alert states the base model is "no longer publicly available (deleted or made private)" and shows both checks as evidence.
3. **Given** a base model unreachable on one check and reachable on the next, **When** the second check runs, **Then** no alert is raised and the first observation stays as a watch event.
4. **Given** an open "no longer publicly available" alert, **When** the base model becomes publicly reachable again, **Then** the alert closes, with the check that found it as evidence.

---

### User Story 4 - Watch events for upstream changes that are not problems on their own (Priority: P3)

The owner sees, as watch events rather than alerts, changes upstream that may matter but do not confirm a problem: a new revision of the base model, the base model's author pointing to a newer model, a newer version of a dataset, a dataset marked as replaced by another, a change in the base model's access gating and other changes to the base model's card.

**Why this priority**: useful context for planning the next model version, but none of these makes the current model wrong; the model is pinned to an exact revision and dataset version.

**Independent Test**: replay recorded responses showing each of these changes and confirm one watch event each with evidence, and no alerts.

**Acceptance Scenarios**:

1. **Given** a base model pinned at one revision, **When** the hub shows a newer revision, **Then** a watch event shows the pinned and the newest revision.
2. **Given** a dataset whose record links to a newer version or is marked as replaced, **When** a check runs, **Then** a watch event names the newer or replacing record.
3. **Given** a change in the base model's access gating or a card change other than its licence, **When** a check runs, **Then** a watch event records what changed.

---

### Edge Cases

- A source is unreachable or rate-limited during a check: nothing opens, changes or closes because of it; the check run records the source as failed; an unreachable base model counts toward "no longer publicly available" only when the hub answered with a refusal, not when the request failed or timed out.
- The same dataset appears in several models: each model gets its own alert.
- A dataset is identified only by a hub repository, without a DOI: retraction and removal records cannot apply; licence and availability checks still do.
- A retraction notice is itself later retracted or corrected: the alert shows the update; a withdrawn notice closes the alert with the withdrawal as evidence.
- A licence identifier the service cannot interpret: watch event, not alert.
- A dataset's removal record has no stated reason: the alert still opens and says the reason was not given.
- A model with no base model or no datasets in its inventory: nothing to check for those; no error.

## Requirements *(mandatory)*

### Functional Requirements

**Scope and schedule**

- **FR-001**: The service MUST check the base model and every training dataset in each model version's inventory (from feature 001) on the same schedule and on-demand trigger as feature 001's checks.
- **FR-002**: The service MUST use only publicly accessible information, with no account or token for any source.
- **FR-003**: The service MUST NOT send personal data to any source, and MUST stay within each source's published rate limits.

**Datasets**

- **FR-004**: The service MUST raise an alert when a published retraction notice names a dataset's DOI, or a paper DOI the inventory ties to that dataset, with the notice's identifier, its source and the retrieval time as evidence.
- **FR-005**: The service MUST raise an alert when the repository that published a dataset confirms the dataset was removed, with the evidence that repository gives. The repositories in scope are Zenodo, Figshare and Hugging Face:
  - Zenodo: the records API's removal record for the dataset (HTTP 410 with a tombstone) raises an alert showing the removal date and stated reason (or that no reason was given).
  - Hugging Face: the hub marking the dataset as disabled raises an alert. If the dataset appears in the hub's public takedown-notice log, the alert shows that entry's date, labelled as a notice date and not a removal date; otherwise it says no reason was given. A dataset moved to another namespace MUST be a watch event, not an alert.
  - Figshare: publishes no anonymous removal signal, so it raises no removal alert. A Figshare item that can no longer be found MUST be recorded as a watch event.
  - The service MUST NOT store the party that requested a takedown.
- **FR-006**: The service MUST raise an alert when a dataset DOI registered with DataCite (the registry that records findability states) is no longer findable there, with the registry's response as evidence. Crossref-registered DOIs are covered by FR-004; a Crossref answer that a DOI is not found MUST be a watch event, not an alert.
- **FR-007**: The service MUST record a watch event, not an alert, when a dataset has a newer version or is marked as replaced, naming the newer or replacing record.

**Licences**

- **FR-008**: The service MUST record the declared licence of the base model and of each dataset when a model version is registered, if the source declares one.
- **FR-009**: The service MUST raise an alert when a declared licence differs from the recorded one after both are normalised to an identifier from the SPDX licence list; differences in spelling, letter case or a known alias of the same identifier MUST NOT raise an alert.
- **FR-010**: The service MUST record a watch event when a licence cannot be normalised, or a source no longer declares a licence that was recorded.

**Base model**

- **FR-011**: The service MUST raise an alert at once when the hub reports the base model as disabled.
- **FR-012**: The service MUST raise a "no longer publicly available (deleted or made private)" alert only when the hub refuses access to the base model (HTTP 401, 403 or 404) on an unbroken run of consecutive scheduled checks, with no reachable answer from any check in between, that spans at least 24 hours from its first to its latest refusal; a refusal that does not complete such a run MUST be a watch event; on-demand checks MUST NOT count towards the span; failed or timed-out requests MUST NOT count.
- **FR-013**: The service MUST record watch events for a newer base-model revision (showing the pinned and newest revision), for the author's pointer to a newer model, for gating changes and for card changes other than the licence.

**Lifecycle and evidence**

- **FR-014**: Every alert and watch event in this feature MUST carry evidence as defined in feature 001: source, retrieval time and the exact identifier matched.
- **FR-015**: An alert MUST close as fixed when the owner registers a newer model version whose inventory no longer depends on the affected base model or dataset (feature 001 rules); a person MAY dismiss it with a listed reason.
- **FR-016**: A "no longer publicly available" alert MUST close when the base model becomes publicly reachable again; a licence change alert MUST close when the declared licence returns to the recorded one; a retraction alert MUST close as withdrawn if the retraction notice is withdrawn.
- **FR-017**: The service MUST NOT change any model, dataset or repository.
- **FR-018**: The service MUST NOT change any alert's state because of a source that failed during a check.
- **FR-019**: Every alert in this feature MUST state its severity as follows: retraction and removal alerts High; licence change alerts High; base model disabled alerts Moderate; "no longer publicly available" alerts Low (feature 001's severity values `HIGH`, `MODERATE` and `LOW`; research U9).

### Key Entities

- **Upstream item**: a base model or a training dataset in a model version's inventory, with its pinned identifier (hub repository and revision, DOI or hub dataset repository) and its recorded licence.
- **Upstream observation**: what a check saw for an upstream item: availability, disabled state, latest revision or version, declared licence, gating and replacement or newer-version links; kept over time so changes can be found.
- **Retraction notice**: a published record retracting a dataset or a paper tied to it, with its identifier, source and date.
- **Removal record**: a repository's confirmation that a dataset was removed: a Zenodo tombstone (the records API's 410 answer) with date and stated reason, or a hub's disabled state with a takedown-notice date where one is listed.
- Alerts, watch events, evidence and check runs are as defined in feature 001.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: On a test set of recorded retraction and removal records, 100% of datasets named in them raise an alert and 0 datasets not named do.
- **SC-002**: On a test set of recorded licence pairs, every real change raises an alert and 0 spelling, case or alias differences do.
- **SC-003**: A base model unreachable on only one check never raises an alert; one unreachable on two consecutive scheduled checks at least 24 hours apart always does, and so does one refused on every scheduled check of an unbroken run that spans at least 24 hours, even when no two consecutive checks are a full 24 hours apart.
- **SC-004**: 100% of alerts and watch events in this feature show their source, retrieval time and the exact identifier matched.
- **SC-005**: When any source is unavailable during a check, 0 alerts change state because of it.
- **SC-006**: A retraction or removal published for a registered model's dataset appears as an alert within one scheduled check interval after the source publishes it.

## Assumptions

- Feature 001 is in place: inventories, alerts, watch events, evidence, check runs and the schedule are reused, not redefined.
- Base models and hub-hosted datasets are on one hub (Hugging Face); other hubs are out of scope.
- Dataset retractions come from public scholarly retraction records (Crossref retraction notices and the Retraction Watch data), removals from the Zenodo records API's 410 tombstone and from Hugging Face's disabled state and takedown-notice log (Figshare publishes no anonymous removal signal; see FR-005 and research/landscape.md section 9), and findability from the DOI registry (DataCite); research/landscape.md sections 3 and 4 confirm these sources and their limits.
- The tie between a dataset and its paper DOI is declared in the inventory by the owner; the service does not guess it.
- Changes are found by polling on the schedule; push notifications (webhooks) need a public endpoint and are out of scope.
- Zenodo answers a removed record's request with its removal record at once, so a Zenodo removal appears at the next check. Other sources may publish later than the removal itself, so SC-006 holds from the time the source publishes, not from the time of removal.
- Out of scope: hub accounts or tokens (so a deleted base model cannot be told from a private one), model-level weakness databases and platform integration.

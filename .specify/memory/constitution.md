# model-dependabot Constitution

model-dependabot raises Dependabot-style alerts for AI models. It watches what a model depends on (the
code libraries in its runtime environment, its weight files, the base model it was fine-tuned from, its
training datasets and known weaknesses of its model family) and tells the model's owner when one of
them becomes vulnerable, changes or is withdrawn.

## Core Principles

### I. Evidence on Every Alert

Every alert MUST cite its primary source, the time the source was retrieved and the exact identifier
it matched: a package name and version, a model repository and revision, a DOI or a file hash. An
alert MUST NOT be raised from inference, a similarity guess or a summary written by a model. An owner's
recorded policy applied to a pinned file counts as a primary source: the evidence is the file's SHA-256
and format plus the policy setting, who set it and when. If the evidence cannot be recorded, there is no
alert.

Rationale: an owner acts on an alert only if it can be checked; an unverifiable alert costs more trust
than it saves.

### II. Pinned Inventory, Open Standards

Every tracked model MUST have an inventory (an AI bill of materials) that pins each dependency exactly:
file hashes, model revisions, dataset DOIs and locked package versions. Inventories MUST use an open
standard (CycloneDX ML-BOM or SPDX 3.0) rather than a custom format, and advisories MUST use the OSV
schema where it fits. A custom field is allowed only where the standard has none, and it MUST be
documented.

Rationale: an alert can only match what was pinned, and open formats let other tools read the same
inventory.

### III. Advise, Never Act

The service MUST only alert and suggest. It MUST NOT change, retrain, re-export, retire or unpublish a
model, and it MUST NOT open changes against a model's repository on its own. An alert closes
automatically only when a newer model version's inventory shows the cause is gone, or when the source
itself withdraws or clears the cause, with that observation recorded as evidence; otherwise a person
closes it with a recorded reason.

Rationale: the model's owner is accountable for the model; a monitoring service that acts on its own
can break what it watches.

### IV. Precision First

An alert MUST be raised only on a confirmed match between an inventory entry and a source. Uncertain
signals (for example a base model's README changing, or an advisory that names a model family but no
version) MUST be recorded as watch events, visible to the owner but not raised as alerts. Each alert
MUST state its severity and the evidence for it.

Rationale: alert fatigue makes people ignore every alert, the real ones included.

### V. Test-First with Offline Feed Tests

Tests MUST be written before the code they test and MUST fail first. Each feed adapter MUST be tested
against recorded responses from its source, so the whole suite runs without network access. A test
that needs the live source MUST be marked and kept out of the default run.

Rationale: the feeds change and go down; recorded responses keep the tests repeatable and show exactly
which source format the code was built against.

## Additional Constraints

- **Neutral open source.** The project is written to be published openly. Code, documentation and
  commit messages MUST NOT name institutions. The first user is a model-hosting platform; anything specific
  to a platform lives in a separate adapter or configuration, not in the core.
- **Privacy.** No personal data (such as an email address) is sent to external APIs; requests use a
  generic User-Agent. Inventories contain no personal data beyond what a source already publishes.
- **Polite to sources.** Feeds are queried within their published rate limits, with caching, and
  results are stored with their retrieval time.
- **House style.** Plain English, British spelling, no serial comma.

## Development Workflow

- Features are specified with Spec Kit before they are built: specification, plan, tasks, then code.
- A change is done when its tests pass, the full suite is green without network access and every
  statement in its documentation has been checked against the code or a primary source.
- Outward actions (publishing the repository, a release, a post) wait for the owner's explicit yes.

## Governance

This constitution supersedes conflicting practice in the specifications and the code. Amendments are
proposed with a rationale, approved by the owner and recorded in the commit that makes them. Versions
follow semantic versioning: MAJOR when a principle is removed or redefined, MINOR when a principle or
section is added or materially expanded, PATCH for clarifications. Each feature plan's Constitution
Check verifies compliance; a justified exception is recorded in that plan's Complexity Tracking.

**Version**: 1.0.3 | **Ratified**: 2026-10-23 | **Last Amended**: 2026-10-25

# Implementation Plan: Model Inventory with Library and Weight-File Alerts

**Branch**: `001-inventory-alerts` | **Date**: 2026-10-23 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/001-inventory-alerts/spec.md`

## Summary

A command-line service that registers a trained model as a pinned inventory (CycloneDX 1.7 JSON: weight
files by SHA-256, packages by purl, base model by `pkg:huggingface` purl at a commit, datasets by DOI),
then checks it daily or on request. Packages are matched against OSV.dev advisories, with OSV's match
re-checked locally by PEP 440 range evaluation; weight files are classified by format and pickle files
scanned statically with `picklescan`, plus the Hugging Face scan verdict for hub-hosted files. Alerts
need a confirmed match and carry stored evidence; everything uncertain is a watch event. A newer model
version closes the alerts whose cause it removed; a source that withdraws or clears the cause closes its
alerts with that observation as evidence. Technical decisions: [research.md](research.md).

## Technical Context

**Language/Version**: Python 3.12, type hints throughout

**Primary Dependencies**: `packaging` 26.3 (PEP 440 versions, name normalisation), `jsonschema` 4.26.0
(CycloneDX schema validation), `picklescan` 1.0.5 (static pickle scan), `cvss` 3.6 (CVSS v3 and v4 base scores, research R3;
LGPL-3.0-or-later, used as an ordinary import); standard library for HTTP
(`urllib`), TOML (`tomllib`) and storage (`sqlite3`)

**Storage**: SQLite file plus a content-addressed store of raw source responses (research R6)

**Testing**: pytest with recorded source responses in `tests/fixtures/`; the default run makes no network
calls; live tests are marked `live` and excluded by default

**Target Platform**: Linux, macOS and Windows hosts with Python 3.12; scheduled by the host

**Project Type**: command-line tool (library plus CLI)

**Performance Goals**: a check of one model with 100 locked packages finishes in under 60 seconds on an
ordinary connection; registering the worked example (about 0.6 GB of weights) in under 5 minutes, hashing
included (SC-001)

**Constraints**: no network in tests; generic User-Agent and no personal data to sources; within
published rate limits; never writes to a model or its repository

**Scale/Scope**: one organisation; tens to hundreds of models; daily checks

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

Checked against constitution 1.0.2 (2026-10-24); the first check was made against 1.0.0.

| Principle | How this plan meets it | Before research | After design |
| :-- | :-- | :-- | :-- |
| I. Evidence on Every Alert | Every alert and watch event stores source, URL, retrieval time, matched identifier and the SHA-256 of the stored raw response (data model: Evidence). A `strict` `format_policy` alert (FR-021) passes under 1.0.2: the owner's recorded policy applied to a pinned file is its primary source, and its evidence is the file's SHA-256 and format plus the policy value, who set it and when | Pass | Pass |
| II. Pinned Inventory, Open Standards | CycloneDX 1.7, validated against the official schema; purls for packages and base models; DOIs; custom values only as documented `model-dependabot:` properties ([inventory profile](contracts/inventory-profile.md)) | Pass | Pass |
| III. Advise, Never Act | No command writes to a model or its repository (FR-017, tested by T054a); an alert closes automatically only on the two paths 1.0.2 allows: a newer registered version without the cause closes it as `fixed` (FR-014), and the source itself withdrawing the advisory (`withdrawn`, FR-009) or clearing the cause (`cleared`, FR-023) closes it with that observation as evidence; otherwise a person dismisses it with a listed reason ([CLI contract](contracts/cli.md)) | Pass | Pass |
| IV. Precision First | Package alerts need OSV's match and the local range evaluation to agree; pickle format alone is a watch event unless the owner opts in to the `strict` format policy (FR-021), whose alert is a confirmed match between a pinned file and the owner's recorded policy, a primary source under principle I of 1.0.2; an incomplete scan is never clean (FR-022); hub verdicts other than an explicit "unsafe" are watch events; every alert kind has a stated severity (data model: Alert); failed sources change nothing | Pass | Pass |
| V. Test-First with Offline Feed Tests | Every adapter tested against recorded responses; dangerous-pickle fixtures are scanned, never loaded; tests written to fail first in `tasks.md` | Pass | Pass |
| Neutral open source; privacy; polite to sources | No institution names; no platform referenced in code; generic User-Agent; cached responses and back-off; each source's published rate limit recorded in research R8 and applied by the fetcher | Pass | Pass |

No violations; Complexity Tracking is empty.

## Project Structure

### Documentation (this feature)

```text
specs/001-inventory-alerts/
├── plan.md              # This file
├── research.md          # Phase 0: decisions R1-R10
├── data-model.md        # Phase 1: entities, rules, alert states
├── quickstart.md        # Phase 1: validation guide
├── contracts/
│   ├── cli.md               # commands, exit codes, JSON shapes
│   ├── manifest.md          # TOML registration input
│   └── inventory-profile.md # CycloneDX 1.7 mapping
├── checklists/requirements.md
└── tasks.md             # Phase 2 (/speckit-tasks)
```

### Source Code (repository root)

```text
pyproject.toml                      # package, console script, dependencies, pytest config
src/model_dependabot/
├── cli.py                          # argument parsing, output (text and JSON), exit codes
├── manifest.py                     # TOML manifest reading and validation
├── lockfile.py                     # hash-locked requirements parsing
├── inventory/
│   ├── build.py                    # manifest -> inventory entries (hashing, gaps)
│   ├── cyclonedx.py                # entries <-> CycloneDX 1.7 JSON, schema validation
│   └── schema/                     # vendored bom-1.7, spdx, jsf schemas with SHA-256 list
├── sources/
│   ├── fetcher.py                  # Fetcher interface, urllib implementation, cache, back-off
│   ├── osv.py                      # querybatch and vulns/{id}
│   ├── hf.py                       # tree hashes, revision, securityStatus verdict
│   └── pickle_scan.py              # picklescan adapter
├── matching/
│   ├── versions.py                 # OSV range evaluation with PEP 440
│   └── severity.py                 # severity and its origin
├── lifecycle.py                    # alerts, watch events, auto-close, dismissal
├── store.py                        # SQLite schema and evidence store
└── reports.py                      # per-model views and history
tools/
└── record_fixtures.py              # records live OSV and Hugging Face responses into tests/fixtures (run by hand)
tests/
├── fixtures/                       # recorded OSV and Hugging Face responses, crafted pickles, manifests
├── unit/
├── contract/                       # CLI JSON shapes, CycloneDX round trip, manifest rules
├── integration/                    # register -> check -> alert -> new version -> fixed, offline
└── live/                           # marked `live`: real-source smoke tests, excluded by default
```

**Structure Decision**: a single Python package with a console script, laid out by responsibility so each
source adapter can be tested alone against its recorded responses.

## Complexity Tracking

> **Fill ONLY if Constitution Check has violations that must be justified**

None.

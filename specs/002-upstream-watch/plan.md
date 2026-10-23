# Implementation Plan: Upstream Watch for Base Models and Training Datasets

**Branch**: `002-upstream-watch` | **Date**: 2026-10-24 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/002-upstream-watch/spec.md`

## Summary

Extends feature 001's command-line service so each check also watches a model's base model and training
datasets. Each dataset DOI is routed by its registration agency: Crossref DOIs and tied paper DOIs are read
for retraction notices (which already include Retraction Watch); DataCite DOIs for findability, licence and
version links, then the repository: Zenodo's records API (410 tombstone for removals) or Figshare (watch
events only). Hub datasets and the base model are read from the Hugging Face Hub API (disabled, gating,
revision, card and licence), with the public takedown log adding a notice date. Licences are normalised
against the vendored SPDX licence list. Alerts need a confirmed source answer and carry evidence, redacted
where a response holds personal data; everything else is a watch event. Decisions: [research.md](research.md).

## Technical Context

**Language/Version**: Python 3.12, type hints throughout (001)

**Primary Dependencies**: no new runtime dependency. 001's `packaging`, `jsonschema` and `picklescan`; the
standard library for HTTP (`urllib`), CSV (`csv`) and JSON. Vendored data: the SPDX licence list 3.29.0
(`licenses.json`, with its SHA-256)

**Storage**: 001's SQLite database and content-addressed evidence store, with new tables for upstream
observations, DOI routing and the takedown log (no `requesting_entity`)

**Testing**: pytest with recorded responses for every new source in `tests/fixtures/`; default run offline;
live smoke tests marked `live`

**Target Platform**: as 001

**Project Type**: command-line tool (library plus CLI), extending 001's package

**Performance Goals**: a check of one model with a base model and ten datasets finishes within 001's
60-second budget while keeping each source's rate limit (research U13)

**Constraints**: anonymous requests only, generic User-Agent, no personal data sent or stored, within published
rate limits (Crossref one request a second, Figshare one a second, Zenodo 60 a minute, Hugging Face 500 API
requests per five minutes); never writes to a model, dataset or repository

**Scale/Scope**: as 001: one organisation, tens to hundreds of models, daily scheduled checks

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | How this plan meets it | Before research | After design |
| :-- | :-- | :-- | :-- |
| I. Evidence on Every Alert | Every alert and watch event stores source, URL, retrieval time, matched identifier and the original response's SHA-256; redacted bodies record both hashes and the fields removed (research U10) | Pass | Pass |
| II. Pinned Inventory, Open Standards | Licences, paper ties and hub datasets use standard CycloneDX 1.7 fields (`licenses`, `externalReferences` of type `citation` and `distribution`); no new custom property; licences normalised to SPDX identifiers (U8, U11) | Pass | Pass |
| III. Advise, Never Act | Nothing writes to a model, dataset or repository. Alerts close automatically only through a newer model version or when the source withdraws or clears the cause, with that observation as evidence (constitution 1.0.1; research U12) | Pass | Pass |
| IV. Precision First | Alerts only on a confirmed source answer: a retraction update, a 410 tombstone, a hub `disabled` flag, a DataCite 404, a recognised licence change or two scheduled refusals 24 hours apart. Takedown-log entries, Figshare 404s, redirects, unrecognised licences, new revisions and card changes are watch events; failed requests change nothing | Pass | Pass |
| V. Test-First with Offline Feed Tests | Every new adapter tested against recorded responses before it is written; the two-refusal rule and licence pairs tested with replayed sequences | Pass | Pass |
| Neutral open source; privacy; polite to sources | No institution names; no email to any source (so Crossref's public pool); personal fields removed before storage (U10); per-source request pacing and ETag caching (U13) | Pass | Pass |

## Project Structure

### Documentation (this feature)

```text
specs/002-upstream-watch/
├── plan.md              # This file
├── research.md          # Phase 0: decisions U1-U13
├── data-model.md        # Phase 1: additions to 001's entities, kinds and states
├── quickstart.md        # Phase 1: validation guide
├── contracts/
│   ├── cli.md               # additions: --scheduled, new sources, JSON shapes
│   ├── manifest.md          # additions: paper_doi, hub datasets
│   └── inventory-profile.md # additions: licences, citations, hub datasets
├── checklists/requirements.md
└── tasks.md             # Phase 2 (/speckit-tasks)
```

### Source Code (repository root)

New and changed files in 001's layout:

```text
src/model_dependabot/
├── cli.py                          # changed: check --scheduled, new source names
├── manifest.py                     # changed: paper_doi, hub datasets
├── inventory/
│   ├── build.py                    # changed: licences recorded at registration
│   └── cyclonedx.py                # changed: licenses, citation and distribution references
├── sources/
│   ├── fetcher.py                  # changed: redirected_from; redaction hook before storage
│   ├── hf.py                       # changed: model and dataset info (disabled, gated, sha, cardData)
│   ├── hf_takedowns.py             # new: takedown log, requesting_entity dropped on read
│   ├── doi_ra.py                   # new: registration agency lookup
│   ├── crossref.py                 # new: works/{doi} updated-by
│   ├── datacite.py                 # new: dois/{doi} state, rightsList, relatedIdentifiers
│   ├── zenodo.py                   # new: records/{id}, 410 tombstone
│   └── figshare.py                 # new: articles/{id}, licence, 404
├── upstream/
│   ├── observe.py                  # new: one observation per item per source per run
│   ├── changes.py                  # new: compare with the previous observation; two-refusal rule
│   └── licences.py                 # new: SPDX normalisation and expressions
├── licences/
│   ├── spdx-licenses-3.29.0.json   # vendored SPDX licence list, with its SHA-256 listed
│   └── aliases.toml                # repository-specific spellings, each with its source
├── redact.py                       # new: per-source field removal (research U10)
├── lifecycle.py                    # changed: new kinds, severities, cleared state
└── store.py                        # changed: observation, routing and takedown tables; trigger
tools/
└── record_fixtures.py              # changed: records the new sources (redacted) into tests/fixtures
tests/
├── fixtures/                       # recorded responses for every new source
├── unit/                           # licences, redaction, two-refusal rule, change detection
├── contract/                       # CLI JSON for new kinds; manifest and CycloneDX additions
├── integration/                    # register -> check -> alert -> close, offline, per user story
└── live/                           # marked `live`
```

**Structure Decision**: the same single package as 001. Each new source is a separate adapter under
`sources/` so it can be tested alone against recorded responses; change detection lives in `upstream/`,
apart from the adapters, so the two-refusal rule and licence comparison are tested without any source.

## Complexity Tracking

None. Closing an alert when the source withdraws or clears its cause was an exception to Principle III
1.0.0; the owner settled it with the 1.0.1 amendment on 2026-10-24, which also covers feature 001's
withdrawn advisories.

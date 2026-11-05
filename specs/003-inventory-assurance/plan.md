# Implementation Plan: Evidence-Backed Dependency Discovery and Inventory Assurance

**Branch**: `ccr-0b4da713-ncfv4q` (spec directory `003-inventory-assurance`) | **Date**: 2026-11-05 |
**Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/003-inventory-assurance/spec.md`

## Summary

Three increments on the existing command-line tool, in priority order.

1. **Trust of imported claims (SEC-01, P1)**: record where each weight file's format claim came from;
   a new check source `format-check` confirms imported (and legacy) code-free claims from the bytes of a
   local file or a bounded ranged read of the hub file at its pinned commit; the strict policy counts a
   code-free file only when its claim is owner-trusted or confirmed. Old imports are re-marked at their
   next check.
2. **`inventory audit` (P1)**: a read-only report of findings, inventory assurance and check coverage from
   the stored data, which never presents "no alerts" as complete or safe.
3. **`discover` (P2, P3)**: a read-only walk of a project folder that proposes candidates from hash-locked
   and unlocked Python dependency files, local weight files and the model card's front matter, bounded and
   contained, with an optional hub lookup and an optional proposed manifest whose unconfirmed entries are
   comments.

Decisions: [research.md](research.md). Owner decisions: [D1 to D8](../decisions/2026-11-04-rfc-5-6.md).

## Technical Context

**Language/Version**: Python 3.12, type hints throughout (as 001 and 002)

**Primary Dependencies**: existing `packaging`, `jsonschema`, `picklescan` and `cvss`; **one new runtime
dependency, PyYAML** (pinned exactly, safe loader with anchors and aliases refused) for model card front
matter (research A6). Standard library for HTTP, TOML reading, file walking and hashing

**Storage**: the existing SQLite database and evidence store. New column `model_versions.origin`, new
column `inventory_entries.format_origin`, new table `claim_checks`, two new watch-event kinds; all added
on open ([data-model.md](data-model.md))

**Testing**: pytest, offline by default; recorded hub answers for ranged reads; fixture projects on disk
(including a symbolic link out and a `..` include); a test that fails on any network use during
discovery; live tests marked `live`

**Target Platform**: as 001 (Linux and macOS CI; Windows where symbolic links are available to the test
user, otherwise the link tests are skipped with a reason)

**Project Type**: command-line tool (library plus CLI) in the existing single package

**Performance Goals**: `inventory audit` answers in under a second for a model with hundreds of entries
and a year of daily runs; `format-check` adds at most two ranged requests and one tree request per
unconfirmed hub file, once per version; `discover` is bound by hashing the project's weight files

**Constraints**: read-only everywhere except `discover -o`; no network in discovery without `--upstream`;
nothing read outside the project or a version's `base_dir`; limits in [contracts/cli.md](contracts/cli.md);
anonymous, rate-limited hub access through the hardened fetcher (SEC-02 to SEC-04)

**Scale/Scope**: as 001: tens to hundreds of models; projects up to 50,000 directory entries and 2,000
weight files

No open NEEDS CLARIFICATION: the spec's two placeholders were answered by the owner, and the planning-time
items (header source, limits, card parser, legacy rows) are settled in research A2 to A10.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | How this plan meets it | Before research | After design |
| :-- | :-- | :-- | :-- |
| I. Evidence on Every Alert | Every claim check stores an evidence row (URL or path, retrieval time, matched identifier, the JSON summary of what was read, the lead's SHA-256). A `format_policy` alert raised because a claim is unconfirmed names the claim and the rule. The audit and discovery raise nothing | Pass | Pass |
| II. Pinned Inventory, Open Standards | Inventories stay CycloneDX 1.7. One custom property, `model-dependabot:format-origin`, documented in [contracts/inventory-profile.md](contracts/inventory-profile.md) because the standard has no field for it; an imported copy of it is ignored | Pass | Pass |
| III. Advise, Never Act | Nothing changes a model, manifest or repository; `discover` writes only the file named by `-o`, refusing to replace one without `--force`; the audit writes nothing. A `format_policy` alert clears only when a confirmation is observed, with it as evidence | Pass | Pass |
| IV. Precision First | No new alert kind. A contradiction or an unreadable header is a watch event; an unconfirmed claim only stops counting as a code-free file under the owner's own strict policy, which is an existing confirmed-policy alert | Pass | Pass |
| V. Test-First with Offline Feed Tests | Ranged hub answers are recorded before the adapter is written (research A4 names the live test that captures them); fixture projects cover every hostile path case; the default run is offline | Pass | Pass (recording needs a network that reaches the hub; this session's does not) |
| Neutral open source; privacy; polite to sources | No institution names; header reads are anonymous `GET`s within the hub's published limit and store no weight bytes; discovery stores nothing and sends nothing unless `--upstream` | Pass | Pass |
| Development workflow | Specified, clarified and planned before code; tasks next | Pass | Pass |

## Project Structure

### Documentation (this feature)

```text
specs/003-inventory-assurance/
├── spec.md              # specification with clarifications
├── plan.md              # this file
├── research.md          # Phase 0: decisions A1-A13
├── data-model.md        # Phase 1: additions to 001/002 entities; audit and discovery shapes
├── quickstart.md        # Phase 1: validation guide
├── contracts/
│   ├── cli.md               # inventory audit, discover, format-check, limits, JSON, proposed manifest
│   └── inventory-profile.md # format-origin property; import never trusts it
├── checklists/requirements.md
└── tasks.md             # Phase 2 (/speckit-tasks)
```

### Source Code (repository root)

```text
src/model_dependabot/
├── cli.py                     # changed: inventory audit, discover, format-check in CHECK_SOURCES
├── store.py                   # changed: origin, format_origin, claim_checks; back-fill on open
├── lifecycle.py               # changed: format-check source; _code_free uses trust; FR-005 alert detail;
│                              #          clear format_policy on confirmation
├── inventory/
│   ├── build.py               # changed: format_origin on entries; classify_lead(name, lead, size)
│   └── cyclonedx.py           # changed: origin import; local bytes at import; format-origin export
├── sources/
│   ├── fetcher.py             # changed: get_range(url, length) on UrlFetcher and RecordedFetcher
│   └── hf.py                  # changed: read_header(repo, commit, file) using get_range
├── assurance/
│   ├── __init__.py
│   ├── trust.py               # new: which claims need confirmation; entry status for the audit
│   ├── format_check.py        # new: read local bytes or hub header, classify, record claim checks
│   └── audit.py               # new: findings, assurance, coverage from the store (read-only)
├── discover/
│   ├── __init__.py
│   ├── walk.py                # new: bounded, contained walk; skipped list
│   ├── python_deps.py         # new: requirements, constraints, lock files, pyproject
│   ├── weights.py             # new: hash and classify local weight files
│   ├── model_card.py          # new: front matter via PyYAML safe loader without aliases
│   ├── compare.py             # new: candidates against an existing manifest
│   ├── upstream.py            # new: --upstream hub lookups
│   └── propose.py             # new: proposed manifest writer, checked by load_manifest
└── reports.py                 # changed: text output for audit and discovery
tools/
└── record_fixtures.py         # changed: records ranged hub answers
tests/
├── fixtures/format_check/     # recorded tree and ranged answers
├── fixtures/boms/             # forged and honest code-free BOMs
├── fixtures/projects/         # discovery projects, including hostile paths
├── unit/                      # classify_lead, trust rules, walk limits, card parser, propose
├── contract/                  # audit and discover JSON; exit codes; check source list
├── integration/               # claim trust, legacy import, audit, discover (offline), upstream
└── live/                      # ranged read on a public file (marked live)
```

**Structure Decision**: the existing single package. The trust rules and the audit live in a new
`assurance/` package, apart from `lifecycle.py`, so the rules can be tested without a check run;
`lifecycle.py` calls them. Discovery is its own `discover/` package that never imports the store, which
makes "discovery opens no database" structural rather than a convention.

## Delivery order

1. Trust of imported claims: schema additions, `format_origin` at registration and import, `classify_lead`,
   `get_range` and `read_header`, `format-check`, `_code_free` and the FR-005 alert detail. One pull
   request; closes the SEC-01 part of #5.
2. `inventory audit`. One pull request.
3. `discover` offline, then `--upstream` and `-o`. One or two pull requests.

Each increment is shippable alone and keeps the full suite green.

## Complexity Tracking

| Exception | Why needed | Simpler alternative rejected because |
| :-- | :-- | :-- |
| Versions registered before this feature (no recorded origin) are treated like imports, so a legacy *manifest* version whose code-free file can no longer be confirmed (local file gone, hub unreachable) or turns out not to be code-free can gain a `format_policy` alert. This is a narrow departure from FR-007 for legacy rows only | The database cannot tell a legacy import from a legacy manifest registration (research A2); the owner chose to re-mark old imports (FR-005) | Trusting all legacy rows keeps the SEC-01 hole open for every existing import; guessing origin from entry shapes is unreliable. Registering the model again restores manifest treatment |
| A new runtime dependency (PyYAML) | Model cards are YAML; FR-018 needs their keys read reliably | A hand-written subset parser would misread real cards; the dependency is pinned and used only with a safe loader that refuses aliases |

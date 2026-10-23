# Research: Model Inventory with Library and Weight-File Alerts

Phase 0 for [plan.md](plan.md). Sources: the project's landscape research (`research/landscape.md`, 2026-10-23)
and checks made on 2026-10-23 against PyPI and the projects' own repositories. Each decision records what
was chosen, why and what else was considered.

## R1. Inventory format: CycloneDX 1.7 JSON, written directly and validated against the official schema

**Decision**: Inventories are CycloneDX 1.7 JSON documents. The service builds them as plain data and
validates every export against the official `bom-1.7.schema.json` (with its referenced
`spdx.schema.json` and `jsf-0.82.schema.json`), vendored in the repository with their SHA-256 hashes.

**Rationale**: CycloneDX has a `machine-learning-model` component type, a `modelCard` with
`modelParameters.datasets`, and `pedigree.ancestors` for the base model (landscape §7), which covers
every inventory entry in the spec. `cyclonedx-python-lib` 11.12.0 (2026-08-13, Apache-2.0) supports
schema 1.7 and the ML component type, but its `model_card` property is commented out in
`cyclonedx/model/component.py`, so it cannot write the parts that matter most here. Writing the JSON
directly and validating it against the official schema keeps the output exact (constitution II).

**Alternatives considered**: `cyclonedx-python-lib` (no model card, as above); SPDX 3.0.1 with the AI and
Dataset profiles (`trainedOn`, `ancestorOf` relationships fit well, but the JSON-LD serialisation is
heavier and tooling is thinner); a custom format (rejected by constitution II).

## R2. Package advisories: OSV.dev, matched by the source and re-checked locally

**Decision**: Query OSV.dev with `POST /v1/querybatch` (ecosystem `PyPI`, package name and exact
version) to find candidate advisories, then fetch each with `GET /v1/vulns/{id}`. Recompute the match
locally from the advisory's `affected[].ranges` (`introduced`, `fixed`, `last_affected` events) and
`affected[].versions`, comparing with PEP 440 rules (`packaging` 26.3). Raise an alert only when OSV's
match and the local recomputation agree; record a watch event when they disagree.

**Rationale**: OSV is the open format the constitution names, carries `withdrawn`, `fixed` and
`last_affected` (schema v1.9.2), aggregates the GitHub and PyPI advisory databases and states no rate
limits (landscape §1). Two independent matches give precision (constitution IV) and evidence that can be
shown (constitution I).

**Alternatives considered**: the GitHub advisory API alone (rate-limited, needs a token for volume);
PyPI's per-release `vulnerabilities` array (a useful cross-check, but one request per package
version); OSV bulk downloads (better at fleet scale; kept for a later feature via `modified_id.csv`).

## R3. Severity

**Decision**: Use the advisory's `database_specific.severity` when present (`LOW`, `MODERATE`, `HIGH`,
`CRITICAL`); otherwise derive the band from a CVSS v3 or v4 score in `severity[]`; otherwise `UNKNOWN`.
The value and its origin are both stored.

**Rationale**: GitHub-reviewed advisories carry a qualitative severity; others carry only a CVSS vector.
Storing the origin keeps the evidence honest.

## R4. Unsafe weight files: format rule plus a static pickle scan

**Decision**: Classify each weight file by format: pickle-based (`.pt`, `.pth`, `.bin`, `.ckpt`,
`.pkl`, and PyTorch zip archives) or code-free (`.safetensors`, `.onnx`, `.gguf`). Pickle-based files
always get a watch event. They are then scanned with `picklescan` 1.0.5 (MIT, active, last push
2026-10-20) through `picklescan.scanner.scan_bytes`, which disassembles the pickle stream without
executing it and labels each imported callable `innocuous`, `suspicious` or `dangerous`. Any `dangerous`
global raises an alert; `suspicious` globals add a watch event.

**Rationale**: this is the owner's clarification (format alone is a watch event; an alert only when a
scan flags dangerous content) and constitution IV. `picklescan` is the lightest maintained scanner and
never loads the file.

**Alternatives considered**: ModelScan 0.8.8 (broader, heavier, more dependencies); fickling 0.1.12
(deeper analysis, still 0.1); both can be added as further scanners later.

## R5. Hub scan verdict: Hugging Face, undocumented interface, fails safe

**Decision**: For files hosted on Hugging Face, read the scan verdict from
`GET /api/models/{repo}?securityStatus=true` (the `securityRepoStatus` object), confirmed live in the
landscape research but not documented. Only an explicit "unsafe" verdict for a file whose hash matches
the inventory raises an alert. Missing, pending or unrecognised responses become watch events.
Per-file hashes come from the tree API's `lfs.oid` and the revision from `X-Repo-Commit`.

**Rationale**: the hub scans with several engines (landscape §2); using it adds coverage at no cost. Because
the interface is undocumented, failing safe to watch events keeps a format change from producing false
alerts (spec assumption).

## R6. Storage: SQLite

**Decision**: One SQLite database file (Python's built-in `sqlite3`), path set by `--db` (default
`./model-dependabot.db`). Raw source responses are stored as files beside it, named by their SHA-256,
and referenced from evidence records.

**Rationale**: one organisation, tens to hundreds of models (spec assumption); no server needed; the
evidence store is content-addressed so it can be audited.

**Alternatives considered**: PostgreSQL (needed only for multi-user service, a later concern); plain
JSON files (no querying, harder to keep consistent).

## R7. Interface and scheduling: a command-line tool, scheduled by the host

**Decision**: Feature 001 ships a command-line tool (`model-dependabot`) with subcommands for register,
inventory, check, alerts and history, each with human-readable and JSON output. Scheduled checks are
`model-dependabot check --all` run daily by the host's scheduler (cron, systemd timer or Windows Task
Scheduler); the quickstart shows each.

**Rationale**: smallest thing that meets every requirement; the JSON output is the contract a later web
view or the first platform adapter consumes.

**Alternatives considered**: a web service with its own scheduler (more moving parts before the core is
proven).

## R8. HTTP access

**Decision**: Python's standard `urllib.request` behind a small `Fetcher` interface: a generic
User-Agent, no personal data, timeouts, retries with back-off and a response cache keyed by URL and
body. Tests replace the fetcher with one that serves recorded responses.

**Rationale**: constitution V (offline tests) and the privacy constraint. `httpx` 0.28.1 was considered;
its last release is from 2024-12-06, and the standard library is enough.

## R9. Registration input: a TOML model manifest

**Decision**: Owners describe a model in a small TOML file (read with the built-in `tomllib`): weight
files (local paths or `hf:` repository files at a revision), the lock file path, the base model
(`hf:owner/name@revision`) and datasets (DOI, optional SHA-256). The service computes hashes itself and
records anything missing as a gap. An existing CycloneDX inventory can be imported instead.

**Rationale**: no new dependency; easy to write by hand or generate from a training pipeline.

## R10. Lock-file parsing

**Decision**: Read pip and uv hash-locked requirements files (`name==version` lines with `--hash=sha256:`
options and backslash continuations). An entry is pinned only with an exact `==` version and at least one
hash; anything else is a gap (FR-003). Names are normalised with `packaging.utils.canonicalize_name`.

**Rationale**: the worked example's lock is uv-generated in this format; normalisation handles the
spec's naming edge case.

## Deferred (not in feature 001)

- OSV bulk feed (`modified_id.csv`) for fleet-scale incremental checks.
- More scanners (ModelScan, fickling) and other hubs.
- Base-model and dataset change alerts; model-level weaknesses; a web view; the first platform adapter.

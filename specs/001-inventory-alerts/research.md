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

## R2. Package advisories: OSV.dev, matched by the source and checked locally for consistency

**Decision**: Query OSV.dev with `POST /v1/querybatch` (ecosystem `PyPI`, package name and exact
version) to find candidate advisories, then fetch each with `GET /v1/vulns/{id}`. More than 1,000
distinct packages in a run are sent as several batches of at most 1,000 queries; a result that carries
`next_page_token` is followed by sending only those queries again with `page_token`, for at most ten
further rounds, after which the source counts as failed. Then evaluate the same record locally from
its `affected[].ranges` and `affected[].versions`, comparing with PEP 440 rules (`packaging` 26.3) and
the schema's event rules: `introduced` opens a range (`"0"` means before every version), `fixed` closes
it (exclusive), `last_affected` closes it (inclusive) and `limit` is an exclusive upper bound on the
whole range (`"*"` means no bound; none given means `"*"`). Raise an alert only when OSV's match and the
local evaluation agree; record an `advisory_unmatched` watch event when they disagree. A range the local
evaluation cannot read (an event value that is not a PEP 440 version, an unknown event or no
`introduced` event) is not "not affected": the watch event records why it could not be read, and an open
alert is not cleared on it.

**Rationale**: OSV is the open format the constitution names, carries `withdrawn`, `fixed` and
`last_affected` (schema v1.9.2), aggregates the GitHub and PyPI advisory databases and states no rate
limits (landscape §1). The local evaluation is a consistency check on the same OSV record, not a second
source: it catches a disagreement between OSV's matcher and the record it serves (or a defect in either
implementation), but it cannot confirm that the advisory is correct or that the feed is complete. It
adds precision (constitution IV) and evidence that can be shown (constitution I); where its reading of
the schema is incomplete it can only lower recall, by turning a match into a watch event.

**Alternatives considered**: the GitHub advisory API alone (rate-limited, needs a token for volume);
PyPI's per-release `vulnerabilities` array (a useful cross-check, but one request per package
version); OSV bulk downloads (better at fleet scale; kept for a later feature via `modified_id.csv`).

## R3. Severity

**Decision**: Use the advisory's `database_specific.severity` when present (`LOW`, `MODERATE`, `HIGH`,
`CRITICAL`); otherwise derive the band from a CVSS v3 or v4 score in `severity[]`; otherwise `UNKNOWN`.
The value and its origin are both stored.

**Rationale**: GitHub-reviewed advisories carry a qualitative severity; others carry only a CVSS vector.
Storing the origin keeps the evidence honest.

**Scoring** (owner decision, 2026-10-24): vectors are scored with the `cvss` package 3.6 (Red Hat
Product Security, released 2025-08-04, no dependencies), which implements the v3 formula and FIRST's
v4 macro-vector table. It replaced a hand-written v3 formula and the earlier gap where a v4 vector
alone gave `UNKNOWN`. Checked: the v3 cases in `tests/unit/test_severity.py` give the same scores, and
the canonical v4 vector `AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` scores 9.3.

## R4. Unsafe weight files: format rule plus a static pickle scan

**Decision**: Classify each weight file by format: pickle-based (`.pt`, `.pth`, `.bin`, `.ckpt`,
`.pkl`, `.joblib` and PyTorch zip archives) or code-free (`.safetensors`, `.onnx`, `.gguf`). Pickle-based
files always get a watch event. They are then scanned with `picklescan` 1.0.5 (MIT, active, last push
2026-10-20) through `picklescan.scanner.scan_bytes`, which disassembles the pickle stream without
executing it and labels each imported callable `innocuous`, `suspicious` or `dangerous`. Any `dangerous`
global raises a `weight_file_scan` alert with severity `HIGH` (origin `policy`); `suspicious` globals add
a watch event.

Two later clarifications refine this. Under the owner's `strict` format policy (FR-021), a pickle-based
file with no code-free file beside it in the same model version raises a `format_policy` alert with
severity `MODERATE` (origin `policy`); its evidence is the file's SHA-256 and format plus the policy
value, who set it and when (constitution I, 1.0.2). When the scanner stops before the end of a file
(FR-022; `picklescan` 1.0.5 stops at the raw array data between the pickle instructions of a joblib
file), the result is a `scan_incomplete` watch event with the scanner and the byte position reached,
never `innocuous`.

**Rationale**: this is the owner's clarification (format alone is a watch event; an alert only when a
scan flags dangerous content, or when the owner opts in to `strict`) and constitution IV. `picklescan` is the lightest maintained scanner and
never loads the file.

**Alternatives considered**: ModelScan 0.8.8 (broader, heavier, more dependencies); fickling 0.1.12
(deeper analysis, still 0.1); both can be added as further scanners later.

## R5. Hub scan verdict: Hugging Face, undocumented interface, fails safe

**Decision**: For files hosted on Hugging Face, read the scan verdict from
`GET /api/models/{repo}?securityStatus=true` (the `securityRepoStatus` object), confirmed live in the
landscape research but not documented. Only an explicit "unsafe" verdict for a file whose hash matches
the inventory raises a `hub_scan` alert with severity `HIGH` (origin `policy`). Missing, pending or
unrecognised responses become watch events. If a later verdict for the same hash is an explicit safe
verdict, the alert closes as `cleared` with the new verdict as evidence (FR-023); a missing, pending or
unrecognised later verdict changes nothing. Per-file hashes come from the tree API's `lfs.oid` and the
revision from the model-info `sha` at that revision (`X-Repo-Commit` wins when a response carries
one; neither the tree nor the model-info API sent it on 2026-10-24, see `tests/fixtures/hf/NOTES.md`).
The security status describes the repository's head commit only. When it gives no issue for a file
pinned at another revision, one request for the tree at the head commit compares the head file's
SHA-256 with the pinned hash: if they match, the clean result stands; if they differ the result is a
`hash_mismatch` watch event, and if the file is not at the head commit (or its hash or the tree cannot be
read) a `hub_scan_unknown` watch event with the reason. A file pinned at the head commit needs no extra
request.

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
body. Tests replace the fetcher with one that serves recorded responses. The fetcher only reads: it
sends `GET`, plus `POST` to OSV's read-only `/v1/querybatch`, and never `PUT`, `PATCH` or `DELETE`
(FR-017).

Published rate limits (FR-020): OSV.dev states no rate limit (R2), so the fetcher relies on the cache
and back-off. The Hugging Face Hub publishes per-window limits for its API and answers `429` when they
are exceeded; the fetcher applies a per-source ceiling on requests per window, honours `Retry-After`
and stops querying that source for the rest of the run after repeated `429`s (the source is then
`failed` for the run, FR-016). The hub documents anonymous limits per IP in five-minute windows (500 API requests,
3,000 resolver requests and 100 page requests; September 2025 figures, "subject to change"), per
https://huggingface.co/docs/hub/rate-limits; the fetcher's ceiling
follows those figures and is re-read from that page when `tools/record_fixtures.py` is first run.

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
Environment markers (for example `; sys_platform == "win32"`) are not evaluated: every locked entry is
checked, whatever platform the model runs on, so a platform-only package can raise an alert on a host
that never installs it (a deliberate over-approximation, tested in `tests/unit/test_lockfile.py`).

**Rationale**: the worked example's lock is uv-generated in this format; normalisation handles the
spec's naming edge case.

## Deferred (not in feature 001)

- OSV bulk feed (`modified_id.csv`) for fleet-scale incremental checks.
- More scanners (ModelScan, fickling) and other hubs.
- Base-model and dataset change alerts; model-level weaknesses; a web view; the first platform adapter.

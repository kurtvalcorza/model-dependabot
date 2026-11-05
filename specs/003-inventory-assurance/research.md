# Research: Evidence-Backed Dependency Discovery and Inventory Assurance

**Feature**: [spec.md](spec.md) | **Plan**: [plan.md](plan.md) | **Date**: 2026-11-05

Each item records the decision, why it was made and what else was considered. Code references are to
`main` at `7adfa4590552` plus the hardening commit `e0cd7a7` on this branch.

## A1. Where an imported code-free claim comes from today

**Finding**: `import` (`inventory/cyclonedx.py`, `_import_weight`) takes `format` and `can-run-code` from
the document's own properties and only checks that they *fit the file name* (`class_fits_name`). A pickle
described as `model.safetensors` with `can-run-code=false` passes. Hub weight files are classified by name
alone (`classify(name, None)`) at registration too, both from a manifest and from an import. The strict
policy (`lifecycle._apply_format_rules`) counts any pinned entry with `can_run_code is False` as a code-free
file beside the others (`_code_free`) and returns early. Nothing records where `can_run_code` came from.

**Decision**: record the origin of each weight entry's format claim when it is registered
(`format_origin`: `bytes`, `name`, `record` or `import`) and keep confirmations of imported claims in a
separate table keyed by model, version and entry (A3), since inventory versions are immutable.
`_code_free` counts an entry only if its origin is `bytes`, `name` (owner's manifest, FR-007) or `record`,
or if its latest confirmation is `confirmed`.

**Alternatives considered**: rewriting `can_run_code` on the stored entry after a check (breaks the
immutable version and its exported BOM); refusing imports with code-free claims (breaks import for honest
BOMs and gives the owner no way forward).

## A2. Telling old imported versions from manifest registrations (FR-005)

**Finding**: the database does not record how a version was registered. `model_versions` holds
`manifest_sha256` (the hash of the manifest *or* the imported BOM), `base_dir` and, for records,
`registration_record_sha256`. An imported version and a manifest version are indistinguishable after the
fact.

**Decision**: add `model_versions.origin` (`manifest`, `record`, `import`), set from now on. Rows from
before this feature get `NULL` (legacy). Rows with `registration_record_sha256` are back-filled as `record`
on open. For a legacy version, every code-free weight entry is treated like an imported claim: it counts
only once confirmed. A legacy version registered from a manifest has local files whose bytes the
`format-check` source confirms locally (they were classified from bytes at registration, so this succeeds
whenever the file is still there), and hub files whose headers it reads (A4). The only legacy versions that
behave differently from today are those whose code-free file cannot be confirmed (local file gone, hub
unreachable) or is shown not to be code-free. Registering the model again gives a version with a known
origin.

**Alternatives considered**: guessing origin from entry shapes (unreliable: an imported local weight looks
like a manifest one); leaving legacy versions trusted (keeps the SEC-01 hole open for every existing
import, against the owner's answer to FR-005). The narrow effect on legacy manifest versions is recorded in
the plan's Complexity Tracking.

## A3. Recording confirmations: a claim-check table and a new source

**Decision**: a new check source `format-check` (name provisional, FR-002b) and a table `claim_checks`. In
each run the source collects every code-free weight entry of each target version that needs confirmation
(origin `import` or legacy, `can_run_code` false, no final confirmation yet). For each it reads the bytes
(local file, A5) or the header (hub file, A4), classifies them and records one row: `confirmed`,
`contradicted` or `unreadable`, with the measured format, the reason and an evidence row. `confirmed` and
`contradicted` are final for that version and entry; `unreadable` is retried next run. The source is in the
default source list, so `check` with no `--source` runs it; with no entries to confirm it makes no
requests and reports `ok`. A failure to reach the hub fails the source (exit code 2) and leaves the claim
unverified, which already counts as absent, so failure is fail-closed.

`format-check` joins `WEIGHT_SOURCES`, so the format rules run after it whenever it is requested.

**Contradiction**: recorded as a watch event `format_claim_contradicted` (the inventory claimed code-free,
the bytes show otherwise), with both the claim and the measurement as evidence. It is not a new alert kind:
the strict policy already alerts on the code-capable file, and a contradicted claim no longer suppresses
it (constitution IV).

**Alternatives considered**: folding the work into `picklescan` (which reads only code-capable local files)
or `hf-scan` (which reads the hub's scan verdict, not bytes); confirming only at import time (stale for
legacy versions, and the hub may be unreachable at import).

## A4. Reading a hub file's header

**Decision**: a ranged `GET` of `https://huggingface.co/{repo}/resolve/{commit}/{file}` with
`Range: bytes=0-1048575` (1 MiB), following redirects under the SEC-02 rules (the hub redirects file
downloads to its storage hosts over https). The total size comes from the response's `Content-Range`
(or `Content-Length` when the server ignores the range and answers 200; then the fetcher reads only the
first 1 MiB and closes). If the lead shows a safetensors header longer than the lead, one more range is
read up to `8 + header length`, capped at 16 MiB; a longer header leaves the claim `unreadable`. Before
the header, the hub's tree at the pinned commit (`HuggingFace.hub_file`) must list the file with the
SHA-256 the inventory pins; a different hash is `contradicted` (identity), a missing file `unreadable`.

Classification reuses `inventory/build.py`'s rules through a new `classify_lead(name, lead, total_size)`,
which runs the same safetensors, GGUF, pickle and zip tests on a lead plus the true size (the existing
tests need the size to check that offsets and counts fit). A lead that starts like a zip is never confirmed
code-free (the central directory is at the end, out of reach). ONNX keeps its known limit: a protocol 0 or
1 pickle named `.onnx` passes, as for local files.

Evidence is a JSON body holding the URL, commit, file, status, `Content-Range`, the lead's SHA-256 and
length, and the measured class; the weight bytes themselves are not stored.

**To verify**: the hub and its storage hosts honour `Range` on `resolve` URLs (the hub's own client resumes
downloads this way). This session's network policy blocks `huggingface.co`, so a marked live test records
the answer and the recorded fixtures are made from it before the adapter is written (constitution V).

**Alternatives considered**: the hub's security scan (says whether a scanner flagged the file, not what its
format is); downloading the whole file (unbounded, and against the "never downloads weights" stance);
trusting the tree's LFS metadata (it gives a hash and size, not a format).

## A5. Confirming a local imported file

**Decision**: when an imported (or legacy) code-free entry has a local `location`, `format-check` reads
the file under the version's `base_dir` with the same containment rule as discovery (A9): the resolved
path must stay inside `base_dir`, and a symbolic link out of it is not followed. The file is hashed in
chunks; a hash that differs from the pinned identifier is `contradicted`; otherwise it is classified from
its bytes with `classify`. At `import`, the same read happens once when the file is present, so a fresh
import of a local mislabelled pickle is classified from its bytes straight away (FR-003): the entry is
stored code-capable, `format_origin` `bytes`, and a `contradicted` confirmation is recorded.

## A6. Model card front matter

**Finding**: Hugging Face model cards keep their metadata as YAML front matter between `---` lines at the
top of `README.md`. The keys used here are `base_model` (a string or a list), `base_model_relation`,
`datasets` (a list), `license`, `license_name` and `license_link`. There is no key for a base model's
revision.

**Decision**: add one runtime dependency, PyYAML, and read the front matter with its safe loader, wrapped
to refuse anchors and aliases (so a crafted card cannot expand into a huge structure) and limited to the
first 256 KiB of the file. Only the keys above are read; any other key is listed as unrecognised.
`license_link` is kept as text and never fetched. A list of base models gives one candidate per entry with
the gap "several base models; multi-parent lineage is #9". A base model always has the gap "no revision"
unless a manifest supplies one. The licence is normalised with the existing SPDX normaliser.

**Alternatives considered**: a hand-written YAML subset parser (fragile on real cards); `ruamel.yaml`
(heavier, no gain here).

## A7. Python dependency files

**Decision**: a file whose name matches `*requirements*.txt`, `*constraints*.txt` or `*.lock.txt` is
parsed with `lockfile.parse_lock` when every requirement in it is pinned with `==` and at least one
`--hash` (the format registration accepts): its packages are candidates with status
declared-but-unverified. Otherwise each requirement is a candidate with the gap "not locked" (or "no exact
version"). `pyproject.toml` `[project].dependencies` and `[project.optional-dependencies]` are read with
`tomllib` the same way. `uv.lock`, `poetry.lock`, `Pipfile.lock` and `pylock.toml` are listed under
skipped with the reason "lock format not read in this version", so coverage shows they exist.

`-r` and `-c` includes are followed only to files inside the project; URL and VCS requirements are kept as
text with the gap "not a registry package".

## A8. Discovery limits

**Decision** (published in the CLI contract): at most 50,000 directory entries visited, depth 24, 2,000
weight files, 1 MiB per text file read (model card front matter 256 KiB). Directories named `.git`, `.hg`,
`.svn`, `.venv`, `venv`, `node_modules`, `__pycache__`, `.tox`, `.mypy_cache`, `.ruff_cache` and
`site-packages` are not entered, and each is listed under skipped. Weight files are hashed in full in
1 MiB chunks; nothing else is read from them beyond what `classify` reads.

## A9. Staying inside the project

**Decision**: the project root is resolved once. The walk uses `os.walk(followlinks=False)`; a file that
is a symbolic link is resolved and read only if the target is inside the root. A path named inside a file
(a manifest weight path, a `-r` include) is joined to its file's directory and resolved; an absolute path,
or one that resolves outside the root, is not read and becomes a gap "outside the project". On a platform
where resolving a path can be raced, the check is made on the resolved path that is then opened.

## A10. The proposed manifest

**Decision**: written with a small TOML writer (the standard library reads TOML but does not write it), in
the existing manifest format (spec 001 contract), and checked by loading it back with `load_manifest`
before it is reported as written. Active entries: `[model] id` (from `--model-id`, else the folder name),
local weight files under `[[weights]] path`, and `[environment] lock` when exactly one hash-locked file was
found (with several, all are comments: "several lock files; choose one"). Every other candidate (base
model, datasets, licence, unlocked dependencies, conflicts, gaps, skipped items) is a comment block with its
status, origin and gaps. The file opens with a header comment stating that it is a proposal and cannot
establish complete training provenance (FR-023). An existing output path is refused unless `--force` is
given; the file is written to a temporary name beside it and renamed.

## A11. Upstream mode for discovery

**Decision**: `--upstream` reads hub model info (`hf.read_model`) for each base model and hub dataset info
(`hf.read_dataset`) for each dataset named as a hub identity in the card, through the same `UrlFetcher` as
`check` (anonymous, rate-limited, redacted, SEC-02 redirect rules). It records the answer's status,
retrieval time, declared licence and current `sha` as a proposed revision labelled "head at observation
time, not established as the training revision". A refusal or failure marks the candidate unavailable with
the reason; discovery still completes and exits 0. DOIs found in the card are not looked up in this
version. Discovery opens no database, so it uses no ETag cache.

## A12. The audit's coverage rules

**Decision**: a source is *relevant* to an entry by kind: a pinned package to `osv`; a pinned local
code-capable weight file to `picklescan`; a pinned hub weight file to `hf-scan`; a weight file whose
code-free claim needs confirmation to `format-check`; a base model to `hf-hub`; a hub dataset to `hf-hub`
and `hf-takedowns`; a dataset DOI to the sources its stored routing names (`crossref`, `datacite`,
`zenodo`, `figshare`). For each relevant source the audit finds the latest finished check run, after the
version was registered, whose scope covered the model (`all` or the model id) and which requested that
source, and reports its time and status. A source never run since registration is "not checked"; a source
whose latest result is older than `--stale-after` hours (default 24) is stale. An entry with no relevant
source (a gap, a dataset with neither DOI nor hub identity, a weight file of unknown format) is uncheckable,
with its reason.

Entry classification for the audit: **verified** when pinned and every claim's origin is the owner's
manifest or registration record, a local measurement or a confirmation; **declared-but-unverified** when a
claim is imported (or legacy) and not yet confirmed; **conflicting** when a confirmation contradicted it;
**unavailable** when it is a gap or its confirmation was unreadable in the latest run.

## A13. Fixtures and evaluation

**Decision**: new recorded fixtures under `tests/fixtures/format_check/` (hub tree and ranged answers:
safetensors, GGUF, a pickle named `.safetensors`, a zip, a 200 that ignores the range, a refusal) and
fixture projects under `tests/fixtures/projects/` (hash-locked and unlocked requirements, `pyproject.toml`,
weight files including a mislabelled pickle, a model card, a symbolic link out, a `..` include, an
oversized file). `RecordedFetcher` gains a `range` key in a recording's meta so a ranged request is matched
exactly. The held-out evaluation (FR-026) reuses `research/heldout/` with a per-kind tally script; its
results are a separate report, not part of the test suite.

## Deferred (not in this feature)

- Naming the deployed weight file so the strict policy judges only it (FR-006).
- Confirming hub weight files registered from an owner's manifest (trusted by name today, FR-007).
- Lock formats other than hash-locked requirements; DOI lookups in discovery; lineage (#9).
- Any release gate (#8).

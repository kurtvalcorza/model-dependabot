# Contract: command-line additions (feature 003)

Extends [001's CLI contract](../../001-inventory-alerts/contracts/cli.md) and
[002's](../../002-upstream-watch/contracts/cli.md). Every existing command, exit code and JSON field is
unchanged; additions are new commands, a new source name and new optional JSON fields (FR-024). Command
names are provisional until this contract is reviewed (decision D2).

## New commands

| Command | What it does |
| :-- | :-- |
| `inventory audit ID [--version N] [--stale-after HOURS]` | Reports findings, inventory assurance and check coverage for one version (the latest by default) from the stored data. Opens the database read-only and never upgrades it; contacts no source and writes nothing. `--stale-after` defaults to 24 |
| `discover PATH [--manifest FILE] [--model-id ID] [--upstream] [-o FILE [--force]]` | Proposes candidate dependencies for the project folder `PATH`. Reads nothing outside `PATH`. No network request unless `--upstream`. Writes nothing unless `-o`; refuses an existing `-o` file unless `--force`. Opens no database |

## Changed command

`check` gains the source `format-check` (confirms imported code-free claims; research A3, A4). It is in
the default source list, so `check ID` and `check --all [--scheduled]` run it. `--source` selects or leaves
it out as for any other source. A version with no claim needing confirmation makes no request for it.

## Exit codes

| Command | 0 | 1 | 2 | 3 |
| :-- | :-- | :-- | :-- | :-- |
| `inventory audit` | the audit completed, whatever it reports (FR-014) | unknown model or version, bad arguments, a database older than feature 002 | never | unexpected error |
| `discover` | discovery completed, including when upstream lookups failed (each such candidate is `unavailable`) | `PATH` is not a directory, `--manifest` unreadable or invalid, `-o` exists without `--force` | never | unexpected error |
| `check` | as before | as before | as before; now also when `format-check` failed (network error or server error after retries; a 401, 403 or 404 is an `unreadable` claim, not a failure) | as before |

## Discovery limits (research A8)

| Limit | Value | When reached |
| :-- | :-- | :-- |
| Directory entries visited | 50,000 | the walk stops; `skipped` gets `{path: PATH, reason: "entry limit reached"}` |
| Depth | 24 | deeper directories are skipped and listed |
| Weight files | 2,000 | further weight files are listed as skipped, not hashed |
| Text file read (requirements, `pyproject.toml`) | 1 MiB | the file is skipped and listed |
| Model card front matter | 256 KiB | the card is listed as unreadable |
| Directories not entered | `.git`, `.hg`, `.svn`, `.venv`, `venv`, `node_modules`, `__pycache__`, `.tox`, `.mypy_cache`, `.ruff_cache`, `site-packages` | listed once each under `skipped` |

## Header-read limits (`format-check`, research A4)

| Limit | Value |
| :-- | :-- |
| First range | 1 MiB |
| Second range (safetensors header only) | up to `8 + header length`, at most 16 MiB; longer is `unreadable` |

## JSON shapes (excerpt)

`inventory audit --json` ([data-model.md](../data-model.md), Audit report):

```json
{
  "model_id": "example-detector-v1",
  "version": 2,
  "produced_at": "2026-11-05T09:00:00Z",
  "stale_after_hours": 24,
  "statement": "No alerts is not evidence that the inventory is complete or the model is safe.",
  "summary": {
    "checked": true, "alerts_open": 0, "watch_events": 1, "entries": 9, "verified": 6,
    "declared_but_unverified": 1, "conflicting": 0, "unavailable": 2, "gaps": 2, "uncheckable": 1,
    "sources_failed": 1, "sources_stale": 0, "sources_not_checked": 0
  },
  "findings": {"state": "checked", "alerts": [], "watch_events": [{"kind": "pickle_format", "...": "..."}]},
  "assurance": {
    "entries": [
      {
        "kind": "weight_file", "identifier": "sha256:…", "location": "hf:org/repo/model.safetensors",
        "status": "declared-but-unverified", "gap_reason": null,
        "claims": [{"claim": "can_run_code", "value": false, "origin": "import", "verification": "unverified"},
                   {"claim": "sha256", "value": "sha256:…", "origin": "import", "verification": "confirmed"}]
      }
    ],
    "undeclared_kinds": ["datasets"]
  },
  "coverage": {
    "sources": [
      {"source": "osv", "relevant_entries": ["pkg:pypi/torch@2.5.1", "…"], "last_run_id": 41, "last_finished_at": "2026-11-05T03:17:09Z",
       "status": "ok", "age_hours": 5.7, "stale": false},
      {"source": "format-check", "relevant_entries": ["sha256:…"], "last_run_id": 41,
       "last_finished_at": "2026-11-05T03:17:09Z", "status": "failed: HTTP 503 after 4 attempts",
       "age_hours": 5.7, "stale": false}
    ],
    "uncheckable": [{"kind": "dataset", "identifier": null, "location": null, "reason": "no DOI"}]
  }
}
```

`discover --json` ([data-model.md](../data-model.md), Discovery result):

```json
{
  "project": "/work/detector",
  "observed_at": "2026-11-05T09:00:00Z",
  "upstream": false,
  "statement": "These are dependencies proposed from the evidence available in the project. Discovery cannot establish complete training provenance.",
  "candidates": [
    {"kind": "package", "identity": {"name": "torch", "version": "2.5.1", "hashes": ["sha256:…"]},
     "origin": {"file": "requirements.lock.txt", "line": 12}, "status": "declared-but-unverified",
     "observed_at": "2026-11-05T09:00:00Z", "gaps": []},
    {"kind": "weight_file",
     "identity": {"path": "runs/best.safetensors", "sha256": "…", "size": 1024, "format": "pickle", "can_run_code": true},
     "origin": {"file": "runs/best.safetensors"}, "status": "verified", "observed_at": "2026-11-05T09:00:00Z",
     "gaps": [], "note": "named as safetensors; the bytes show a pickle"},
    {"kind": "base_model", "identity": {"hub_repo": "org/base", "revision": null},
     "origin": {"file": "README.md", "key": "base_model"}, "status": "declared-but-unverified",
     "observed_at": "2026-11-05T09:00:00Z", "gaps": ["no revision"], "manifest": "conflicts",
     "manifest_value": {"hub_repo": "org/other-base"}}
  ],
  "declared_not_seen": [],
  "skipped": [{"path": ".venv", "reason": "environment directory not entered"},
              {"path": "uv.lock", "reason": "lock format not read in this version"}],
  "limits": {"entries": 50000, "depth": 24, "weight_files": 2000, "text_bytes": 1048576, "card_bytes": 262144},
  "output": {"path": "proposed.toml", "written": true}
}
```

`check --json`: `sources` may include `"format-check": "ok" | "failed: …" | "skipped"`; each model's
summary may include `claim_checks: [{identifier, outcome, measured_format, reason}]`.

## Proposed manifest written by `discover -o` (FR-022, research A10)

The existing [manifest format](../../001-inventory-alerts/contracts/manifest.md), unchanged. Only entries
registration measures or pins itself are active; everything else is a comment. Loading the file back with
the manifest reader must succeed before discovery reports it as written.

```toml
# Proposed by model-dependabot discover on 2026-11-05T09:00:00Z from /work/detector.
# These are dependencies proposed from the evidence available in the project.
# Discovery cannot establish complete training provenance. Review every comment below.

[model]
id = "detector"

[[weights]]
path = "runs/best.safetensors"   # verified: sha256 …, bytes show pickle (can run code)

[environment]
lock = "requirements.lock.txt"   # 41 packages, hash-locked

# --- not registered as written: uncomment what you accept --------------------------------------
# base_model: declared-but-unverified, from README.md (base_model); gaps: no revision
# [base_model]
# hub = "hf:org/base"
# revision = "<commit>"
#
# dataset: declared-but-unverified, from README.md (datasets); gaps: no DOI, hub dataset
# [[datasets]]
# hub = "hf:org/data"
#
# package: not locked, from pyproject.toml ([project].dependencies): numpy>=1.26
```

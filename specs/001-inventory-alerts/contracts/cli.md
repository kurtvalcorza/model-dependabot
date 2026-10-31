# Contract: command-line interface

The tool is `model-dependabot`. Every command accepts `--db PATH` (default `./model-dependabot.db`) and
`--json` (machine-readable output, the contract a later web view or platform adapter consumes). Human
output is plain text. No command changes a model or writes to a model's repository (FR-017).

## Commands

| Command | Does | Requirements |
| :-- | :-- | :-- |
| `register MANIFEST.toml [--model-id ID]` | Registers a new model, or a new version of `ID`, from a [manifest](manifest.md); computes hashes; records gaps. A new version re-evaluates the previous version's open alerts at registration (fixed or carried forward), by comparing the two inventories; no source is consulted. | FR-001 to FR-003, FR-005, FR-014 |
| `record MANIFEST.toml -o FILE` (or `--out FILE`) | On the machine that holds the weight files: hashes each local weight file, classifies its format, scans each code-capable one with the local pickle scanner and writes a [registration record](registration-record.md). Writes no database entry. | FR-001, FR-002, FR-011, FR-022 |
| `register MANIFEST.toml --from-record RECORD.json [--model-id ID]` | Registers as `register` does, but takes the local weight files' hashes, formats and scan evidence from the record instead of reading the bytes, which need not be on this machine; applies the recorded scans as a check's local scan would. Refuses (exit code 1, nothing written) a record that does not match the manifest, whose `record_sha256` is wrong or that lacks scan evidence for a code-capable file ([rules](registration-record.md#registering-from-a-record)). | FR-001 to FR-003, FR-011, FR-022 |
| `import BOM.json --model-id ID` | Registers a version from an existing CycloneDX inventory ([profile](inventory-profile.md)); entries without exact identifiers become gaps. | FR-004, FR-003 |
| `inventory show ID [--version N]` | Lists entries with identifiers, and gaps with their reasons. | US1 |
| `inventory export ID [--version N] -o FILE` | Writes the stored CycloneDX 1.7 document, validated against the official schema. | FR-004 |
| `check (ID \| --all) [--source osv,picklescan,hf-scan]` | Runs the checks now and records a check run; closes alerts as `withdrawn` or `cleared` when a source that answered in this run withdraws or clears the cause. Scheduled use: `check --all` daily. With `picklescan`, a file registered from a record whose bytes are not on this machine is a `weight_file_absent` watch event; without it no local file is read. | FR-006, FR-009, FR-011, FR-012, FR-016, FR-023 |
| `policy ID --format (default\|strict) --by NAME` | Sets the model's format policy and records who set it and when (the evidence for a `format_policy` alert); takes effect at the next check. | FR-021 |
| `alerts ID [--state open\|closed\|all]` | Lists alerts by severity, then watch events. | FR-018 |
| `alert show ALERT_ID` | One alert with all its evidence. | FR-019 |
| `alert dismiss ALERT_ID --reason REASON [--note TEXT] --by NAME` | Dismisses with a listed reason. | FR-015 |
| `history ID` | Closed alerts with how (`fixed`, `dismissed`, `withdrawn` or `cleared`) and when they closed. | US5 |

`REASON` is one of `not_used_at_runtime`, `risk_accepted`, `false_positive`, `fix_not_available`.

## Exit codes

| Code | Meaning |
| :-- | :-- |
| 0 | Success. For `check`: completed, whether or not alerts were found |
| 1 | Invalid input (manifest, inventory, arguments) |
| 2 | `check` finished but at least one source failed; affected alerts were left unchanged |
| 3 | Unexpected error |

`check` never exits non-zero just because alerts exist, so a scheduler does not mistake findings for
failures; scripts read the JSON instead.

## JSON shapes (excerpt)

`alerts ID --json`:

```json
{
  "model_id": "example-detector-v1",
  "current_version": 2,
  "alerts": [
    {
      "alert_id": 17,
      "kind": "package_advisory",
      "state": "open",
      "severity": "HIGH",
      "severity_origin": "database_specific",
      "cause": {"advisory_id": "GHSA-xxxx-xxxx-xxxx", "advisory_ids": ["GHSA-xxxx-xxxx-xxxx", "PYSEC-2026-0000"], "aliases": ["PYSEC-2026-0000", "CVE-2026-0000"], "package": "pillow", "version": "12.3.0", "fixed": ["13.0.0"], "severity_from": "GHSA-xxxx-xxxx-xxxx"},
      "opened_in_version": 1,
      "evidence": [
        {"source": "osv.dev", "url": "https://api.osv.dev/v1/vulns/GHSA-xxxx-xxxx-xxxx", "retrieved_at": "2026-10-23T08:00:00Z", "matched_identifier": "pkg:pypi/pillow@12.3.0", "body_sha256": "…", "canonical_sha256": "…", "detail": {"local_match": true}},
        {"source": "osv.dev", "url": "https://api.osv.dev/v1/vulns/PYSEC-2026-0000", "retrieved_at": "2026-10-23T08:00:00Z", "matched_identifier": "pkg:pypi/pillow@12.3.0", "body_sha256": "…", "canonical_sha256": "…", "detail": {"local_match": true}}
      ]
    }
  ],
  "watch_events": [
    {"kind": "pickle_format", "identifier": "sha256:e0ae635d…", "detail": {"format": "pytorch-zip", "suggestion": "safetensors or ONNX"}}
  ],
  "last_check": {"run_id": 42, "sources": {"osv": "ok", "picklescan": "ok", "hf-scan": "failed: timeout"}}
}
```

`history ID --json` (closed alerts, oldest closure first; `outcome` is `fixed`, `dismissed`, `withdrawn`
or `cleared`, with the fields that outcome needs and the others `null`):

```json
{
  "model_id": "example-detector-v1",
  "current_version": 2,
  "history": [
    {
      "alert_id": 17,
      "kind": "package_advisory",
      "outcome": "fixed",
      "severity": "HIGH",
      "cause": {"advisory_id": "GHSA-xxxx-xxxx-xxxx", "package": "pillow", "version": "12.3.0"},
      "opened_in_version": 1,
      "closed_at": "2026-10-24T09:00:00Z",
      "closed_by_version": 2,
      "dismissal_reason": null,
      "dismissed_by": null,
      "note": null,
      "evidence": [{"source": "inventory", "url": "", "retrieved_at": "2026-10-24T09:00:00Z", "matched_identifier": "pkg:pypi/pillow@12.3.0", "body_sha256": "…", "canonical_sha256": "…", "detail": {"previous_version": 1, "version": 2, "found": false}}]
    }
  ]
}
```

A lock that pins one package at two versions (environment markers are not evaluated, research R10)
gives one `package_advisory` alert per vulnerability and package, as `cause_key` has no version: its
`cause.version` and `cause.identifier` are the first affected pin in inventory order, and
`cause.also_affected` lists the other affected pinned versions, sorted; it is left out when there is none.
Amended 2026-10-31 after review (F9): the cause had named whichever pin was processed last.

A `package_advisory` alert stands for one vulnerability. When OSV returns several records for the
same package version that alias each other, the alert's `cause.advisory_ids` lists every id, primary
first: `cause.advisory_id` is that primary id (the GHSA id if there is one, the lexicographically
first if several, else the lexicographically first id) and `cause_key` is built from it. `aliases`,
`affected` and `fixed` are the union over the records, `severity` is the highest of them and
`cause.severity_from` names the record it came from, and there is one evidence entry per record. An
alert with one record has `advisory_ids` of one id.

Each evidence entry has `body_sha256`, the SHA-256 of the stored raw response, and
`canonical_sha256`, the SHA-256 of the body's canonical JSON form (sorted keys, no insignificant
whitespace, UTF-8), or `null` for a body that is not JSON. A consumer that compares an alert's
evidence between runs should compare `canonical_sha256` where it is set: a source may serve the same
JSON with different bytes, and such a response is not stored as new evidence.

Field names in the JSON are stable within a major version of the tool.

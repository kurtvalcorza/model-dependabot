# Contract: command-line interface

The tool is `model-dependabot`. Every command accepts `--db PATH` (default `./model-dependabot.db`) and
`--json` (machine-readable output, the contract a later web view or platform adapter consumes). Human
output is plain text. No command changes a model or writes to a model's repository (FR-017).

## Commands

| Command | Does | Requirements |
| :-- | :-- | :-- |
| `register MANIFEST.toml [--model-id ID]` | Registers a new model, or a new version of `ID`, from a [manifest](manifest.md); computes hashes; records gaps. A new version re-evaluates the previous version's open alerts (fixed or carried forward). | FR-001 to FR-003, FR-005, FR-014 |
| `import BOM.json --model-id ID` | Registers a version from an existing CycloneDX inventory ([profile](inventory-profile.md)); entries without exact identifiers become gaps. | FR-004, FR-003 |
| `inventory show ID [--version N]` | Lists entries with identifiers, and gaps with their reasons. | US1 |
| `inventory export ID [--version N] -o FILE` | Writes the stored CycloneDX 1.7 document, validated against the official schema. | FR-004 |
| `check (ID \| --all) [--source osv,picklescan,hf-scan]` | Runs the checks now and records a check run. Scheduled use: `check --all` daily. | FR-006, FR-011, FR-012, FR-016 |
| `alerts ID [--state open\|closed\|all]` | Lists alerts by severity, then watch events. | FR-018 |
| `alert show ALERT_ID` | One alert with all its evidence. | FR-019 |
| `alert dismiss ALERT_ID --reason REASON [--note TEXT] --by NAME` | Dismisses with a listed reason. | FR-015 |
| `history ID` | Closed alerts with how and when they closed. | US5 |

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
  "model_id": "rice-pest-r50-v5",
  "current_version": 2,
  "alerts": [
    {
      "alert_id": 17,
      "kind": "package_advisory",
      "state": "open",
      "severity": "HIGH",
      "severity_origin": "database_specific",
      "cause": {"advisory_id": "GHSA-xxxx-xxxx-xxxx", "aliases": ["CVE-2026-0000"], "package": "pillow", "version": "12.3.0", "fixed": ["13.0.0"]},
      "opened_in_version": 1,
      "evidence": [
        {"source": "osv.dev", "url": "https://api.osv.dev/v1/vulns/GHSA-xxxx-xxxx-xxxx", "retrieved_at": "2026-10-23T08:00:00Z", "matched_identifier": "pkg:pypi/pillow@12.3.0", "body_sha256": "…", "detail": {"local_match": true}}
      ]
    }
  ],
  "watch_events": [
    {"kind": "pickle_format", "identifier": "sha256:e0ae635d…", "detail": {"format": "pytorch-zip", "suggestion": "safetensors or ONNX"}}
  ],
  "last_check": {"run_id": 42, "sources": {"osv": "ok", "picklescan": "ok", "hf-scan": "failed: timeout"}}
}
```

Field names in the JSON are stable within a major version of the tool.

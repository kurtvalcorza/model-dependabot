# Contract: edge evidence in findings, inherited events and the audit (feature 011)

## Edge view (all outputs)

```json
{
  "edge_id": 7,
  "relationship": "merged-from",
  "relationship_recorded": null,
  "parent": {"kind": "hub", "repo": "example-org/base-a", "revision": "0123…"},
  "origin": "manifest",
  "claimed_origin": null,
  "state": "owner",
  "source": {"file": "model.toml", "sha256": "…", "key": "parents[0]"},
  "recorded_at": "2026-11-20T10:00:00Z",
  "gap": null,
  "resolved": null,
  "note": null
}
```

`parent.kind = "model"` has `model_id` and `version`; `resolved` is then true or false; `note` is
`resolved by id and version only` for a resolved imported reference. `state` is `owner` or `unverified`
and never `verified` (FR-008, SC-006); a test asserts that the string `verified` never appears as an
edge state in any text or JSON output.

## Direct hub finding (alert, FR-009, FR-014, FR-024)

`base_model_disabled`, `base_model_unavailable` and a base model's `licence_changed` keep their kind,
cause key, severity and state rules. The cause gains:

```json
"edges": [
  {"relationship": "fine-tuned-from", "origin": "manifest", "revision": "0123…", "source_key": "parents[0]"},
  {"relationship": "quantized-from", "origin": "manifest", "revision": "89ab…", "source_key": "parents[1]"}
]
```

Text (`alerts`, `alert show`) adds one line per edge under the cause:
`  via merged-from edge (manifest, owner) at 0123…`. A legacy edge reads
`  via unspecified edge (manifest, owner) at 0123…`.

## Inherited finding (watch event `lineage_inherited`, FR-018 to FR-020)

```json
{
  "kind": "lineage_inherited",
  "entry_identifier": "model:example-base@1/weight_file_scan:sha256:…",
  "detail": {
    "reach": "transitive",
    "relationship_unspecified": false,
    "parent_alert": {"alert_id": 12, "model_id": "example-base", "kind": "weight_file_scan",
                     "cause_key": "weight_file_scan:sha256:…", "severity": "HIGH", "state": "open"},
    "paths": [[
      {"child": "example-child@1", "parent": "example-mid@1", "relationship": "adapter-for", "origin": "manifest"},
      {"child": "example-mid@1", "parent": "example-base@1", "relationship": "adapter-for", "origin": "manifest"}
    ]]
  }
}
```

Text: `inherited from parent example-base v1 (transitive: example-child v1 -adapter-for-> example-mid v1
-adapter-for-> example-base v1): alert 12 weight_file_scan HIGH`. A direct one reads
`inherited from parent example-base v1 over adapter-for (manifest)`. An `unspecified` edge on the path
adds `[relationship unspecified]`. An inherited event never counts as an alert, for `check` output,
summaries or `--fail-on` (FR-027).

## Audit (`inventory audit`, FR-030)

JSON gains `lineage: {edges: [edge view…], problems: [...], notes: [...]}`; each problem is
`{kind, models: ["id@version", …], edges: [edge_id, …], detail}` with kind `cycle`, `duplicate_parent`,
`ambiguous_relationship` or `parent_not_registered`. Text gains:

```text
Lineage (2 edges, 1 problem):
  merged-from   hf:example-org/base-a@0123…   manifest  owner
  fine-tuned-from model:example-b@1          manifest  owner  resolved
  problem cycle: example-a v1 -> example-b v1 -> example-a v1
  note merge with one parent
```

## Exit codes

Unchanged for every command (SC-007). New manifest errors are exit 1, as every invalid manifest value.

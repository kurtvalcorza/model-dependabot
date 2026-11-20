# Contract: command-line additions (feature 010)

Extends the CLI contracts of [001](../../001-inventory-alerts/contracts/cli.md) to
[004](../../004-scan-policy-gates/contracts/cli.md). Every existing command, option, exit code, text
line and JSON field keeps its meaning and its bytes. The only addition is one option on two commands.
Every command still takes `--db PATH` and `--json`.

## Changed commands

| Command | Change |
| :-- | :-- |
| `alert show ALERT_ID [--advice]` | With `--advice`: the payload gains `advice` (one advisory view) as its last key; the text gains a blank line and the advice block after today's text |
| `alerts ID [--state open\|excepted\|closed\|all] [--advice]` | With `--advice`: every object in `alerts` and `excepted` gains `advice` as its last key, watch events gain nothing, and the payload gains `advice_summary` as its last key; the text gains a blank line and one advice block per alert, in the listing order |

`history`, `run show`, `check`, `inventory audit` and every other command are unchanged and take no
`--advice` option (spec, Assumptions: no changes to `check`).

## Invariants

- **Prefix**: with `--advice`, the text output begins with the exact bytes the same command prints
  without it, and the JSON output parses to an object that, with every `advice` and
  `advice_summary` key removed, is equal to the JSON without the option (FR-018).
- **Exit codes**: the same as without `--advice` in every case, including an unknown alert or model
  (exit 1) (FR-017).
- **Read-only**: no store write and no network request (FR-002, SC-004; research R8 and Q2).
- **Deterministic**: the same stored rows give the same bytes (FR-003).

## JSON: the `advice` object

Shape and field order of [data-model.md](../data-model.md), Advisory view. Example for a package
advisory on an `import` version, abridged:

```json
"advice": {
  "schema": "advice/2",
  "alert_id": 7,
  "severity": {"value": "HIGH", "origin": "cvss_v3", "note": "band of the source's CVSS vector"},
  "entry": {
    "status": "resolved", "reason": null, "kind": "package",
    "identifier": "pkg:pypi/pillow@9.0.0", "matched_by": "identifier",
    "in_current_version": true, "last_held_in_version": 2, "opened_in_version": 1, "closed_by_version": null,
    "places": [
      {"version": 2, "origin": "import", "section": null, "location": null, "revision": "9.0.0",
       "marker": {"state": "not_recorded", "expression": null}},
      {"version": 1, "origin": "manifest", "section": "[environment] lock", "location": null, "revision": "9.0.0",
       "marker": {"state": "set", "expression": "sys_platform == \"linux\""}}
    ]
  },
  "relationship": {
    "value": "package pinned in this model's environment lock", "steps_from_model": 1,
    "basis": {"declared_by": "imported", "origin": "import", "section": null, "version": 2}
  },
  "runtime_use": {
    "state": "unknown", "polarity": null,
    "basis": {"why": "no source observes runtime use and the owner has not declared it for this alert"},
    "context": []
  },
  "established": [
    {"kind": "established",
     "text": "osv reported pkg:pypi/pillow@9.0.0 at 2026-11-19T10:00:00Z (https://api.osv.dev/v1/vulns/GHSA-xxxx)",
     "evidence_ids": [12],
     "evidence": [{"evidence_id": 12, "source": "osv", "url": "https://api.osv.dev/v1/vulns/GHSA-xxxx",
                   "retrieved_at": "2026-11-19T10:00:00Z", "matched_identifier": "pkg:pypi/pillow@9.0.0",
                   "redacted_fields": []}]}
  ],
  "not_established": [
    {"kind": "not_established", "text": "whether this alert affects model demo"},
    {"kind": "not_established", "text": "whether the affected part of pillow is used by the model's code"},
    {"kind": "not_established", "text": "whether pillow is installed where the model runs"}
  ],
  "limitations": [{"kind": "limitation", "text": "It does not prove the vulnerable code is reachable from the model. ..."}],
  "claims": [{"field": "sha256", "value": ["sha256:..."], "origin": "import", "verification": "unverified", "reason": "..."}],
  "impact": "impact undetermined",
  "owner_decision": null,
  "review_steps": [{"number": 1, "text": "..."}, {"number": 4, "text": "How this alert closes: ..."}],
  "rule_doc": "docs/rules/MDB201.md"
}
```

The values above are illustrative; the field names, order and value sets are the contract. Exact
step and limitation wording comes from `rule-texts.toml`.

`advice_summary` (on `alerts --advice` only): `{"alerts_listed": N, "note": null}`, or with
`alerts_listed` 0 a note worded for the `--state` filter applied, then "That is not an assessment
of the model or of how complete its inventory is.": `open` "No alert is open for this model.",
`excepted` "No alert of this model is excepted.", `closed` "No alert of this model is closed.",
`all` "This model has no alert." (US2 scenario 6; review round 1, M10-R1).

## Text: the advice block

```text
Advice for #7 MDB201 (docs/rules/MDB201.md)
  Severity: HIGH (cvss_v3, band of the source's CVSS vector)
  Entry: package pkg:pypi/pillow@9.0.0, in the current version (v2); opened in v1
    v2 import, no manifest section, 9.0.0, marker not recorded
    v1 manifest, [environment] lock, 9.0.0, marker sys_platform == "linux"
  Relationship: package pinned in this model's environment lock (imported declaration, v2)
  Runtime use: unknown: no source observes runtime use and the owner has not declared it for this alert
  Established:
    - osv reported pkg:pypi/pillow@9.0.0 at 2026-11-19T10:00:00Z (https://api.osv.dev/v1/vulns/GHSA-xxxx) [evidence 12]
  Not established:
    - whether this alert affects model demo
    - whether the affected part of pillow is used by the model's code
  Limitations:
    - It does not prove the vulnerable code is reachable from the model. ...
  Claims:
    - sha256 (origin import): unverified
  Impact: impact undetermined
  Owner decision: none
  Review steps:
    1. ...
    4. How this alert closes: ...
```

A `fixed` alert's entry line ends `; last held in v<N>, fixed by v<M>`. An `unresolved` entry prints `Entry: unresolved: <reason> (<identifier>)` and `Relationship: none`. A
dismissal prints `Owner decision: dismissed not_used_at_runtime by <by> at <at>: <note>`; an exception
prints one `Owner decision: exception <id> for <global> by <by> at <at>, expires <date>: <reason>` line
per excepted global. Blocks are separated by one blank line; the text ends without a trailing blank
line, as today.

## Exit codes

Unchanged: 0 on success, 1 for an unknown alert or model or an invalid option, 3 for an unexpected
error. `--advice` adds no code and changes none (FR-017).

## As built (T040)

- A section with no item prints `  <Title>: none` (`Established`, `Not established`, `Limitations`,
  `Claims`).
- A runtime use of `unknown` with context prints one line per other alert:
  `    alert #<id> on the same identifier was dismissed not_used_at_runtime by <by> at <at>`.
- A weight file's relationship line reads `weight file of this model (local) <location>` or
  `(hub) hf:<repo>/<file>`, then `(<owner's|imported|legacy> declaration, v<N>)`.
- `alerts ID --advice` with nothing listed prints, after today's text and a blank line, the
  note of `advice_summary`, worded for the `--state` filter.
- `check`, `history`, `run show` and every other command refuse `--advice` as any unknown option
  (exit 1).
- Issue #28: `schema` is `advice/2`, which adds `places[].marker` to `advice/1`. A package place carries `marker` (`set`, `none` or `not_recorded`; data-model.md,
  Issue #28) and its text line ends `, marker <expression>`, `, no marker` or
  `, marker not recorded`. The marker limitation is listed only for a `not_recorded` marker.

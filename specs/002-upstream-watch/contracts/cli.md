# Contract: command-line interface (additions)

Feature 001's [CLI contract](../../001-inventory-alerts/contracts/cli.md) stands; this feature adds to it,
with one exception: 001's line "Scheduled use: `check --all` daily" is **superseded** for feature 002 by
`check --all --scheduled` daily. A plain `check --all` still runs every check but records the run as
`on_demand`, so it never counts towards FR-012; a host already running `check --all` must add `--scheduled`
(README, T059). No command changes a model, a dataset or any repository (FR-017).

## Changed commands

| Command | Addition | Requirements |
| :-- | :-- | :-- |
| `register MANIFEST.toml` | Also looks up each DOI's registration agency and records the declared licence of the base model and each dataset in the inventory (research U1, U8). A failed lookup is recorded and retried at the next check; registration does not fail because of it. | FR-008 |
| `check (ID \| --all) [--scheduled] [--source …]` | `--scheduled` marks the run as scheduled (FR-012 counts only scheduled refusals); the host scheduler runs `check --all --scheduled`. New source names: `hf-hub`, `hf-takedowns`, `crossref`, `datacite`, `zenodo`, `figshare`. Omitting `--source` runs every source. | FR-001, FR-012, FR-018 |
| `alerts ID` | Lists the new alert kinds by severity with 001's kinds, then the new watch-event kinds. | FR-014 |
| `alert show ALERT_ID` | For redacted evidence, shows both hashes and the fields removed (research U10). | FR-014 |

Exit codes are 001's. A run in which any source failed exits 2, and no alert changed state because of that
source.

## JSON shapes (excerpt)

`alerts ID --json`, showing one alert per new family:

```json
{
  "model_id": "example-detector",
  "current_version": 1,
  "alerts": [
    {
      "alert_id": 31,
      "kind": "dataset_removed",
      "state": "open",
      "severity": "HIGH",
      "severity_origin": "policy",
      "cause": {"dataset": "hf-dataset:owner/name@0123abcd…", "host": "huggingface", "disabled": true, "notice_date": "2026-09-04", "reason": "no reason given"},
      "evidence": [
        {"source": "hf-hub", "url": "https://huggingface.co/api/datasets/owner/name?expand[]=disabled", "retrieved_at": "2026-10-24T02:15:00Z", "matched_identifier": "hf-dataset:owner/name@0123abcd…", "original_sha256": "…", "body_sha256": "…", "redacted_fields": []},
        {"source": "hf-takedowns", "url": "https://huggingface.co/datasets/huggingface-legal/takedown-notices/resolve/main/index.csv", "retrieved_at": "2026-10-24T02:15:01Z", "matched_identifier": "hf-dataset:owner/name@0123abcd…", "original_sha256": "…", "body_sha256": "…", "redacted_fields": ["requesting_entity"], "detail": {"notice_date": "2026-09-04", "label": "notice date, not removal date"}}
      ]
    },
    {
      "alert_id": 32,
      "kind": "licence_changed",
      "state": "open",
      "severity": "HIGH",
      "severity_origin": "policy",
      "cause": {"item": "pkg:huggingface/owner/base@df939e66…", "recorded": "Apache-2.0", "declared": "CC-BY-NC-4.0"},
      "evidence": [{"source": "hf-hub", "…": "…"}]
    },
    {
      "alert_id": 33,
      "kind": "base_model_unavailable",
      "state": "open",
      "severity": "LOW",
      "severity_origin": "policy",
      "cause": {"item": "pkg:huggingface/owner/base@df939e66…", "statement": "no longer publicly available (deleted or made private)", "refusals": ["2026-10-22T02:15:00Z", "2026-10-23T02:15:00Z"]},
      "evidence": [{"source": "hf-hub", "…": "…"}, {"source": "hf-hub", "…": "…"}]
    }
  ],
  "watch_events": [
    {"kind": "base_model_new_revision", "identifier": "pkg:huggingface/owner/base@df939e66…", "detail": {"pinned": "df939e66…", "newest": "7a1c02b4…"}},
    {"kind": "dataset_unreachable", "identifier": "10.6084/m9.figshare.0000000", "detail": {"source": "figshare", "http_status": 404}}
  ],
  "last_check": {"run_id": 57, "trigger": "scheduled", "sources": {"hf-hub": "ok", "hf-takedowns": "ok", "crossref": "ok", "datacite": "ok", "zenodo": "failed: timeout", "figshare": "skipped"}}
}
```

`cause.host` names where a hub dataset lives (`huggingface`); it is not the DOI routing `repository` column of
the data model, which holds only `zenodo`, `figshare` or `other` for DataCite DOIs. A `licence_changed`
alert is one per item (cause key kind + item): a further change while it is open adds evidence and updates
`cause.declared` on the same alert, and a return to the recorded licence closes it as `cleared`, which
`history` then lists.

New field names are stable within a major version of the tool, as for 001.

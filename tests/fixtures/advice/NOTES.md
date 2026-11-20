# Advisory-view fixtures (feature 010, T004 and T005)

`build.py` writes one store at the current schema for the advisory-view tests. It is built through
the `Store` API, not by running checks: every alert carries the cause shape the check that raises its
kind writes (`src/model_dependabot/lifecycle.py`), and every evidence row's body is a recorded answer
copied from `tests/fixtures` (never fetched). Nothing is a weight file and nothing is scanned or
loaded; the weight-file hashes are placeholders.

| Name in `build()` | Model | Rule | What it covers |
| :-- | :-- | :-- | :-- |
| `weight_file_scan` | `advice-model` | MDB101 | local pickle `weights/model.pkl`; `except_weight_alert` marks it excepted |
| `hub_scan` | `advice-model` | MDB102 | hub weight file `hf:mcpotato/42-eicar-street/pytorch_model.bin`, body `hf/eicar-security` |
| `format_policy` | `advice-model` | MDB103 | the same local pickle under the strict format policy |
| `globals_policy` | `advice-model` | MDB104 | the same local pickle under the strict globals policy |
| `package_advisory` | `advice-model` | MDB201 | pillow 12.3.0, an alias group of two advisories, bodies `osv/vuln-GHSA-*` |
| `fixed` | `advice-model` | MDB201 | validators 0.12.2, pinned in version 1 only: fixed by version 2 |
| `dataset_retracted` | `advice-model` | MDB301 | DOI dataset, body `crossref/retracted`, one field redacted |
| `paper_retracted` | `advice-model` | MDB302 | a paper the DOI dataset cites |
| `cleared` | `advice-model` | MDB302 | a second cited paper whose retraction the source cleared |
| `dataset_removed` | `advice-model` | MDB303 | hub dataset `yavon/muxue`, keyed by repository; version 2 pins another revision |
| `dataset_not_findable` | `advice-model` | MDB304 | a DOI that is not findable, body `datacite/not-found` |
| `licence_changed` | `advice-model` | MDB401 | the base model's licence, keyed by repository |
| `licence_changed_dataset` | `advice-model` | MDB401 | the DOI dataset's licence |
| `base_model_disabled` | `advice-model` | MDB501 | base model `openai-community/gpt2`, body `hf_upstream/model-disabled` |
| `base_model_unavailable` | `unavailable-model` | MDB502 | gated base model, body `hf_upstream/model-gated` |
| `record_weight` | `record-model` | MDB101 | a version registered from a record, with a `weight_file_absent` watch event |
| `imported_package` | `import-model` | MDB201 | an `import` version: claims `unverified`, declaration `imported` |

Because these causes are hand-written, the upstream kinds are also covered by alerts a real check
raised (review round 1, M10-R4; issue #32): `tests/integration/test_advice_real_lifecycle.py` runs
real checks on recorded answers and asserts their views resolve, for MDB102 (`hub_scan`), MDB301
(`dataset_retracted`), MDB302 (`paper_retracted`), MDB303 (`dataset_removed`, a disabled hub dataset
and a Zenodo 410), MDB304 (`dataset_not_findable`), MDB401 (`licence_changed` of a base model) and
MDB501 (`base_model_disabled`). If the lifecycle's cause shapes drift from the ones written here,
those tests fail.

`advice-model` has two versions: version 2 drops validators and pins the hub dataset at a new
revision. Every alert except `fixed` and `cleared` is carried to version 2.

`verdicts.json` lists the impact verdicts no view may state (FR-011, research R10) and the two rule
page sentences allowed to contain one, verbatim from `docs/rules/MDB101.md:13` and
`docs/rules/MDB102.md:13`.

# Data Model: Upstream Watch for Base Models and Training Datasets

Additions to feature 001's [data model](../001-inventory-alerts/data-model.md). Model, Model version,
Advisory, Evidence and Watch event are reused; the changes below extend them. Decisions are in
[research.md](research.md) (U1 to U13).

## Inventory entry (extended)

| Field | Rule |
| :-- | :-- |
| `kind` | Adds no new kind: `base_model` and `dataset` already exist |
| `identifier` | Base model `pkg:huggingface/owner/name@commit` (001); dataset a DOI (001) **or** `hf-dataset:owner/name@commit` for a hub-hosted dataset |
| `recorded_licence` | Base model and dataset: the licence written into the inventory at registration (U8, U11); empty if the source declared none or failed. When empty, the baseline licence is the one in the item's first stored upstream observation (below), so the inventory itself is never changed |
| `licence_form` | `spdx` (an identifier from the SPDX list), `expression`, `unrecognised` or `none` |
| `paper_dois` | Dataset only: zero or more Crossref DOIs the owner ties to the dataset (spec assumption: declared, never guessed) |

A hub dataset without a revision is a gap ("no revision"), as for 001's hub weight files; gaps are not
checked.

## DOI routing (new, cached)

| Field | Rule |
| :-- | :-- |
| `doi` | Normalised to lower case |
| `agency` | `Crossref`, `DataCite` or another agency named by `doiRA` (U1); `none` when `doiRA` answers `"status": "DOI does not exist"`; empty when the lookup failed |
| `repository` | DataCite DOIs only: `zenodo`, `figshare` or `other`, from the DataCite record's `url` |
| `repository_id` | The Zenodo record id or Figshare article id |
| `looked_up_at` | UTC timestamp |

Looked up at registration and kept; re-looked up only if empty because the lookup failed. `none` is a
definite answer, not a failed lookup: it is kept, and asked again at most once per check run in case the
DOI is registered later; a failed lookup never replaces it. doi.org's answers in a check run are stored as
evidence (source `doi-ra`) only when a watch event or alert cites them, and never open an alert alone.

## Check run (extended)

| Field | Rule |
| :-- | :-- |
| `trigger` | `scheduled` (from `check --all --scheduled`) or `on_demand` (U7) |
| `sources` | Adds `hf-hub`, `hf-takedowns`, `crossref`, `datacite`, `zenodo` and `figshare` |

## Upstream observation (new)

What one check saw for one upstream item. One row per item per source per run in which the source answered.
A failed request writes no observation (FR-018).

| Field | Rule |
| :-- | :-- |
| `run_id`, `source` | The check run and the source that answered |
| `item` | The inventory identifier (base-model purl, dataset DOI or `hf-dataset:` reference) |
| `http_status` | As received; a redirect records the status of the first response and `redirected_to` |
| `outcome` | `reachable`, `refused` (HTTP 401, 403 or 404 from the hub), `not_found` (404 from DataCite, Crossref or Figshare), `removed` (Zenodo 410), `redirected`. Only a DataCite `not_found` can open an alert (`dataset_not_findable`); a Crossref `not_found` records a watch event (`dataset_unreachable` for a dataset DOI, `paper_not_found` for a tied paper DOI), as does a Figshare one |
| `disabled` | Hub items: true or false |
| `gated` | Hub items: `false`, `auto` or `manual` |
| `head_revision` | Hub items: `sha`; datasets with a version link: the newest version's DOI or record |
| `declared_licence`, `licence_form` | As declared, and its normalised form (U8) |
| `card_hash` | Base model: SHA-256 of canonical `cardData` without licence fields and `new_version` (U7) |
| `new_version_pointer` | Base model: `cardData.new_version` |
| `updates` | Crossref: the `updated-by` entries (type, source, notice DOI, date) |
| `removal` | Zenodo: `removal_date` and `removal_reason`; hub datasets: the matched takedown-log `notice_date` and `reported_content`, with the log's URL as evidence |
| `evidence_ref` | The stored (redacted where U10 applies) response |

Changes are found by comparing an observation with the previous observation of the same item from the same
source; the first observation is the baseline and raises nothing by itself.

## Takedown notice (new, cached)

| Field | Rule |
| :-- | :-- |
| `date` | As published, labelled a **notice date**, never a removal date |
| `reported_content` | As published; matched against hub dataset paths (U5) |

The `requesting_entity` and `file` columns are dropped when the log is read and are never stored (FR-005,
U10): a notice's file name can name the requesting party. A match yields only `notice_date` and
`reported_content`; its evidence points to the log by its URL and the notice date.

## Evidence (extended)

| Field | Rule |
| :-- | :-- |
| `original_sha256` | SHA-256 of the response as received |
| `body_sha256` | SHA-256 of the stored body: equal to `original_sha256` unless redacted |
| `redacted_fields` | The fields removed before storing (U10); empty for most sources |

Feature 001 defines `body_sha256` as the hash of "the stored raw response". From this feature on, read that
as **the stored body**: the raw response itself for most sources, the redacted copy where U10 applies. The
response as received stays checkable through `original_sha256`.

## Alert (extended)

New `kind` values, their cause keys and severities (FR-019, U9):

| `kind` | Raised when | `cause_key` | Severity |
| :-- | :-- | :-- | :-- |
| `dataset_retracted` | Crossref lists a retraction, withdrawal or removal update for the dataset DOI | kind + dataset DOI | `HIGH` |
| `paper_retracted` | The same for a paper DOI tied to a dataset | kind + dataset identifier + paper DOI | `HIGH` |
| `dataset_removed` | Zenodo answers 410 with a tombstone, or the hub reports the dataset disabled | kind + dataset identifier | `HIGH` |
| `dataset_not_findable` | DataCite answers 404 for a DataCite DOI | kind + dataset DOI | `HIGH` |
| `licence_changed` | The declared licence's normalised form differs from the recorded licence (or the baseline observation's), both recognised | kind + item (one alert per item) | `HIGH` |
| `base_model_disabled` | The hub reports the base model disabled | kind + base-model purl | `MODERATE` |
| `base_model_unavailable` | The refusal-span rule is met (U7) | kind + base-model purl | `LOW` |

All carry `severity_origin: "policy"`, extending feature 001's list of kinds whose severity is `policy`.

**Licence alert identity**: a further licence change while a `licence_changed` alert is open adds that
observation as evidence and updates the alert's declared licence; it never opens a second alert for the same
item. If the declared licence's normalised form returns to the recorded one, the alert closes as `cleared`
with that observation as evidence (constitution 1.0.2, Principle III).

**Refusal-span rule** (U7): `base_model_unavailable` opens when an unbroken run of refusal observations from
scheduled check runs, with no reachable observation from any run in between, spans at least 24 hours from
its first to its latest refusal. On-demand refusals neither count towards the span nor break the run; a
reachable observation from any run ends it; failed requests write no observation and are ignored.

This feature reuses feature 001's `cleared` state (001 FR-023: the source itself no longer shows the cause)
and extends it to two new kinds (U12). State transitions added to 001's:

```text
 open (base_model_unavailable) ── base model reachable again ─────────────────▶ cleared
 open (licence_changed) ── declared licence returns to the recorded one ───────▶ cleared
 open (licence_changed) ── declared licence changes again ────────────────────▶ open, evidence added, declared licence updated
 open (dataset_retracted, paper_retracted) ── no retraction update listed any more ─▶ withdrawn
 open (any kind above) ── new version no longer depends on the item ─────────▶ fixed
 open (any kind above) ── person dismisses with a listed reason ──────────────▶ dismissed
 open (dataset_retracted, paper_retracted) ── correction or concern published ─▶ open, evidence added
 fixed / dismissed / withdrawn / cleared (any kind above) ── cause found again in the current version ──▶ a new open alert
```

The last line is 001's re-open rule, applied unchanged to the new kinds; `history` lists their closed
alerts with how (`fixed`, `dismissed`, `withdrawn` or `cleared`) and when they closed, as 001's CLI contract
already states.

A source that failed in a run cannot open, change or close any alert in that run (001 rule; FR-018).

## Watch event (extended)

New `kind` values (FR-007, FR-010, FR-013, U5 to U8):

| `kind` | Recorded when |
| :-- | :-- |
| `base_model_new_revision` | The hub's head revision differs from the pinned commit (shows both) |
| `base_model_new_version_pointer` | `cardData.new_version` appears or changes |
| `gating_changed` | `gated` changes |
| `card_changed` | `card_hash` changes |
| `base_model_refused` | A refusal that does not (yet) meet the refusal-span rule |
| `dataset_new_version` | A newer version or record is linked |
| `dataset_replaced` | DataCite lists `IsObsoletedBy` |
| `dataset_moved` | The hub redirects the dataset to another namespace |
| `dataset_unreachable` | The hub refuses a dataset, Figshare answers 404, Crossref answers 404 for a Crossref-registered dataset DOI, Zenodo answers 404 for a record asked by its DOI (U4), or no source can be asked about a dataset DOI (constitution IV: its agency is unknown, `none` or one no source reads, and the Zenodo exception of U1 does not apply); `detail.reason` names why (for example `doi.org reports the DOI does not exist`) and doi.org's answer in the run is the evidence |
| `paper_not_found` | Crossref answers 404 for a Crossref-registered paper DOI tied to a dataset, or no source can be asked about a tied paper DOI (its agency is unknown, `none` or one no source reads), with `detail.reason` as above |
| `licence_unrecognised` | A declared licence cannot be normalised |
| `licence_missing` | A source no longer declares a licence that was recorded |
| `upstream_notice` | Crossref lists a correction or expression of concern and no retraction alert is open |

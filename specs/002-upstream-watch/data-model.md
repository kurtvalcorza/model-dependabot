# Data Model: Upstream Watch for Base Models and Training Datasets

Additions to feature 001's [data model](../001-inventory-alerts/data-model.md). Model, Model version,
Advisory, Evidence and Watch event are reused; the changes below extend them. Decisions are in
[research.md](research.md) (U1 to U13).

## Inventory entry (extended)

| Field | Rule |
| :-- | :-- |
| `kind` | Adds no new kind: `base_model` and `dataset` already exist |
| `identifier` | Base model `pkg:huggingface/owner/name@commit` (001); dataset a DOI (001) **or** `hf-dataset:owner/name@commit` for a hub-hosted dataset |
| `recorded_licence` | Base model and dataset: the licence set written into the inventory at registration (U8, U11): every licence entry the source declares, normalised, one per line; empty if the source declared none or failed. When empty, the baseline licence is the one in the item's first stored upstream observation (below), so the inventory itself is never changed |
| `licence_form` | `spdx` (an identifier from the SPDX list), `expression`, `unrecognised` or `none`; for a set of several entries, `unrecognised` if any entry is, else `expression` if any entry is one, else `spdx` |
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
| `declared_licence`, `licence_form` | Every licence entry as declared, one per line in the source's order (DataCite `rightsList` entries that are not access-rights statements under `info:eu-repo/semantics/`; each entry of a hub `cardData.license` list; Zenodo and Figshare as they declare), and the set's form (U8) |
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
| `paper_retracted` | The same for a paper DOI tied to a dataset | kind + dataset DOI + paper DOI; kind + `hf-dataset:owner/name`, without the revision, + paper DOI (hub) | `HIGH` |
| `dataset_removed` | Zenodo answers 410 with a tombstone, or the hub reports the dataset disabled | kind + dataset DOI (Zenodo); kind + `hf-dataset:owner/name`, without the revision (hub) | `HIGH` |
| `dataset_not_findable` | DataCite answers 404 for a DataCite DOI | kind + dataset DOI | `HIGH` |
| `licence_changed` | The normalised set of declared licence entries, order ignored, differs from the recorded set (or the baseline observation's), both recognised; adding or reordering an entry that leaves the set equal raises nothing | kind + item (one alert per item): the dataset DOI, or for a base model or hub dataset its repository without the revision | `HIGH` |
| `base_model_disabled` | The hub reports the base model disabled | kind + base-model purl without the version (`pkg:huggingface/owner/name`) | `MODERATE` |
| `base_model_unavailable` | The refusal-span rule is met (U7) | kind + base-model purl without the version | `LOW` |

All carry `severity_origin: "policy"`, extending feature 001's list of kinds whose severity is `policy`.

**Licence alert identity**: a further licence change while a `licence_changed` alert is open adds that
observation as evidence and updates the alert's declared licence; it never opens a second alert for the same
item. The alert's cause lists every source that reports the change (`sources`). A listed source drops out
only when it answers in a check with the recorded licence set again; the alert closes as `cleared`, with
those observations as evidence, once no listed source is left. A listed source that failed or was not asked
in a check (for example under `--source`) keeps its report, whatever the other sources say (FR-018,
constitution 1.0.2, Principle III). An alert written before causes listed `sources` is read as listing its
one `source`.

### Identity and clearance

Each alert kind is about one thing, at one scope. That scope decides what registering a new version
compares (001 FR-014), and the source that can clear an alert is the one that reported it. A gap in a new
version's inventory (an entry that names the same package, file, dataset or repository but lacks its pin)
never counts as removal: the alert stays open, neither fixed nor carried forward (001 FR-016).

| `kind` | Identity scope | Closes as `fixed` when a new version | Closes as `cleared` when | Closes as `withdrawn` when |
| :-- | :-- | :-- | :-- | :-- |
| `package_advisory` | advisory and package, at the pinned version | no longer pins an affected version of the package | OSV and the local evaluation agree the pinned version is unaffected | OSV marks the advisory withdrawn |
| `weight_file_scan` | file SHA-256 | no longer has a file with that hash | never: a local scan finding stays until the file goes | never |
| `hub_scan` | file SHA-256 | no longer has a file with that hash | the hub gives an explicit `safe` verdict for that hash | never |
| `format_policy` | file SHA-256 | no longer has the file, or has a code-free file beside it | the owner's format policy is no longer `strict` | never |
| `dataset_retracted` | dataset DOI | no longer pins the DOI | a successful, well-formed Crossref answer lists no retraction, withdrawal or removal | never: no source read here publishes an explicit withdrawal of a notice |
| `paper_retracted` | dataset DOI and paper DOI; for a hub dataset, its repository (`owner/name`, any revision) and paper DOI | no longer pins the dataset DOI or names the hub repository, or no longer ties the paper to it | as `dataset_retracted`, for the paper DOI | never |
| `dataset_removed` (Zenodo) | dataset DOI | no longer pins the DOI | never | never |
| `dataset_removed` (hub) | hub repository (`owner/name`), any revision | no longer names the repository | never | never |
| `dataset_not_findable` | dataset DOI | no longer pins the DOI | never | never |
| `licence_changed` | item (dataset DOI; for a base model or hub dataset, its repository, any revision) and the sources reporting the change | no longer pins the DOI or names the repository | every source that reported the change answers with the recorded licence set again | never |
| `base_model_disabled` | hub repository (`owner/name`), any revision | no longer names the repository | the hub reports `disabled: false` | never |
| `base_model_unavailable` | hub repository (`owner/name`), any revision | no longer names the repository | any hub answer that is not a refusal | never |

For a repository-wide kind, a new version that pins another revision of the same repository carries the
alert forward to that revision; only depending on a different repository, or the hub's own clearance,
closes it. A licence read from a base model's or hub dataset's info and a paper tied to a hub dataset are
observations of the repository, not of one revision: their alerts follow the repository in the same way,
and the baseline licence (when the inventory records none) is the first licence observed for any revision
of the repository, so a re-pin does not start a new baseline. A paper alert is carried forward only while
the new version still ties that paper to the dataset. Revision- and hash-scoped kinds keep exact-identifier comparison. A person can dismiss any open
alert with a listed reason (`dismissed`). An open repository-wide alert stored before this rule, with the
revision in its cause key, is rekeyed by repository when the database is opened; this covers
`base_model_disabled`, `base_model_unavailable`, a hub dataset's `dataset_removed` and `paper_retracted`,
and a base model's or hub dataset's `licence_changed`.

**Answer identity** (hub): a hub answer is about the repository it names, not the one asked for.
Model and dataset info, security status and revision answers name their repository in `id` (model
answers also in `modelId`), spelt as the hub spells it (`tests/fixtures/hf/`, `tests/fixtures/hf_upstream/`).
When a 200 answer names another repository, compared ignoring case as the hub does, it is unreadable:
model or dataset info fails the `hf-hub` source for the run (no observation, so nothing opens or
closes), a security status is `unrecognised` (a watch event) and a revision is a gap. An answer that
names no repository, such as a tree listing, is read as before. A renamed repository still surfaces as
a move, because model and dataset info never follow redirects (U5); the rule guards against a 200
answer that a redirect elsewhere or a misrouted response delivers for the wrong repository.

**Refusal-span rule** (U7): `base_model_unavailable` opens when an unbroken run of refusal observations from
scheduled check runs, with no reachable observation from any run in between, spans at least 24 hours from
its first to its latest refusal. On-demand refusals neither count towards the span nor break the run; a
reachable observation from any run ends it; failed requests write no observation and are ignored. Any hub
answer other than a refusal ends a refusal run and clears `base_model_unavailable`, including a redirect
or a 200 with `disabled: true`; a disabled model is then reported by `base_model_disabled`, which closes
as `cleared` with that observation as evidence when a later hub answer reports `disabled: false`
(constitution 1.0.2).

This feature reuses feature 001's `cleared` state (001 FR-023: the source itself no longer shows the cause)
and extends it to two new kinds (U12). State transitions added to 001's:

```text
 open (base_model_unavailable) ── base model reachable again ─────────────────▶ cleared
 open (base_model_disabled) ── the hub reports disabled: false ─────────────────▶ cleared
 open (licence_changed) ── every reporting source returns to the recorded licence ─▶ cleared
 open (licence_changed) ── declared licence changes again ────────────────────▶ open, evidence added, declared licence updated
 open (dataset_retracted, paper_retracted) ── well-formed answer lists no retraction ─▶ cleared
 open (base_model_*, hub dataset_removed, hub licence_changed, hub paper_retracted) ── new version pins another revision of the repository ─▶ open, carried forward
 open (any kind above) ── new version names the item only in a gap ────────▶ open, unchanged
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
| `base_model_unrecognised` | A hub answer of a shape this feature does not read (for example a `disabled` value that is not `true` or `false`): recorded, never an alert (U7 fail-safe) |
| `dataset_new_version` | A newer version or record is linked |
| `dataset_replaced` | DataCite lists `IsObsoletedBy` |
| `dataset_moved` | The hub redirects the dataset to another namespace |
| `dataset_unreachable` | The hub refuses a dataset, Figshare answers 404, Crossref answers 404 for a Crossref-registered dataset DOI, Zenodo answers 404 for a record asked by its DOI (U4), or no source can be asked about a dataset DOI (constitution IV: its agency is unknown, `none` or one no source reads, and the Zenodo exception of U1 does not apply); `detail.reason` names why (for example `doi.org reports the DOI does not exist`) and doi.org's answer in the run is the evidence |
| `paper_not_found` | Crossref answers 404 for a Crossref-registered paper DOI tied to a dataset, or no source can be asked about a tied paper DOI (its agency is unknown, `none`, DataCite, whose DOIs no retraction source reads, or one no source reads), with `detail.reason` as above (for a DataCite paper DOI `registered with DataCite, which no retraction source reads`, with doi.org's answer in the run as the evidence) |
| `licence_unrecognised` | A declared licence entry cannot be normalised, so the declared set differs from the recorded one only in an unrecognised entry |
| `licence_missing` | A source no longer declares a licence that was recorded |
| `upstream_notice` | Crossref lists a correction or expression of concern and no retraction alert is open |

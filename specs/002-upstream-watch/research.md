# Research: Upstream Watch for Base Models and Training Datasets

Phase 0 for [plan.md](plan.md). Builds on feature 001's decisions ([001 research](../001-inventory-alerts/research.md)
R1 to R10), which are reused unchanged unless a decision below extends them. Sources: `research/landscape.md`
sections 3, 4 and 9, plus live anonymous requests made on 2026-10-24 with a generic User-Agent (marked
**live-tested** below).

## U1. Which source answers for which dataset: route by DOI registration agency, then by repository

**Decision**: At registration, look up each DOI's registration agency once with
`GET https://doi.org/doiRA/{doi}` and cache it (an agency never changes for a DOI). Crossref DOIs (papers, and
datasets registered there) go to Crossref for retractions. DataCite DOIs go to DataCite for findability,
licence and version links; the DataCite record's `url` then routes the dataset to its repository: `zenodo.org`
to Zenodo, `figshare.com` or a `*.figshare.com` portal to Figshare. Hub datasets (`hf:datasets/owner/name`)
go to the Hugging Face Hub.

**Rationale**: **Live-tested**: `doiRA` returned `DataCite` for `10.5281/zenodo.3242074` and `Crossref` for
`10.1177/1758835919874651`. Routing by agency avoids asking DataCite about Crossref DOIs, where a 404 would
be meaningless and would otherwise look like FR-006's "no longer findable".

**Alternatives considered**: guessing from the DOI prefix (`10.5281` for Zenodo, `10.6084` for Figshare):
breaks for Figshare institutional portals and other repositories; asking every source about every DOI:
more requests and false "not found" signals.

## U2. Retractions: the Crossref REST API, which already carries Retraction Watch

**Decision**: For each Crossref DOI in scope (a dataset DOI registered at Crossref, or a paper DOI the owner
ties to a dataset), read `GET https://api.crossref.org/works/{doi}` and its `updated-by[]` list. An entry of
type `retraction`, `withdrawal` or `removal` raises an alert (FR-004); `expression_of_concern` and
`correction` add evidence to an open alert or, with no alert open, record a watch event. Requests run one at
a time at no more than one per second.

**Rationale**: **Live-tested**: the retracted article `10.1177/1758835919874651` returns `updated-by` with two
retraction entries for the notice `10.1177/17588359211061903`, one with `source: "retraction-watch"` (and its
`record-id`) and one with `source: "publisher"`; the reverse query `filter=updates:{doi}` finds the same
notice. So one per-DOI request covers both publisher notices and the Retraction Watch database. The anonymous
public pool answered with `x-rate-limit-limit: 1`, `x-rate-limit-interval: 1s` and
`x-concurrency-limit: 1`; the faster pool needs a contact email, which the privacy constraint rules out.

**Alternatives considered**: cloning the Retraction Watch CSV from GitLab daily (a second copy of data the
API already serves, and a growing clone); the `filter=updates:` search (one more request per DOI for the
same answer).

## U3. Findability, licence and version links for DataCite DOIs: DataCite REST

**Decision**: `GET https://api.datacite.org/dois/{doi}` for each DataCite DOI. A 404 while DataCite answers
other requests normally raises the "no longer findable" alert (FR-006). `rightsList[]` gives the declared
licence (FR-008, FR-009). `relatedIdentifiers[]` with `IsPreviousVersionOf` or `HasVersion` pointing to a
newer record, or `IsObsoletedBy`, records a watch event (FR-007).

**Rationale**: DataCite documents moving a DOI from `findable` to `registered` as the route for retracted
content, and registered DOIs disappear from the public API (landscape §4). Figshare's unpublishing also sets
the DOI to `registered` (landscape §9), so this check is the one confirmed path to an alert for an unpublished
Figshare dataset.

## U4. Zenodo removals: the records API tombstone, not the monthly dump

**Decision**: For each Zenodo dataset, `GET https://zenodo.org/api/records/{id}` at every check. HTTP 410 with a
`tombstone` raises the removal alert (FR-005) with `tombstone.removal_date` and `tombstone.removal_reason.id`
as evidence. HTTP 200 gives the licence (`metadata.license.id`) and, through `links.latest`, a newer version
(watch event, FR-007). Before the response is stored, `tombstone.removed_by`, `tombstone.note` and
`tombstone.citation_text` are removed (U10).

**Rationale**: **Live-tested**: a record listed as deleted returned `410` with
`{"status":410,"message":"Record deleted","tombstone":{"removal_date":…,"removal_reason":{"id":…},…}}`.
This is a per-record answer available at every check, so a removal shows within one check interval of
the removal itself (SC-006), not within a month. The exporter (`GET /api/exporter`, **live-tested**) lists a
Zenodo-wide `records-deleted.csv.gz` of 27,423,086 bytes, last updated 2026-10-03, with columns
`record_id,doi,parent_id,parent_doi,removal_note,removal_reason,removal_date,citation_text`. Guests are
allowed 60 requests a minute and 2,000 an hour (landscape §4).

**Alternatives considered**: downloading the deleted-records dump on each change (27 MB, monthly at best,
and its `citation_text` names people, so every copy would need redacting); OAI-PMH deleted headers (not
needed once the record API answers).

## U5. Hugging Face removals, reason and moves: dataset info, takedown log, redirects

**Decision**: For each hub dataset, `GET /api/datasets/{owner}/{name}?expand[]=disabled&expand[]=gated&expand[]=private&expand[]=cardData&expand[]=sha`.
`disabled: true` raises the dataset removal alert (FR-005). Once per check run, if any hub dataset is in
scope, the public takedown log `huggingface-legal/takedown-notices` `index.csv` is fetched (cached by ETag)
and searched for the dataset's path; a match adds the entry's `date` (labelled `notice_date`) and its `file`
to the evidence. A 307 redirect to another namespace (such as `defunct-datasets/`) records a `dataset_moved`
watch event, never an alert. HTTP 401, 403 or 404 records a `dataset_unreachable` watch event.

**Rationale**: **Live-tested** (landscape §9, re-checked 2026-10-24): `yavon/muxue` returns 200 with
`disabled: true, private: false`; a nonexistent dataset returns 401; `the_pile_books3` returns 307 to
`defunct-datasets/the_pile_books3`, which returns `disabled: false`; `index.csv` has the header
`date,requesting_entity,reported_content,file` and 67 data rows from 2022-06-28 to 2026-09-04. The log
records notices received, not confirmed disablements, so a log entry alone never raises an alert; it only
enriches one already raised by `disabled: true`.

**Consequence for 001's fetcher**: urllib follows redirects silently. The `Fetcher` interface gains a
`redirected_from` field so a move is visible; this is an addition, not a change to 001's behaviour.

**To confirm when recording fixtures**: the exact form of `reported_content` (full URL or path), so the
match rule is written against real rows. Rows reading `Multiple` never match.

## U6. Figshare: watch events only

**Decision**: For a Figshare dataset, take the article id from the DataCite record's `url` and read
`GET https://api.figshare.com/v2/articles/{id}`, at most one request per second. HTTP 200 gives the licence
(`license.name`, normalised through U8). HTTP 404 records a `dataset_unreachable` watch event. No Figshare
response raises a removal alert. An unpublished item can still raise FR-006's "no longer findable" alert
through DataCite (U3).

**Rationale**: landscape §9: Figshare's API has no removal field, and its 404 is shared by removed, private
and nonexistent items (documented). The clarified FR-005 keeps Figshare to watch events.

## U7. Base model: hub model info and the two-refusal rule

**Decision**: `GET /api/models/{owner}/{name}?expand[]=disabled&expand[]=gated&expand[]=private&expand[]=cardData&expand[]=sha&expand[]=lastModified`
at every check.

- `disabled: true` raises the base-model-disabled alert at once (FR-011).
- HTTP 401, 403 or 404 is a **refusal** observation. A timeout, connection error or HTTP 5xx is a source
  failure, not an observation (FR-012, FR-018).
- The "no longer publicly available" alert opens when the two most recent refusal observations from
  **scheduled** check runs are at least 24 hours apart and no reachable observation, from any run, lies
  between them. A refusal that does not meet this records a `base_model_refused` watch event.
- `sha` differing from the pinned commit records `base_model_new_revision` (pinned and newest revision);
  `cardData.new_version` records `base_model_new_version_pointer`; a change in `gated` records
  `gating_changed`; a change in the hash of `cardData` with the licence fields (`license`, `license_name`,
  `license_link`) and `new_version` removed records `card_changed` (FR-013).

**Rationale**: landscape §3 live-tested these fields and the 401 answer for a missing model. The 24-hour
two-observation rule is the owner's guard against transient refusals (spec clarification).

**Scheduled versus on-demand**: FR-012 counts scheduled checks only, so a check run records its `trigger`.
`check --all --scheduled` is what the host scheduler runs; any other `check` is `on_demand`
([CLI contract](contracts/cli.md)).

**To confirm when recording fixtures**: that a disabled **model** answers like a disabled dataset (200 with
`disabled: true`). If it does not, the adapter fails safe to a watch event and the fixture records what the
hub returned.

## U8. Licence normalisation: the SPDX licence list, vendored, plus a small documented alias table

**Decision**: Vendor the SPDX licence list JSON (`licenses.json`, version 3.29.0, released 2026-09-16, 740
licences; **live-tested**) with its SHA-256. A declared licence is normalised in this order: exact SPDX
identifier ignoring case; SPDX full name ignoring case; an entry in `licences/aliases.toml`, a short in-repo
table of repository-specific spellings (for example Figshare's `CC BY 4.0` to `CC-BY-4.0`), each with the
source that uses it. Licence expressions (`MIT OR Apache-2.0`) are normalised term by term with operators
upper-cased. Anything else is **unrecognised**: kept as declared, compared as text and reported as a watch
event (FR-010), never an alert.

**Recorded licence**: the licence written into the inventory at registration (CycloneDX `licenses` on the
base-model or dataset component, U11). If the source failed at registration, or the inventory was imported
without licences, the first successful observation becomes the baseline and is labelled as such; it never
raises an alert by itself.

**Rationale**: the owner chose the SPDX list (clarification Q4); constitution II prefers the open standard.
Hub licence tags are lower-case SPDX identifiers where one exists (`mit`, `apache-2.0`, `cc-by-4.0`) and
hub-specific names otherwise (`llama3.1`, `openrail`, `other`), so case-insensitive identifier matching
covers the common case and hub-specific names fall to the watch-event path.

**Alternatives considered**: a licence-detection library (heavier, and text-based detection is inference,
which constitution I rules out for alerts); hand-maintained aliases only (drifts from the standard).

## U9. Severity: fixed by alert kind

**Decision**: FR-019's bands map onto feature 001's severity values: retraction and removal `HIGH`, licence
change `HIGH`, base model disabled `MODERATE`, base model no longer publicly available `LOW`, all with
`severity_origin: "policy"`.

**Rationale**: one severity scale across features, so alerts sort together (001 FR-018).

## U10. Personal data in source responses: store redacted evidence

**Decision**: Feature 001 stores every raw response, content-addressed, as evidence. For responses that carry
personal data, the stored body is a redacted copy with the listed fields removed; the evidence record keeps the
SHA-256 of the original body, the SHA-256 of the stored body and the list of fields removed. Fields removed:

- takedown log `index.csv`: the `requesting_entity` column;
- Zenodo tombstone: `removed_by`, `note` and `citation_text`;
- Crossref and DataCite records: `author`, `creators`, `contributors` and `editor`;
- Hugging Face model and dataset info: nothing (`author` is the repository namespace, already part of the
  identifier).

**Rationale**: FR-003 and FR-005 (the requesting party of a takedown is never stored) and the constitution's
privacy constraint. Recording the original hash keeps the evidence checkable against the source (constitution
I) without keeping the personal fields.

## U11. Inventory additions: licences, paper ties and hub datasets in standard CycloneDX fields

**Decision**: Extend feature 001's inventory profile ([contract](contracts/inventory-profile.md)):

- recorded licences in the standard `licenses` array of the base-model and dataset components (`license.id`
  for an SPDX identifier, `license.name` for an unrecognised one, `expression` for an expression);
- a paper DOI the owner ties to a dataset as an `externalReferences` entry of type `citation` with URL
  `https://doi.org/<doi>`;
- a hub-hosted dataset as a `data` component with `bom-ref: "hf-dataset:<owner>/<name>@<commit>"` and an
  `externalReferences` entry of type `distribution` pointing to the hub page.

**Rationale**: **Live-tested**: the CycloneDX 1.7.2 schema's `externalReference.type` enum (47 values)
includes `citation`, and `component` has `licenses` and `data`. So no `model-dependabot:` property is needed
for this feature (constitution II).

## U12. Closing alerts when the upstream condition ends

**Decision**: Add one alert state to feature 001's lifecycle, `cleared`: a "no longer publicly available"
alert closes as `cleared` when the base model is reachable again (FR-016), with that observation as
evidence. A retraction alert closes as `withdrawn` (001's existing state) when a later successful Crossref
response no longer lists any retraction, withdrawal or removal update for the DOI, with that response as
evidence. Every other alert in this feature stays open until a newer model version no longer depends on the
affected item (`fixed`) or a person dismisses it.

**Rationale**: FR-015 and FR-016. Constitution 1.0.1 (Principle III) allows automatic closing when the source
withdraws or clears the cause, as feature 001 already does for withdrawn advisories.

## U13. Request budget per check

**Decision**: Per model version: one hub request for the base model; per dataset one to three requests
(Crossref or DataCite, the repository and Crossref for each tied paper); one `index.csv` per check run,
cached by ETag; agency lookups only at registration. Requests to one source run sequentially within its
limit: Crossref one a second, Figshare one a second, Zenodo 60 a minute, Hugging Face 500 API requests per
five minutes per IP (landscape §9).

**Rationale**: constitution ("polite to sources"); keeps a model with ten datasets within 001's 60-second
check budget.

## Deferred (not in feature 002)

- Removal alerts for Figshare (needs a tested unpublished item; landscape §9).
- Base models and datasets on hubs other than Hugging Face.
- Hub webhooks (need a public endpoint; spec assumption).
- Using the takedown log for base models.

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

**Exception (2026-10-24, from a live end-to-end run)**: a deleted Zenodo record's DOI
(`10.5281/zenodo.12584226`, removed as `duplicate`) is not known to doi.org: **live-tested**, `doiRA`
answered `[{"DOI": "10.5281/zenodo.12584226", "status": "DOI does not exist"}]` (no `RA`), DataCite answered
404 and Zenodo answered 410 with a tombstone. Routing by agency alone skipped it silently, which
constitution IV does not allow. So a DOI of the exact form `10.5281/zenodo.<digits>` whose agency is unknown
(failed lookup, or `none` for "DOI does not exist") and that DataCite has not routed, or whose agency is
DataCite and whose DataCite record is 404, is still asked at Zenodo with that record id (U4). Such a DOI is
also asked at DataCite, but a DataCite 404 then is supporting evidence only (FR-006 stays limited to DOIs
DataCite registered). The exception is narrow because the prefix rule fails only for repositories other
than Zenodo: `10.5281/zenodo.<digits>` names a Zenodo record id by construction, and only Zenodo's own
answer decides. Any other DOI that no source can be asked about records a watch event naming why
(data-model.md), never an alert.

## U2. Retractions: the Crossref REST API, which already carries Retraction Watch

**Decision**: For each Crossref DOI in scope (a dataset DOI registered at Crossref, or a paper DOI the owner
ties to a dataset), read `GET https://api.crossref.org/works/{doi}` and its `updated-by[]` list. An entry of
type `retraction`, `withdrawal` or `removal` raises an alert (FR-004); `expression_of_concern` and
`correction` add evidence to an open alert or, with no alert open, record a watch event. A 404 for a
Crossref-registered DOI records a watch event, never an alert: `dataset_unreachable` for a dataset DOI,
`paper_not_found` for a tied paper DOI (Crossref has no findability state, so a 404 confirms nothing about
removal). Requests run one at a time at no more than one per second.

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
other requests normally raises the "no longer findable" alert (FR-006, which covers DataCite DOIs only;
Crossref DOIs are covered by FR-004 through U2, and a Crossref 404 is a watch event). `rightsList[]` gives the declared
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
`tombstone.citation_text` are removed, and so are the record's `metadata.creators`,
`metadata.contributors` and `owners` (U10).

**Rationale**: **Live-tested**: a record listed as deleted returned `410` with
`{"status":410,"message":"Record deleted","tombstone":{"removal_date":…,"removal_reason":{"id":…},…}}`.
This is a per-record answer available at every check, so a removal shows within one check interval of
the removal itself (SC-006), not within a month. The exporter (`GET /api/exporter`, **live-tested**) lists a
Zenodo-wide `records-deleted.csv.gz` of 27,423,086 bytes, last updated 2026-10-03, with columns
`record_id,doi,parent_id,parent_doi,removal_note,removal_reason,removal_date,citation_text`. Guests are
allowed 60 requests a minute and 2,000 an hour (landscape §4).

**Asked by DOI (U1 exception)**: a `10.5281/zenodo.<digits>` DOI that doi.org does not know, or whose
DataCite record is 404, is asked here with that record id. **Live-tested** with `10.5281/zenodo.12584226`:
410 with a `duplicate` tombstone raises `dataset_removed` (HIGH) with the Zenodo response as evidence and
doi.org's and DataCite's answers as supporting evidence; 200 is a normal observation; 404 is a
`dataset_unreachable` watch event.

**Alternatives considered**: downloading the deleted-records dump on each change (27 MB, monthly at best,
and its `citation_text` names people, so every copy would need redacting); OAI-PMH deleted headers (not
needed once the record API answers).

## U5. Hugging Face removals, reason and moves: dataset info, takedown log, redirects

**Decision**: For each hub dataset, `GET /api/datasets/{owner}/{name}?expand[]=disabled&expand[]=gated&expand[]=private&expand[]=cardData&expand[]=sha`.
`disabled: true` raises the dataset removal alert (FR-005). Once per check run, if any hub dataset is in
scope, the public takedown log `huggingface-legal/takedown-notices` `index.csv` is fetched (cached by ETag)
and searched for the dataset's path; a match adds the entry's `date` (labelled `notice_date`) and its `reported_content`
to the evidence, which points to the log by its URL and the notice date. A 307 redirect to another namespace (such as `defunct-datasets/`) records a `dataset_moved`
watch event, never an alert. HTTP 401, 403 or 404 records a `dataset_unreachable` watch event.

**Rationale**: **Live-tested** (landscape §9, re-checked 2026-10-24): `yavon/muxue` returns 200 with
`disabled: true, private: false`; a nonexistent dataset returns 401; `the_pile_books3` returns 307 to
`defunct-datasets/the_pile_books3`, which returns `disabled: false`; `index.csv` has the header
`date,requesting_entity,reported_content,file` and 67 data rows from 2022-06-28 to 2026-09-04. The log
records notices received, not confirmed disablements, so a log entry alone never raises an alert; it only
enriches one already raised by `disabled: true`.

**Consequence for 001's fetcher**: urllib follows redirects silently. The fetcher now follows them itself (at
most five hops) and marks the final answer with `redirected_from`, so 001's adapters behave as before; a call
that must see a move (hub dataset and model info) passes `follow_redirects=False` and gets the 3xx with
`redirected_from` and `redirected_to`. This is an addition, not a change to 001's behaviour.

**Confirmed when recording fixtures** (2026-10-24, `tests/fixtures/hf_takedowns/`, 67 data rows from
2022-06-28 to 2026-09-04): `reported_content` is a bare repository path `owner/name` (51 rows, for example
`pytorch/silero_tts`), with no host, no scheme and no `datasets/` or `spaces/` prefix, so a row cannot say
whether it names a model, a dataset or a Space. The other 16 rows read `Multiple` in three spellings
(`Multiple` 12, `multiple` 3, ` Multiple` with a leading space 1). The match rule is therefore: the row's
value, with surrounding spaces removed, equals the hub dataset's `owner/name`; a value that reads
`multiple` ignoring case and surrounding spaces never matches. The `/resolve/main/index.csv` URL answers
307 to `/api/resolve-cache/datasets/huggingface-legal/takedown-notices/<commit>/index.csv?…`; the redaction
rule matches the log's repository anywhere in a hub path, so the redirect target is redacted too. The `file`
column (notice file names such as `2024/2024-04-08-<name>.pdf`) often embeds the requesting party's name, so
U10 removes it with `requesting_entity` (owner ruling, 2026-10-24).

## U6. Figshare: watch events only

**Decision**: For a Figshare dataset, take the article id from the DataCite record's `url` and read
`GET https://api.figshare.com/v2/articles/{id}`, at most one request per second. HTTP 200 gives the licence
(`license.name`, normalised through U8). HTTP 404 records a `dataset_unreachable` watch event. No Figshare
response raises a removal alert. An unpublished item can still raise FR-006's "no longer findable" alert
through DataCite (U3).

**Rationale**: landscape §9: Figshare's API has no removal field, and its 404 is shared by removed, private
and nonexistent items (documented). The clarified FR-005 keeps Figshare to watch events.

## U7. Base model: hub model info and the refusal-span rule

**Decision**: `GET /api/models/{owner}/{name}?expand[]=disabled&expand[]=gated&expand[]=private&expand[]=cardData&expand[]=sha&expand[]=lastModified`
at every check.

- `disabled: true` raises the base-model-disabled alert at once (FR-011).
- HTTP 401, 403 or 404 is a **refusal** observation. A timeout, connection error or HTTP 5xx is a source
  failure, not an observation (FR-012, FR-018).
- The "no longer publicly available" alert opens when an **unbroken run of refusal observations from
  scheduled check runs**, with no reachable observation from any run in between, spans at least 24 hours
  from its first to its latest refusal. On-demand refusals do not count towards the span and do not break
  the run; a reachable observation from any run ends the run; failed requests are ignored. Because the span
  is measured from the first refusal of the run, daily runs that land a few seconds under 24 hours apart
  still open the alert on the next scheduled run. A refusal that does not meet this records a
  `base_model_refused` watch event.
- `sha` differing from the pinned commit records `base_model_new_revision` (pinned and newest revision);
  `cardData.new_version` records `base_model_new_version_pointer`; a change in `gated` records
  `gating_changed`; a change in the hash of `cardData` with the licence fields (`license`, `license_name`,
  `license_link`) and `new_version` removed records `card_changed` (FR-013).

**Rationale**: landscape §3 live-tested these fields and the 401 answer for a missing model. The 24-hour
refusal-span rule is the owner's guard against transient refusals (spec clarification). Measuring the
span over the whole unbroken run, not over the two most recent refusals, keeps SC-003 deterministic: with a
daily schedule whose start times drift by seconds, a pairwise rule could stay just under 24 hours on every
pair and never open the alert.

**Scheduled versus on-demand**: FR-012 counts scheduled checks only, so a check run records its `trigger`.
`check --all --scheduled` is what the host scheduler runs; any other `check` is `on_demand`
([CLI contract](contracts/cli.md)).

**Confirmed when recording fixtures** (2026-10-24, `tests/fixtures/hf_upstream/model-disabled`): a
disabled **model** answers like a disabled dataset. `sd-concepts-library/dyoudim-style`, found as the
first of the takedown log's model-like `owner/name` paths whose model info has `disabled: true`, returned
HTTP 200 with `{"disabled": true, "gated": false, "private": false, "cardData": {"license": "mit"},
"sha": …, "lastModified": …}` under the `expand[]` request above, the same shape as `yavon/muxue`. The
fail-safe to a watch event (T042) stays for any other shape.

## U8. Licence normalisation: the SPDX licence list, vendored, plus a small documented alias table

**Decision**: Vendor the SPDX licence list JSON (`licenses.json`, version 3.29.0, released 2026-09-16, 740
licences; **live-tested**) with its SHA-256. A declared licence is normalised in this order: exact SPDX
identifier ignoring case; SPDX full name ignoring case; an entry in `licences/aliases.toml`, a short in-repo
table of repository-specific spellings (for example Figshare's `CC BY 4.0` to `CC-BY-4.0`), each with the
source that uses it. Licence expressions (`MIT OR Apache-2.0`) are normalised term by term with operators
upper-cased; the term after `WITH` is matched, ignoring case, against the vendored SPDX exceptions list
(`exceptions.json` of the same tag, 86 exceptions, with its SHA-256), so `<licence> WITH <exception>` can
alert on a real change, and an unknown exception leaves the expression unrecognised (owner decision of
2026-10-24).

**Several licences** (owner decision of 2026-10-24): every licence entry a source declares is recorded
(DataCite `rightsList` entries that are not access-rights statements under `info:eu-repo/semantics/`;
each entry of a hub `cardData.license` list; Zenodo and Figshare as they declare), and licences are
compared as the **normalised set** of their entries, order ignored. `licence_changed` opens only when the
set changes; adding or reordering an entry that leaves the set equal raises nothing. The CycloneDX
`licenses` array holds the full recorded set, one choice per entry. Anything else is **unrecognised**: kept as declared, compared as text and reported as a watch
event (FR-010), never an alert.

**Recorded licence**: the licence written into the inventory at registration (CycloneDX `licenses` on the
base-model or dataset component, U11). If the source failed at registration, or the inventory was imported
without licences, the first successful observation becomes the baseline and is labelled as such; it never
raises an alert by itself. That stored observation is the baseline record; the inventory is never changed.

**Licence alert identity**: `licence_changed` is keyed on kind + item, so one item has at most one open
licence alert. A further change while it is open adds evidence and updates the declared licence on the same
alert; a return of the declared licence to the recorded one closes it as `cleared` with that observation as
evidence (constitution 1.0.2, Principle III; U12).

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

- takedown log `index.csv`: the `requesting_entity` and `file` columns (a notice's file name can name the
  requesting party), leaving `date` and `reported_content`;
- Zenodo: the tombstone's `removed_by`, `note` and `citation_text`, the record's `metadata.creators` and
  `metadata.contributors` and its `owners`;
- Figshare articles: `authors` and `citation`;
- Crossref and DataCite records: `author`, `creators`, `contributors` and `editor`, wherever they appear (so a
  Crossref `reference[].author` goes too); Crossref also loses each reference's free-text `unstructured`,
  keeping the rest of the reference;
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

**Decision**: Reuse feature 001's `cleared` state (001 FR-023 and data model), adding no new state, and
extend it to two kinds: a "no longer publicly available" alert closes as `cleared` when the base model is
reachable again (FR-016), and a `licence_changed` alert closes as `cleared` when the declared licence returns
to the recorded one (U8) at every source that reported the change, each with that observation as evidence.
A retraction alert closes as `cleared` when a later successful, well-formed Crossref response no longer
lists any retraction, withdrawal or removal update for the DOI, with that response as evidence. It does not
close as `withdrawn`: absence from the feed is the source's current state, not a published withdrawal of
the notice, and Crossref does not describe disappearance as one. `withdrawn` is kept for explicit withdrawal
evidence (an OSV record marked withdrawn). A Crossref answer that cannot be read as the work asked for (the
message not an object, `updated-by` not a list, an entry without a type, or a record for another DOI) is a
failed read, never an answer with no updates (001 FR-016). Every other alert in this feature stays open
until a newer model version no longer depends on the affected item (`fixed`) or a person dismisses it. 001's
re-open rule (a closed alert whose cause is found again in the current version gives a new open alert)
applies to the new kinds unchanged.

**Rationale**: FR-015 and FR-016. Constitution 1.0.2 (Principle III) allows automatic closing when the source
withdraws or clears the cause, as feature 001 already does for withdrawn and cleared advisories. Amended
2026-10-25 after review: retraction closure moved from `withdrawn` to `cleared`, and malformed Crossref
answers made failed reads (data-model.md, Identity and clearance).

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

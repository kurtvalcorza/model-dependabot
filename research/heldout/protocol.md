# Held-out evaluation corpus — protocol (v0.1, pre-registered)

Written 2026-10-25 (UTC) **before any candidate search was run**. Changes after collection starts are
appended under "Amendments" with a timestamp and reason; nothing above that line is edited afterwards.

Status: **candidate list, not frozen.** The owner approves (or strikes) items before the corpus is frozen.

## 1. Purpose and unit of analysis

Estimate model-dependabot's field sensitivity, precision and false-closure frequency on real upstream
incidents that were *not* used to build its fixtures. The unit is one **(item, alert kind)** pair: an
upstream identifier the tool would watch (purl@version, HF repo@commit, file sha256, DOI) and the alert kind
the label is about. One item may appear under two kinds (e.g. a Zenodo DOI under `dataset_removed` and
`licence_changed`); it is then two units.

## 2. Exclusions that apply to every kind

- E1. Any identifier already in `model-dependabot/tests/fixtures/**` (development fixtures): OSV
  GHSA-24rc-8hj2-v98c, GHSA-cp9v-662q-vvx9, PYSEC-2019-64, packages pillow 12.3.0 / 13.0.0 and
  validators 0.12.2 as positives; HF `mcpotato/42-eicar-street`, `openai-community/gpt2`,
  `meta-llama/Llama-3.1-8B`, `sd-concepts-library/dyoudim-style`, `defunct-datasets/the_pile_books3`,
  `the_pile_books3`, `yavon/muxue`; Crossref DOIs 10.1016/j.lungcan.2003.10.006, 10.1038/nature14539,
  10.1088/1361-6595/aaebdb, 10.1177/1758835919874651; DataCite/Zenodo 10.1594/pangaea.958394,
  zenodo 12584226, 3242074, 8176941; Figshare 1, 21108811, 34763127, m9.figshare.29500136.
- E2. Items whose state is visibly in flux on the retrieval day (e.g. an HF scan with `scansDone: false`,
  an OSV record modified in the last 7 days). Stable state is preferred because the label must still hold
  when the tool is run later.
- E3. Items whose only interest is a named individual (a person-centred retraction story, a personal HF
  account incident). Personal names of authors/requesters are redacted in all notes (`[redacted]`).
- E4. Anything requiring authentication, a token, an account, or sending an email address / personal data.
- E5. Items that are private, gated behind a click-through with no public metadata, or illegal to fetch.

## 3. Sampling frame, inclusion rules, and negatives per kind

Negatives are **same-population items with no incident**: drawn from the same API/listing and the same
category as the positives (same ecosystem, same registry, same hub type), checked live to show no incident
signal. Where possible a negative is a *matched* control (same package / same record family / same
publisher-year) so the comparison is not trivially "popular vs obscure".

| Kind | Frame | Positive inclusion | Matched negative |
| :-- | :-- | :-- | :-- |
| `package_advisory` | OSV, ecosystem PyPI, ML-adjacent packages (torch, transformers, numpy, pillow, tensorflow, keras, onnx, mlflow, gradio, langchain, etc.), advisories published 2019–2026 | An OSV record whose `affected[].ranges` place a concrete released version inside an affected range; the unit is `pkg:pypi/<name>@<version>` + advisory id | The same package at a released version that OSV `/v1/query` returns no advisory for (normally the fixed / latest version) |
| `package_advisory` (withdrawn) | OSV PyPI records with a `withdrawn` timestamp | `withdrawn` present; unit = purl@affected-version + id | covered by the above negatives |
| `hub_scan` | HF model repos, `?securityStatus=true` | `securityRepoStatus.scansDone == true` and `filesWithIssues` non-empty; identifier = repo@sha + flagged path (+ lfs sha256 when the tree exposes it) | HF repos from the same search/listing with `scansDone == true` and `filesWithIssues == []` |
| `weight_file_scan` | (local scan) | Not sampled here: local-scan ground truth needs downloading weight files, which this protocol does not do. Gap documented. | — |
| `base_model_disabled` | HF model repos | `GET /api/models/{repo}?expand[]=disabled` answers with `disabled: true` | Same-owner or same-family repo with `disabled: false` |
| `base_model_unavailable` | HF model repos referenced publicly (model cards, papers, collections) that no longer resolve | Hub answers a refusal (401/403/404/451) for an id that is documented to have existed | A live repo from the same owner |
| `dataset_retracted` | Crossref works of type `dataset` (and, as the closest proxy, `paper_retracted`-style journal articles about datasets) with `updated-by[]` | `updated-by[].type` in {retraction, withdrawal, removal}, any source incl. `retraction-watch` | Same publisher / same year Crossref work with `updated-by` absent or containing only correction/expression_of_concern |
| `dataset_removed` (Zenodo) | Zenodo records | `GET /api/records/{id}` answers 410 with a tombstone body | Neighbouring Zenodo record id answering 200 |
| `dataset_removed` (hub) | HF dataset repos | `GET /api/datasets/{repo}?expand[]=disabled` answers `disabled: true` | Live dataset from the same owner or listing |
| `licence_changed` | Zenodo records with ≥2 versions; DataCite DOIs with versions; HF repos whose card licence changed | `metadata.license.id` (Zenodo) / `rightsList` (DataCite) differs between two versions of the same concept record | A multi-version record whose licence is identical across versions |

Search order is declared: use the provider's own search/listing with a fixed query, take results in the
order returned, apply E1–E5 and the inclusion rule, and stop at the target count. Skipped items are logged
with the reason so the selection can be audited.

Targets: **~10 positives + ~10 negatives per kind where available.** Fewer is acceptable and documented;
the budget for this pass is ~120 tool calls, so lower-yield kinds may end below target.

## 4. Ground-truth labels and expected tool outcome

Each record carries `label` ∈ {`positive`, `negative`} and `expected_outcome`:

- `alert_open:<kind>` — the tool should open that alert kind on a fresh register/check.
- `alert_closed:withdrawn` — for a withdrawn OSV advisory: the tool should *not* open, or should close an
  existing alert as `withdrawn`.
- `no_alert` — a negative: no alert of that kind, no watch event required.
- `watch_event` — the upstream signal is real but below alert threshold under the spec (e.g. an HF
  `caution` level, an expression of concern, a refusal shorter than the 24 h refusal-span rule). Counted
  separately; neither a hit nor a miss for alert precision/recall.

Terminal states (from `specs/002-upstream-watch/data-model.md`, Identity and clearance): an alert that is
later closed is scored by its *first* state against the label; closure is scored separately:
`fixed` (new version no longer pins), `cleared` (source no longer shows cause in a well-formed answer),
`withdrawn` (OSV only), `dismissed` (human, excluded from automatic scoring).

## 5. Outcome definitions (event level)

- **Detected (TP):** label positive, tool opens the expected alert kind for that identifier.
- **Missed (FN):** label positive, tool opens no alert of that kind (a watch event instead counts as a miss
  for alert recall but is reported in its own column).
- **False alarm (FP):** label negative, tool opens an alert of that kind.
- **True negative (TN):** label negative, no alert of that kind.
- **False closure:** a positive whose alert the tool closes (`cleared`/`withdrawn`/`fixed`) while the
  upstream cause still holds and the dependency is unchanged — measured by re-checking positives on a
  later run; also any withdrawn advisory that the tool keeps open (false non-closure, reported beside it).
- Source failure (timeout, 5xx, rate-limit) is recorded as `indeterminate`, not as a miss.

## 6. Reporting uncertainty

Per kind and per source: counts TP/FN/FP/TN/indeterminate, sensitivity = TP/(TP+FN), specificity =
TN/(TN+FP), precision = TP/(TP+FP), each with a **Wilson 95% score interval**. With n≈10 per cell the
intervals are wide (e.g. 10/10 → [0.72, 1.00]); results are reported as counts first and never pooled
across kinds into a single accuracy number.

## 7. Record schema (`candidates.jsonl` / `candidates.json`)

`id, kind, label, identifier, source_url, retrieved_utc, http_status, proof_field, proof_quote,
expected_outcome, response_sha256, raw_path, notes`. `response_sha256` is SHA-256 of the exact bytes saved
under `raw/`. Requests use the generic User-Agent `heldout-corpus-research/0.1`, no email, no token.

## Amendments

Appended after collection started (2026-10-25, 02:14-02:45 UTC). Nothing above was edited.

- A1 (02:14) `package_advisory` frame made concrete: OSV PyPI bulk export `PyPI/all.zip` (sha256
  95b325be...0be5, 26,612 records, 622 withdrawn), `random.Random(20261025)`; one advisory per package from
  the ML list in `scripts/osv.py`; affected version = last entry of `affected[].versions`; positive kept only
  if live `/v1/query` lists it. Withdrawn sample: 10 of 589 eligible, any PyPI package (not ML-restricted,
  because withdrawn ML-package records are too few to fill the cell). Observation: none of the 10 withdrawn
  ids is returned by live `/v1/query` for its affected version, so on a fresh registration the expected
  outcome is "no alert"; the `withdrawn` closure path is only exercised for a pre-existing alert.
- A2 (02:16) `hub_scan` frame: HF `/api/models?search=<term>&sort=downloads&limit=40` for 10 fixed terms
  (`scripts/hfscan.py`), first 90 unique repos in returned order. Positives and negatives both come from
  this name-matched listing; HF `caution`-only files map to `watch_event` (lifecycle.py routes caution to
  SCAN_SUSPICIOUS).
- A3 (02:19) HF disabled/unavailable frame: the public `huggingface-legal/takedown-notices` index.csv
  (sha256 d5f772c0...2b83), every single-repo row, plus repos linked from "Multiple" notices (first 70).
  Takedown-listed repos that the hub still reports `disabled: false` are kept as **hard negatives**.
- A4 (02:23) Crossref has exactly one work of type `dataset` with a retraction on retrieval day, so
  `dataset_retracted` is 1 positive. Added `paper_retracted` as a proxy cell: retracted articles in data
  journals (Scientific Data, Data in Brief, ESSD, GigaScience, MDPI Data), with same-journal same-year
  negatives at listing offset 40 and correction/EoC-only hard negatives.
- A5 (02:27) Zenodo removed frame: 140 ids from `random.Random(20261025).sample(range(1e6, 1.75e7))`;
  410 = positive, 200 = negative, 404 ignored; stopped at 10/10 after 74 probes (52x200, 10x410, 12x404).
- A6 (02:33) `licence_changed` frame: Zenodo search `resource_type.type:dataset`, sort `mostviewed`, pages
  1-4 (100 records), versions via `/api/records/{id}/versions?size=25&sort=oldest`, ordered by `created`.
  Licence compared by Zenodo licence id. DataCite and HF licence histories not sampled (budget).
- A7 `weight_file_scan` and `format_policy` not sampled (needs downloading weight files).
- A8 Raw bodies in `raw/` are verbatim upstream responses and may contain names in titles/citations; they are
  kept only for hash verification and must not be redistributed. Candidate notes redact names.

### Freeze (2026-10-25)

The owner approved the candidate list with these changes, and the corpus was frozen as
`corpus.json` (153 records):

- Struck 5 `hub_scan` positives that copy the existing `42-eicar-street` fixture (HO-030 to HO-034),
  since they are not held out from the fixtures.
- Struck 10 Zenodo `dataset_removed` positives (HO-129, HO-130, HO-136 to HO-143), which are spam or
  blocked-user removals rather than dataset withdrawals.
- Accepted `paper_retracted` as the stand-in for dataset retractions, as Crossref lists only one
  retracted dataset.

The saved upstream bodies (`raw/`) are not committed, because they can carry personal names in titles
and citations; each record keeps the body's SHA-256 and the quoted field that proves its label. Before
scoring, re-check each record's live state and re-label any that has drifted, recording the change here.

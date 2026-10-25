# Held-out corpus (frozen 2026-10-25)

This is the candidate list for model-dependabot's held-out evaluation. Collected 2026-10-25, 02:14 to 02:45 UTC,
using anonymous read-only requests with User-Agent `heldout-corpus-research/0.1`: no email, no token, no account.
The rules were written in `protocol.md` before any search ran. Every change made after collection started is
appended there as amendments A1–A8. The owner approved the list on 2026-10-25 with 15 strikes; the counts below are the frozen corpus (see the Freeze section of `protocol.md`).

## Files

- `protocol.md`: the sampling frames, inclusion and exclusion rules (E1–E5), label definitions, what each
  outcome means, and the Wilson reporting rule, plus the amendments.
- `corpus.json`: the frozen corpus, 153 records (the 168 candidates HO-001 to HO-168 less the 15 struck at the freeze; see `protocol.md`). Duplicates are removed and E1/E3 drops are applied.
  The fields follow protocol section 7. Hub-scan positives also carry `file_sha256` and the hash of the tree response.
- Not committed, kept with the collector: `candidates.jsonl`, the raw write-immediately log, appended as each record was confirmed. It holds 18
  duplicate lines, written when a module import re-ran the first Crossref pass. `assembly_log.json` records them.
- `skipped.jsonl`: every candidate that was looked at and rejected, with the reason.
- `raw/` (not committed; it can carry personal names): the saved response bodies, named `<sha256[:16]>.body`. All 168 recorded hashes were re-verified
  (`raw_sha256_verified: true`). `raw/osv-dump/PyPI-all.zip` (sha256 95b325be…0be5) and
  `raw/hf-takedowns/index.csv` (sha256 d5f772c0…2b83) are the frame snapshots.
- `scripts/`: the collection code, which is reproducible with its fixed seeds. Run it with `python -I`.

## Counts per kind

| Kind | Pos | Neg | Notes |
| :-- | --: | --: | :-- |
| package_advisory (active) | 10 | 9 | 10 ML packages; each negative is the latest release of the same package. pillow@13.0.0 was dropped (E1 fixture) |
| package_advisory (withdrawn) | 10 | — | None of the 10 is returned by live `/v1/query`. On a fresh registration the expected result is no alert; `withdrawn` closure is only tested against an alert that already exists |
| hub_scan | 7 | 12 | Both sides come from the same name-matched HF search. 5 near-copies of the `42-eicar-street` fixture were struck at the freeze |
| weight_file_scan / format_policy | 0 | 0 | Not sampled: it would mean downloading weight files |
| base_model_disabled | 2 | 4 | All 4 negatives are hard: listed in the takedown index but `disabled: false`. Far below target |
| base_model_unavailable | 15 | 6 | Each is one refusal observation, so the expected result is `watch_event` until the 24 h refusal-span rule is met. The repo type (model or dataset) is unclear for some |
| dataset_removed (HF hub) | 21 | 6 | `disabled: true`, from takedown notices. 7 of the 21 share one owner. The 6 negatives are hard (takedown-listed but still live) |
| dataset_removed (Zenodo) | 0 | 10 | Seeded random id probe. Every 410 found was a spam or blocked-user removal, so all 10 positives were struck at the freeze |
| dataset_retracted | 1 | 3 | Crossref has exactly 1 dataset-typed work with a retraction |
| paper_retracted (proxy, added in A4) | 7 | 11 | Data-journal retractions. The negatives are 7 matched (same journal and year) plus 4 hard (correction or EoC only) |
| licence_changed (Zenodo) | 9 | 10 | 4 of the 9 positives involve a Zenodo `other-*` id, so they are marked UNCERTAIN (unrecognised licence may become a watch_event) |

There are 7 records in total whose `expected_outcome` is marked UNCERTAIN. They are listed in `corpus.json`.

The intervals are wide. A perfect 10/10 gives a Wilson 95% interval of [0.72, 1.00], 2/2 gives [0.34, 1.00], and
1/1 gives [0.21, 1.00]. Report the results as per-kind counts. Do not pool them into a single accuracy figure.

## Gaps

- There are no `weight_file_scan` items, no DataCite or HF licence histories, and no Figshare items.
- `base_model_disabled` (2 positives) and `dataset_retracted` (1) are far below target.
- None of the Zenodo 410s is a real dataset removal.
- No HF dataset licence changes were sampled.
- No false-closure items have been collected yet. These need a second run on a later day, re-checking the positives.

## Caveats on hub_scan

- 5 of the 12 positives are EICAR or "eicar-street" style test repos. They are close relatives of the dev fixture
  `mcpotato/42-eicar-street`.
- The two `same-owner` repos share one file sha256. Because hub_scan is scoped by file hash, they count as one unit.
- Some flagged files are not stored in LFS, so the hub exposes no sha256 for them. Those are marked UNCERTAIN.

## Sampling-bias risks (stated plainly)

1. **The frames are the same APIs and fields the tool reads.** OSV, the HF `securityStatus`/`disabled` fields,
   the Crossref `updated-by` list, Zenodo 410s and the HF takedown index (which the tool also uses, see
   `tests/fixtures/hf_takedowns`) were all used to *select* the positives. The labels therefore measure whether
   the tool's parsing and lifecycle are faithful to what each source currently says. They do not measure
   whether upstream completeness is correct, and incidents a source never published cannot appear here.
   Recall against "real-world incidents" is overstated to the same extent. An independent frame would be
   needed to correct this, for example NVD or GitHub advisories not yet in OSV, Retraction Watch CSV rows
   missing from Crossref, or press-reported HF removals.
2. **The populations are skewed toward test and spam items.** Hub-scan positives come from name searches
   ("eicar", "malicious", "picklebomb"), so they are mostly deliberate proof-of-concept repos. Zenodo
   removals are all spam. HF removals cluster in a few takedown notices (7 of 21 from one owner). Field items,
   such as real models with an incidental unsafe pickle or a real dataset withdrawn by its curator, are
   under-represented. Performance on those could differ.
3. **Labels are point-in-time, and several kinds depend on state.** The OSV negatives are "latest release with
   no advisory today" and can turn positive later. `base_model_unavailable` needs 24 h of scheduled refusals.
   Withdrawn advisories only test closure if an alert already exists. Takedown-listed repos change state.
   Freeze the list together with the saved raw bodies, and re-label any item whose live state has drifted
   before scoring.

Smaller risks: package selection is restricted to an ML list I chose (withdrawn advisories are not restricted
this way). The Zenodo licence frame is the 100 most-viewed datasets. The Crossref paper negatives all sit at
listing offset 40.

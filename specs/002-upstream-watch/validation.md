# Validation: Upstream Watch for Base Models and Training Datasets

Recorded 2026-10-24 on branch `002-upstream-watch` (on top of `8424621`), Windows 11, Python 3.12 under
`uv`. Exit codes are the commands' own (no pipes in front of them). Section 2 is T060; section 3 is the
T062 neutrality and privacy search. The walk-through of quickstart.md on a real model inventory (T061)
is recorded separately, by the owner's run.

## 1. Owner decisions and dispositions built in this pass

| Item | What changed | Proof |
| :-- | :-- | :-- |
| Licence sets (owner, 2026-10-24) | Every licence entry a source declares is recorded, one per line; licences are compared as the normalised set, order ignored; the CycloneDX `licenses` array holds one choice per entry | `tests/unit/test_licence_sets.py` (seen failing: 15 of 19, then 19 passed) |
| SPDX exceptions list (owner, 2026-10-24) | `licences/spdx-exceptions-3.29.0.json` (86 exceptions, 41,420 bytes, SHA-256 `59ee7c150de521d635cbf9367b8cf543b8da6781ea3ac1c073d305524f84ada2` in `SHA256SUMS`); `<licence> WITH <exception>` normalised against it, exception ids ignoring case; an unknown or misplaced exception stays unrecognised | same file; `git check-attr` shows `text: unset` for the new JSON and `SHA256SUMS` |
| `base_model_unrecognised` row | Added to data-model.md's watch-event table | data-model.md |
| `base_model_disabled` cleared | A later hub answer with `disabled: false` closes it as `cleared` with that observation as evidence; a refusal or failed request does not | `tests/unit/test_lifecycle_base_model.py` (2 tests; the first seen failing) |
| Refusal run ended by any non-refusal | Documented in data-model.md (refusal-span rule) | data-model.md |

## 2. Suite, lint, live tests and performance (T060)

| Command | Result | Exit code | Time |
| :-- | :-- | :-- | :-- |
| `uv run pytest -q` | 811 passed, 12 deselected (the `live` tests). Network blocked by `tests/conftest.py` (sockets and name resolution) | 0 | 61.8 s |
| `uv run ruff check` | All checks passed | 0 | under 1 s |
| `uv run ruff format --check` | 151 files already formatted | 0 | under 1 s |
| `uv run pytest -m live -q -rA` (run once) | 11 passed, 1 failed | 1 | 7.9 s |
| `uv run pytest -m live -q tests/live/test_live_upstream.py::test_the_takedown_log_still_lists_the_recorded_notice` | 1 passed | 0 | 0.5 s |

The one live failure was in the new test, not a source: it read the notice's `date` key, but
`TakedownLog.find` returns `notice_date` and `reported_content`. With the test corrected the live log
still lists `yavon/muxue` with notice date 2025-01-29. Every live answer matched its recorded shape:
doiRA (DataCite for the Zenodo DOI, Crossref for the retracted paper), `openai-community/gpt2` reachable
with licence `mit`, `yavon/muxue` 200 with `disabled: true`, a nonexistent dataset 401, the Crossref
retraction still listed, DataCite routing the Zenodo DOI to record 3242074, Zenodo record 12584226 410
with a tombstone, Figshare article 34763127 declaring `CC BY 4.0`. No fixture was edited.

The baseline before this pass was 765 passed, 3 deselected (commit `8424621`).

### Performance (plan.md: one model, a base model and ten datasets, budget 60 seconds)

`uv run python tools/perf_upstream_check.py` (exit code 0). The model has a base model
(`openai-community/gpt2`) and ten datasets: the Zenodo record 3242074 tied to the retracted paper, the
deleted Zenodo record 12584226, the Figshare article 34763127, a DOI doi.org does not know, the disabled
hub dataset `yavon/muxue` and five hub datasets derived from its recording under made-up names. Requests
go through `UrlFetcher` with its per-host pacing and real sleeps; only the opener is replaced so that it
answers from the recordings.

| Measure | Value |
| :-- | :-- |
| `register` | 0.19 s, exit code 0 |
| `check --all --scheduled` | 0.30 s, exit code 0 (0.39 s on a first run) |
| Requests | 32 in all; the check sent 18: doi.org 2, huggingface.co 9, api.crossref.org 1, api.datacite.org 3, zenodo.org 2, api.figshare.com 1 |
| Sources | every source `ok` |
| Budget | 60 s: within it |

The recordings answer at once, so the time is the tool's own work plus pacing; against the real sources
the round trips add to it, and Crossref and Figshare (one request a second each) set the floor when a
model ties many papers or Figshare datasets.

## 3. Neutrality and privacy (T062)

Pattern `P = (the list itself is kept outside the repository)`
(the 001 pattern).

| Search | Result |
| :-- | :-- |
| `grep -rniEc "$P" src tests tools README.md research specs` | 44 lines in 8 files. 38 are licence and exception names in the vendored SPDX lists and schema (University of California, Nara Institute of Science and Technology, University of Illinois): third-party data. 3 are third-party metadata in recorded public answers used as test data: Crossref funder names in `crossref/retracted.json`, the holding library of the Figshare article in `figshare/public-article.json`, and the gated-model fixture `meta-llama/Llama-3.1-8B` (`hf_upstream/model-gated.json`). 3 are in feature 001's own records (`plan.md:58`, `validation.md:73,78`), as recorded there. None names the project's users or authors |
| `git log --format=%B \| grep -ciE "$P"` | 0 commit messages match. The commit author field carries the account's name and its GitHub no-reply address, which is git metadata rather than message text |
| Email addresses in `src tests tools README.md research specs` (outside the vendored SPDX and JSF files and the gated-model card) | `firstname.lastname@example.com` (CycloneDX schema example), `someone@example.org` (a test that the fetcher refuses such a User-Agent, and 001's record of it) |
| Personal fields in fixtures | The names `removed_by`, `citation_text`, `creators`, `contributors`, `owners`, `authors` and `requesting_entity` occur only in `.meta.json` files' `redacted_fields`; the recorded takedown log's header is `date,reported_content` |
| User-Agent | `DEFAULT_USER_AGENT = f"model-dependabot/{__version__}"` (`sources/fetcher.py:38`); `UrlFetcher` refuses one carrying an email address |
| Privacy end to end | `tests/integration/test_privacy.py`: canary values put back into derived takedown-log, Zenodo, Figshare, Crossref and DataCite answers are found in no file under the database directory after `register` and `check --all --scheduled`, and the evidence lists the removed fields |

No change was needed.

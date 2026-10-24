# Quickstart: validating feature 002

Runnable checks that prove upstream watch end to end. Feature 001's [quickstart](../001-inventory-alerts/quickstart.md)
must pass first. Commands assume the repository root and a uv environment; the
[CLI contract](contracts/cli.md) and [data model](data-model.md) define the commands, kinds and states.

## 1. Offline test suite (no network)

```bash
uv run pytest
```

Expected: all tests pass with network access disabled. Each new source adapter (`hf-hub` for models and
datasets, `hf-takedowns`, `crossref`, `datacite`, `zenodo`, `figshare`, DOI agency lookup) runs against
recorded responses in `tests/fixtures/` (constitution V).

## 2. Retraction and removal (US1, SC-001)

Using recorded responses:

- a dataset tied to a paper DOI that Crossref lists as retracted: one `paper_retracted` alert naming both
  DOIs and the notice, with `source: "retraction-watch"` or `"publisher"` in the evidence;
- a Zenodo dataset whose record answers 410: one `dataset_removed` alert with the removal date and reason;
- a hub dataset reported `disabled: true` and listed in the takedown log: one `dataset_removed` alert whose
  evidence labels the date a notice date;
- a DataCite DOI that answers 404: one `dataset_not_findable` alert;
- a dataset in none of these: no alert.

## 3. Licences (US2, SC-002)

Replay pairs of recorded responses: `apache-2.0` then `Apache-2.0` (no alert), Figshare `CC BY 4.0` against a
recorded `CC-BY-4.0` (no alert), `apache-2.0` then `cc-by-nc-4.0` (one `licence_changed` alert showing both),
`mit` then `llama3.1` (a `licence_unrecognised` watch event, no alert), a licence then none
(`licence_missing` watch event). `apache-2.0` then `cc-by-nc-4.0` then `mit`: still one `licence_changed`
alert, with both observations as evidence and `mit` as the declared licence; `apache-2.0` then
`cc-by-nc-4.0` then `Apache-2.0`: the alert closes as `cleared`.

## 4. Base model availability (US3, SC-003)

Replay hub answers across simulated check runs:

- scheduled refusal at day 0, reachable at day 1: a `base_model_refused` watch event, no alert;
- scheduled refusals at day 0 and day 1 (24 hours apart): one `base_model_unavailable` alert, severity `LOW`,
  showing the refusals of the run;
- scheduled refusals at day 0, then a few seconds under 24 hours later, then a few seconds under 24 hours
  after that: no alert on the second run, one alert on the third, because the unbroken run of scheduled
  refusals now spans at least 24 hours from its first refusal (the refusal-span rule, research U7);
- an on-demand refusal between them changes nothing (it neither counts nor breaks the run); an on-demand
  reachable answer ends the run; a timeout is a failed source, not a refusal;
- the base model reachable again: the alert closes as `cleared`;
- `disabled: true`: one `base_model_disabled` alert at once, severity `MODERATE`.

## 5. Watch events only (US4)

Replay a newer head revision, a `new_version` pointer, a gating change from `false` to `manual`, a card
change, a newer Zenodo version, a DataCite `IsObsoletedBy`, a hub redirect to `defunct-datasets/`, a
Figshare 404 and a Crossref 404 for a tied paper DOI (`paper_not_found`). Expected: one watch event each, no
alerts.

## 6. Source failure (SC-005)

Run a check with one source unreachable (simulated). Expected: exit code 2; no alert opens, changes or
closes because of that source; the check run records the source as failed.

## 7. Privacy

After the suites above, search the evidence store and database for the fixtures' takedown-log
`requesting_entity` and `file` values, the Zenodo `citation_text`, `removed_by`, `metadata.creators`,
`metadata.contributors` and `owners` values, the Figshare `authors` and `citation` values and the Crossref and
DataCite person names (including Crossref `reference[].author` and `reference[].unstructured`). Expected: none
found; the evidence records list those fields in `redacted_fields`.

## 8. Live smoke tests (optional, marked `live`)

```bash
uv run pytest -m live
```

Expected: the live answers still match the shapes recorded in the fixtures (for example `yavon/muxue`
`disabled: true`, a nonexistent dataset 401, the Zenodo 410 tombstone). Excluded from the default run.

## 9. Scheduling

The host scheduler now runs `uv run model-dependabot check --all --scheduled` daily, superseding feature
001's `check --all` ([CLI contract](contracts/cli.md)); only these runs count towards the refusal-span rule.

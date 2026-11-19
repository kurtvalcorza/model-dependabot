# Quickstart: An Actionable Alert View for Model Maintainers

Validation scenarios for feature 010, run offline. Each scenario names the test that runs it; the
manual commands show what a maintainer sees. Results are recorded in `validation.md` (T044).

The family model of `tests/fixtures/advice/` pins a local pickle weight file, a hub weight file, a
locked package at an affected version, a base model and a DOI dataset that cites a paper; its recorded
answers raise one alert of every rule ID across its models (T004). Commands below assume a store built
from it at `$DB`.

## 1. The baseline holds without `--advice` (US4, SC-002)

```sh
uv run pytest tests/integration/test_cli_baseline.py -q
```

Expect: every invocation of `tests/fixtures/cli_baseline/pre-010-baseline.json` (alerts with each
`--state`, `alert show` per state, `history`, `run show`, `check` with and without `--fail-on HIGH`)
gives the same stdout, stderr and exit code, byte for byte.

## 2. Which entry, and how it relates (US1)

```sh
model-dependabot alert show 3 --advice --db "$DB"
```

Expect for the package alert: `Entry: package pkg:pypi/<name>@<version>, in the current version`, the
place with its origin and `[environment] lock`, `Relationship: package pinned in this model's
environment lock (owner declaration, v1)`, `Runtime use: unknown: ...`. Then:

```sh
model-dependabot alert dismiss 3 --reason not_used_at_runtime --by maintainer --note "CLI only" --db "$DB"
model-dependabot alert show 3 --advice --db "$DB"
```

Expect `Runtime use: declared not_used by maintainer at <time>` and an `Owner decision: dismissed
not_used_at_runtime ...` line; `Impact: impact undetermined` is unchanged. Test:
`tests/integration/test_advice_entry.py`.

## 3. Unresolved and no longer current (US1 scenarios 3 and 4)

Register version 2 without the package, check, then `alert show <id> --advice` on the fixed alert:
expect `last held in v1` and the place from v1. For an alert whose identifier no version holds (built
in the test by editing a copy of the store's alert cause), expect `Entry: unresolved: no stored
version holds this identifier`. Test: `tests/unit/test_affected.py`.

## 4. Established apart from not established (US2, SC-003)

```sh
model-dependabot alerts paper-model --state all --advice --json --db "$DB"
```

Expect for the `paper_retracted` alert: every `established` item has `evidence_ids` drawn from the
alert's own evidence; `not_established` starts with the impact question and lists whether the
retraction affects the data this model was trained or evaluated on; `impact` is `impact undetermined`;
no string contains a phrase of `tests/fixtures/advice/verdicts.json`. Test:
`tests/integration/test_advice_statements.py`.

## 5. Review steps (US3, SC-001)

```sh
uv run pytest tests/unit/test_rule_texts.py tests/unit/test_review_steps.py -q
```

Expect: 12 rule IDs, each with limitations, closing text, fix text, steps and not-established items;
every `model-dependabot ...` command in a step parses with the real parser; two alerts of one rule ID
differ only in substituted identifiers; the rule pages are in step with `rule-texts.toml`.

## 6. Read-only, offline and deterministic (FR-002, FR-003, SC-004)

```sh
uv run pytest tests/integration/test_advice_read_only.py -q
```

Expect: `total_changes` unchanged, database file and evidence directory byte-identical, no request
made, and two renderings byte-identical, for `alert show --advice` and `alerts --advice`, text and
JSON.

## 7. Exit codes and the gate (US4, FR-017)

```sh
uv run pytest tests/contract/test_exit_codes_advice.py -q
```

Expect: each `alerts` and `alert show` invocation of the baseline exits the same with `--advice`; an
unknown alert exits 1 with and without it; `check --fail-on` counts are unchanged after any number of
advice views.

## 8. Four questions from one view (SC-005)

For one alert per family (weight files, packages, datasets and papers, licences, base model), read the
text view alone and answer: which entry, how it relates, what is established, what to do next. Record
the five answers in `validation.md` (T043).

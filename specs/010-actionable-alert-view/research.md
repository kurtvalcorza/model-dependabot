# Research: An Actionable Alert View for Model Maintainers

**Feature**: [spec.md](spec.md) | **Plan**: [plan.md](plan.md) | **Date**: 2026-11-19

Each item records the finding, the decision, why it was made and what else was considered. Code
references are to `main` at `47ebfbe` (PR #27 merged); the last commit to touch `src/` before it is
`0e927e6`. A reference marked *confirmed* was read at that commit; one marked *inferred* names the task
that confirms it.

## Questions for the owner

Planning found four choices that change what users see or how a requirement is read. **The owner
accepted all four recommendations on 2026-11-19** (column "Ruled"); tasks.md follows the rulings. The
same review ruled that 010 lands before 011 (plan, "Overlap with feature 011").

| # | Question | Options | Recommended | Ruled | Tasks affected |
| :-- | :-- | :-- | :-- | :-- | :-- |
| Q1 | Environment markers are not stored (R5), so the spec's edge case "the view names the marker" cannot be met from stored rows | (a) this feature names no marker; every package alert lists "whether the package is installed where the model runs" as not established and the limitation "this inventory does not record environment markers"; storing markers is a follow-up issue; (b) store the marker at registration (a new nullable `inventory_entries.marker` column and a `LockEntry.marker` field), so versions registered after this feature show it | **(a)**: the view stays read-only with no schema change (plan, Storage); (b) is an inventory change for a separate feature, and old versions would still read "not recorded". The spec's edge case needs a one-line amendment under either ruling | **(a)**, owner, 2026-11-19; spec edge case amended; follow-up issue #28 | T027, T040 |
| Q2 | `Store.__init__` migrates an older database on open, a write (R8); FR-002 and SC-004 say the view writes nothing | (a) keep today's open for `--advice`; SC-004 is measured on a database already at the current schema, and the view code never calls a writing method; (b) open with `Store.open_read_only` when `--advice` is given | **(a)**: (b) makes `alerts ID --advice` exit 3 on a database older than feature 002 where `alerts ID` migrates and exits 0, which FR-017 forbids | **(a)**, owner, 2026-11-19; SC-004 measured on a current-schema database | T015, T022, T037 |
| Q3 | Do the numbered review steps also appear on the rule pages? (R4) | (a) yes: "How to fix or accept it" on each page is the fix prose followed by the steps, rendered from the same file, with placeholders shown as `<identifier>`; (b) no: the steps live only in the view | **(a)**: one text, read the same way in both places (FR-014); the pages keep their four headings, so `tests/unit/test_rules.py:51-55` still holds | **(a)**, owner, 2026-11-19 | T012 |
| Q4 | The constitution says "The first user is a model-hosting platform"; D3 and the spec say the first user of this view is the model maintainer (plan, Constitution Check) | (a) no amendment; (b) a PATCH clarification in its own change | **(a)** for this feature: the view names no platform, so nothing in it conflicts | **(a)**, owner, 2026-11-19; no constitution change | none |

## R1. How the view is asked for and where it appears (FR-001, FR-018)

**Finding** (*confirmed*): `alerts` and `alert show` are leaf parsers (`cli.py:270-278`); their handlers
build a payload and text (`cli.py:851-855`, `cli.py:863-869`), and `main` prints the JSON with
`indent=2, sort_keys=False` or the text (`cli.py:368-371`). `alert show` text is the alert line, a
`Model:` line and the evidence rows (`cli.py:493-496`); `alerts` text is `alerts_text`
(`reports.py:247-270`).

**Decision**: one `--advice` flag (`store_true`) on both leaf parsers, as clarified. With the flag:

- JSON: every alert object that today has the fields of `alert_view` (`reports.py:70-90`) gains exactly
  one key, `advice`, appended last; no existing key changes value or position. `alerts ID --advice`
  also gains a top-level `advice_summary` appended last (US2 scenario 6). Watch events gain nothing.
- Text: today's text is printed unchanged, then a blank line, then one advice block per alert in the
  listing order. So the output with the flag starts with the exact bytes of the output without it, a
  property the contract test checks.

**Alternatives**: a new `advice` command (rejected by the owner's clarification); interleaving each
advice block under its alert line (breaks the prefix property and makes FR-016 harder to argue).

## R2. Resolving the affected entry (FR-005, FR-006)

**Finding** (*confirmed*): alerts store a `cause` JSON and a `cause_key`; entries are stored per version
(`store.entries`, `store.py:1458-1478`) with `kind`, `identifier`, `name`, `version` (the package
version), `location`, `hub_repo`, `hub_file`, `hub_revision` and `paper_dois`. Cause keys:
`package_advisory:<advisory>:<canonical name>` (`lifecycle.py:361-363`), `<kind>:<sha256 hex>` for the
four weight kinds (`lifecycle.py:1047-1049`), `<kind>:<identifier>[:<paper DOI>]` for the upstream kinds
(`lifecycle.py:2552-2554`). Base-model alerts and hub-dataset removal and paper alerts are keyed by
repository, not revision (`lifecycle.py:2557-2568`, `2582`, `2903-2907`, `3097`; the migration
`_rekey_repository_alerts`, `store.py:920`). Each cause carries `identifier`; package causes add
`package`, `version` (`lifecycle.py:874-886`); base-model causes add `repo` (`lifecycle.py:3169`,
`3247`); paper causes add `paper_doi` (`lifecycle.py:2899-2907`); licence causes add `item`
(`lifecycle.py:3474-3483`).

**Decision**: a pure function `resolve_entry(alert, versions)` where `versions` maps each stored version
of the alert's model to its entries and origin. It looks for exact matches only, by alert kind:

| Alert kinds | Match an entry with | On a repository key |
| :-- | :-- | :-- |
| `weight_file_scan`, `hub_scan`, `format_policy`, `globals_policy` | `kind = weight_file`, `identifier = cause.identifier` (`sha256:<hex>`) | not applicable |
| `package_advisory` | `kind = package`, `identifier = cause.identifier` (the purl) | not applicable |
| `dataset_retracted`, `dataset_not_findable`, `dataset_removed` | `kind = dataset`, `identifier = cause.identifier` | `dataset_removed` on a hub dataset: `hub_repo` equals the repository in the cause key |
| `paper_retracted` | `kind = dataset` whose `paper_dois` holds `cause.paper_doi` and whose `identifier` equals `cause.dataset` | hub dataset: `hub_repo` equals the repository in the key, whatever revision it pins, **and** `paper_dois` holds `cause.paper_doi` (both paths require the paper) |
| `licence_changed` | `kind` `base_model` or `dataset`, `identifier = cause.item` | repository scope: `name` (base model) or `hub_repo` (dataset) equals the scope |
| `base_model_disabled`, `base_model_unavailable` | `kind = base_model`, `name = cause.repo` | always by repository |

No match in any version gives `unresolved` with one of three reasons: `no stored version holds this
identifier`, `the alert's cause does not name an identifier` and `the alert's model has no stored
version`. Matches are listed in a fixed order: version descending (so the current version, when it
holds the entry, comes first), then the order `store.entries` returns (`ORDER BY entry_id`, `store.py:1460`; the records carry no
`entry_id`, `ENTRY_FIELDS`, `store.py:446-465`). A match
in the current version sets `in_current_version: true`; otherwise the view names
`last_held_in_version`, the highest version that holds it.

**Reuse**: whether a cause is repository-scoped and which repository an entry belongs to are already
decided in `lifecycle.py`: `_repository_scoped` (`lifecycle.py:3572-3584`), `_hub_scope`
(`lifecycle.py:2571-2578`), `base_model_repo` and `hub_dataset_repo` (`lifecycle.py:2557-2568`). The
resolver imports them unchanged rather than re-deriving them. Extracting them into a shared module would
edit `lifecycle.py`, which the 011 overlap ruling keeps out of 010; that extraction is a follow-up after
011.

**Alternatives**: matching by package name alone (would pick the wrong pinned version, a partial match
FR-006 forbids); reading only the alert's `current_version` (cannot name the last holder of a `fixed`
alert's entry).

## R3. Runtime use (FR-007, FR-008)

**Finding** (*confirmed*): the manifest has no runtime key (`manifest.py:21-27`; unknown keys are an
error, `manifest.py:3-4`). The only related record is the dismissal reason `not_used_at_runtime`
(`store.py:72`). A dismissal stores `dismissal_reason`, `dismissed_by`, `note` and `closed_at`; there is
no `dismissed_at` column (`alerts` table, `store.py:256-277`). `dismiss_alert`
(`lifecycle.py:2483-2503`) closes the alert through `store.close_alert(..., state="dismissed")`
(*confirmed*), and `close_alert` sets `closed_at` to `self._stamp()`, the store's clock
(`store.py:1752-1764`, *confirmed*). T014 keeps that as a regression assertion.

**Decision**: `runtime_use` is `declared` with polarity `not_used` when this alert's stored state is
`dismissed` and its reason is `not_used_at_runtime`, with basis `{by: dismissed_by, at: closed_at,
note}`. Otherwise `unknown`, with basis "no source observes runtime use and the owner has not declared
it for this alert", plus `context`: the ids, `dismissed_by` and `closed_at` of every other alert of the
same model whose resolved entry has the same identifier and that was dismissed `not_used_at_runtime`,
by alert id. `observed` is a defined value that nothing produces in this feature; a test asserts no
code path returns it. A held dismissal's new alert (`cause.reopens`, `lifecycle.py:50`, `272`) is
another alert, so it reads `unknown` with the dismissed one as context.

## R4. One source of text per rule ID (FR-010, FR-014, FR-015)

**Finding** (*confirmed*): every page under `docs/rules/` has exactly four headings
(`tests/unit/test_rules.py:16-21`, `51-55`) and prose sections; there is no structured text today. The
safe list shows the house pattern for package data: a TOML file beside an `__init__.py` and a
`README.md`, read with `tomllib` (`assurance/globals_policy.py:6`, `23`, `47`). The build backend is
`uv_build` (`pyproject.toml:27`), which ships files inside the package directory.

**Decision**: `src/model_dependabot/rule_texts/rule-texts.toml`, version 1, one table per rule ID with
`limitations` (the page's "What it does not prove"), `closes` ("How it closes"), `fix` ("How to fix or
accept it" prose), `steps` (an ordered array) and `not_established` (an ordered array whose first item
is the impact question). Version 1 copies the three prose sections of each page verbatim, so the
existing prose of every page is unchanged when the file lands; under the Q3 ruling each page also gains
its numbered review steps after the fix prose, so all 12 pages change by that list. `rules.py` loads it once and refuses a file where a
rule ID lacks a field, a field is empty, an unknown placeholder is used, or a rule ID is missing or
extra. `tools/render_rule_pages.py` rewrites the three sections of each page from the file (Q3 (a):
the steps follow the fix prose, numbered, placeholders shown as `<name>`); a test renders and
compares, so a page edited by hand fails the suite. "What raises it" stays hand-written (it describes
the code, not the view).

**Placeholders** allowed in `steps` and `not_established`, filled only from the alert's stored fields
(FR-014): `{alert_id}`, `{model_id}`, `{identifier}`, `{location}`, `{package}`, `{version}`,
`{advisory_ids}`, `{dataset}`, `{paper_doi}`, `{repo}`, `{item}`, `{rule_doc}`. A placeholder with no
stored value renders as `not recorded`, and a test (T031) checks that every placeholder of a rule's
steps is present in the cause shape of that kind's fixture alert.

**Alternatives**: Python constants in `rules.py` (harder for a reviewer to read beside the pages); pages
as the source, parsed at run time (the CLI would read `docs/`, which is not package data).

## R5. Environment markers are not stored

**Finding** (*confirmed*): `LockEntry` holds `name`, `version`, `hashes`, `pinned` and `gap_reason`
(`lockfile.py:27-34`); the parsed `Requirement`'s marker is not kept (`lockfile.py:89-110`), and
`inventory_entries` has no marker column (`store.py:153-177`; `ENTRY_FIELDS`, `store.py:446-465`).
The spec's edge case (`lockfile.py:4` mentions markers in the lock syntax only) assumed otherwise.

**Superseded (issue #28)**: `LockEntry.marker` and a nullable `inventory_entries.marker` column now
record each lock entry's marker (the empty string for none); see data-model.md, Issue #28.

**Decision**: Q1. Under the recommendation, every `package_advisory` view lists, among its limitations,
"this inventory does not record environment markers, so it cannot say whether the package is installed
where the model runs", and among not-established statements "whether `{package}` is installed where
the model runs".

## R6. Statements: established, not established, limitations (FR-009 to FR-011, FR-013)

**Finding** (*confirmed*): each alert's evidence rows carry `source`, `url`, `retrieved_at`,
`matched_identifier`, the body hashes and `redacted_fields` (`reports.py:36-46`, `66-67`;
`store.alert_evidence`, `store.py:1945-1950`). An excepted alert links the exception's evidence row
(source `exception`, feature 004). Imported claims and their verification come from
`trust.claim_verification(entry, version_origin, checks)` (`assurance/trust.py:126-152`) with
`store.claim_checks(model_id, version)` (`store.py:1536`).

**Decision**:

- **Established**: one statement per evidence row of the alert, in `evidence_id` order, of the form
  "`<source>` reported `<matched_identifier>` at `<retrieved_at>` (`<url>`)", citing that row's id,
  plus, for a `withdrawn` or `cleared` alert, the closing row stated as "the source withdrew or cleared
  the cause". An exception's evidence row is not an established fact about the dependency; it is shown
  in the owner-decision block and cited from there (R7). No statement is built from the cause alone.
  Redacted fields are listed on the statement ("redacted: …"), as `evidence_line` does
  (`reports.py:229-238`).
- **Not established**: `rule-texts.toml` `not_established` of the rule, first item always "whether this
  alert affects model `{model_id}`"; then, by condition: the entry is `unresolved`; the version is an
  `import`; the entry is a hub weight file ("no local scan read this file; the hub's own verdict is
  the source"); the version has a `weight_file_absent` watch event for the file ("the bytes were not
  read in this place"); a package (Q1).
- **Limitations**: the rule's `limitations` text, unchanged.
- **Claims**: every claim of the resolved entry in the current (or last holding) version with its
  verification; `unverified` and `contradicted` are shown with that state and never as established
  (FR-013, D6).

## R7. The owner-decision block (FR-012)

**Decision**: present when the alert is `dismissed` or `excepted` (view state, `reports.py:56-63`),
otherwise `null`. A dismissal shows `{type: dismissal, by: dismissed_by, at: closed_at, reason, note}`.
An exception shows one item per excepted global from `cause.excepted` (`global`, `exception_id`,
`accepted_by`, `recorded_at`, `expires_on`; feature 004 data-model), plus the exception's `reason`
from `store.get_exception` (`store.py:1222`). The block never sets or changes `impact`.

## R8. Read-only and the store's open (FR-002, SC-004)

**Finding** (*confirmed*): `Store.__init__` runs the schema script and the open-time migrations
(`store.py:662-687`); `Store.open_read_only` opens with `mode=ro` and refuses a schema older than
feature 002 (`store.py:631-660`). Today's `alerts` and `alert show` use the writing open (`cli.py:546`).

**Decision**: Q2. Under the recommendation the view functions take an open `Store` and use only its
reading methods; T015 asserts `store.conn.total_changes` is unchanged across a view build and that the
database file and the evidence directory are byte-identical after `alert show --advice` and
`alerts --advice` on a current-schema database.

## R9. The CLI baseline (FR-016, SC-002)

**Finding** (*confirmed*): feature 004 recorded its equivalence baseline with
`tools/record_equivalence_baseline.py` and `tests/fixtures/equivalence/scenarios.py`, offline, with a
fixed clock and the scenario directory normalised to `<work>`.

**Decision**: `tests/fixtures/cli_baseline/scenarios.py` builds one store from recorded answers and
runs a named invocation list, text and `--json` each: `alerts ID` with each `--state` (`open`,
`excepted`, `closed`, `all`), `alert show` for one alert of each state (open, excepted, dismissed,
fixed, withdrawn or cleared), `history ID`, `run show RUN_ID`, `check ID` and `check ID --fail-on HIGH`
(the last two run in copies of the store so the read invocations see a fixed state).
`tools/record_cli_baseline.py` records stdout, stderr and the exit code of each invocation to
`tests/fixtures/cli_baseline/pre-010-baseline.json`, together with the commit and the `git rev-parse
HEAD:src` tree hash it was recorded from. It records from the build before this feature, as FR-016
says, not from a fixed commit: the `main` commit that 010's first `src/` pull request is based on. At
planning time that is `47ebfbe`, whose `src` tree is `4ca0c708b930870cbf5bce02b3f2ef20f4797882` (last
`src/` commit `0e927e6`). The recorder refuses to run unless `git status --porcelain -- src` is empty and
`git rev-parse HEAD:src` equals the expected tree it is given (and, when the file exists, the tree already
in it); it writes the commit and the tree into the file. `tests/integration/test_cli_baseline.py` asserts
the recorded tree, pins the SHA-256 of `pre-010-baseline.json` (a re-record fails the suite until the pin
is updated, an owner decision) and replays the list byte for byte. Feature 004's T005 recorded the commit
and the `src` tree equality the same way.

**Ordering with 011**: 010 lands first (plan, "Overlap with feature 011"), so the baseline holds
base-model scenarios as they are before 011; when 011 changes their output, 011 re-records the file and
its pin.

A replay test passes on arrival by design (the build has not moved yet). To show it can fail, T007
also records in `validation.md` one deliberate mutation (a changed character in `alert_line`) that the
test catches, then reverts it.

## R10. The verdict guard (FR-011, SC-003)

**Decision**: `tests/fixtures/advice/verdicts.json` lists phrases, each with the FR-011 clause it
guards, matched case-insensitively as substrings in the text view and in every string of the JSON view:
for example "is compromised", "rights are lost", "rights are kept", "is safe", "safe to load",
"was never affected", "not affected", "no impact", "inventory is complete", "model is clean",
"clean result". The
view's own fixed sentences (impact, `unknown` runtime use, the empty-model note) are written to pass it;
the test runs over one view per rule ID and every state (SC-003). Adding a phrase is a test change, so
the list is versioned with the code.

**Finding** (*confirmed*): the rule pages already use some of these phrases in negated form, for example
"is safe" in `docs/rules/MDB101.md:13` and "clean result" in `docs/rules/MDB102.md:13`, both inside a
"does not prove" or "not a" sentence. Copied verbatim into `limitations` (R4), they would trip a plain
substring guard. A grep of all 12 pages for the phrases above finds exactly these two (*confirmed*).
**Decision** (review R5): no negation heuristic. `verdicts.json` carries an `allowed` list of exact
sentences, each with its rule ID and field: the MDB101 `limitations` sentence at `docs/rules/MDB101.md:13`
and the MDB102 `limitations` sentence at `docs/rules/MDB102.md:13`, verbatim. The guard removes each
allowed sentence, by exact content, from every string of the view, wherever it appears (in `limitations`,
or in the `closes` text embedded in the last review step after `How this alert closes:`), and then fails on
any phrase left. Any other occurrence fails, in the view and in `rule-texts.toml` alike; adding an allowed
sentence is a reviewed change to the fixture.

The empty-model note reads: "No alert is open for this model. That is not an assessment of the model or
of how complete its inventory is."

# Quickstart: validating feature 011

**Feature**: [spec.md](spec.md) | **Plan**: [plan.md](plan.md)

Every scenario runs offline: hub answers come from recorded fixtures (`tests/fixtures/hf_upstream/`,
`tests/fixtures/hf/`), and the suite blocks sockets (`tests/conftest.py`). The manifests below are written
by the tasks into `tests/fixtures/lineage/`.

## 0. Set-up for the manual scenarios

```bash
export S=$(mktemp -d)
export MD="uv run model-dependabot --db $S/md.db"
export L=tests/fixtures/lineage
```

## 1. The automated suite

```bash
uv run pytest -q
uv run ruff check && uv run ruff format --check
```

Record the pass count at T005, on the `main` feature 010 leaves, and after the last task (no pipe; read
the real exit code).

## 2. Several typed parents (User Story 1)

```bash
$MD register $L/merge-two.toml          # two merged-from hub parents, each with a commit
$MD inventory show example-merge         # 2 base_model entries; Lineage (2 edges), origin manifest, owner
$MD register $L/adapter-no-revision.toml # exit 0; gap "no revision" on the adapter-for edge
$MD register $L/bad-relationship.toml    # exit 1; names parents[0] and the four types
$MD register $L/both-forms.toml          # exit 1; "use either [base_model] or [[parents]], not both"
```

Expected: the first two succeed with the stated edges; the last two exit 1 and record nothing.

## 3. Legacy `[base_model]` is unchanged (SC-001)

```bash
uv run pytest tests/integration/test_lineage_equivalence.py -q
```

Compares every legacy scenario with `tests/fixtures/equivalence/pre-011-baseline.json` on entry
identifiers, gaps, cause keys, alert count, states and severities, watch event kinds and exit codes.

## 4. CycloneDX round trip (User Story 2)

```bash
$MD register $L/four-types.toml                       # one parent of each type, one a registered model
$MD inventory export example-four -o $S/four.json
$MD import $S/four.json --model-id example-four-copy
$MD inventory audit example-four-copy                  # 4 edges, origin import, unverified, claimed origin manifest
$MD import $L/third-party-two-untyped.json --model-id example-third
$MD inventory audit example-third                      # 2 edges, relationship unspecified, origin import
```

`tests/contract/test_inventory_profile_lineage.py` validates each export against the official 1.7 schema.

## 5. Findings along edges (User Story 3), integration tests

```bash
uv run pytest tests/integration/test_lineage_propagation.py -q
```

Covers: a disabled `merged-from` parent raises one `base_model_disabled` alert citing the edge; two pins of
one repository give one alert naming both edges; a registered parent's weight-file alert reaches an
`adapter-for` child as a `lineage_inherited` watch event and not a `quantized-from` child; a
grandparent's finding is transitive with the full path; an `unspecified` edge passes only the all-yes rows.

## 6. Graph problems (User Story 4)

```bash
$MD register $L/cycle-a.toml                    # parent example-cycle-b v1: gap "parent not registered"
$MD register $L/cycle-b.toml                    # parent example-cycle-a v1 resolves: cycle formed
$MD inventory audit example-cycle-a             # problem cycle: example-cycle-a v1 -> example-cycle-b v1 -> example-cycle-a v1
$MD check example-cycle-a --source picklescan   # exit 0; the cycle listed; no watch event
```

`--source picklescan` reads nothing over the network for these models. A check with `--source hf-hub`
of a model with hub parents asks huggingface.co; run it only where the network is meant to be used,
or through `cli.main` with a recorded fetcher, as `validation.md` records.

## 7. Discovery and audit (User Story 5)

```bash
$MD discover tests/fixtures/projects/card-two-merge -o $S/proposed.toml
grep -n 'parents\|relationship' $S/proposed.toml   # two commented [[parents]] blocks, merged-from
```

Expected: no "several base models" gap; each candidate `declared-but-unverified` with the gap "no revision".

## 8. The constitution amendment (T001)

```bash
grep -n 'derived from\|Version' .specify/memory/constitution.md
```

Expected: the preamble names "the models it was derived from by fine-tuning, adaptation, merging or
quantisation" and the footer reads version 1.1.0.

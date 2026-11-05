# Quickstart: validating feature 003

Run from the repository root after `uv sync`. Everything here runs offline against recorded answers and
fixture projects unless marked live. Shapes: [contracts/cli.md](contracts/cli.md),
[data-model.md](data-model.md).

## 1. The automated suite

```bash
uv run pytest -q                       # offline; includes every scenario below
uv run ruff check && uv run ruff format --check
```

Expected: all tests pass with no network access.

## 2. An imported code-free claim cannot hide a pickle (User Story 1)

The fixtures hold `tests/fixtures/boms/forged-code-free.json` (a BOM whose only code-free weight is a pickle
named `model.safetensors`, hosted on the hub at a pinned commit) and the recorded hub answers for it in
`tests/fixtures/format_check/`. The integration test `tests/integration/test_claim_trust.py` performs:

```bash
model-dependabot import forged-code-free.json --model-id forged
model-dependabot policy forged --format strict --by owner
model-dependabot check forged --source format-check,hf-scan
model-dependabot alerts forged --json
model-dependabot inventory audit forged --json
```

Expected:

- `check` reports `format-check: ok` and a `format_claim_contradicted` watch event for `model.safetensors`
  (header shows a pickle);
- a `format_policy` alert is open for each code-capable file, its cause lists the contradicted claim and
  the rule "imported code-free claims count only once confirmed";
- the audit shows the entry as `conflicting`.

With the honest fixture `tests/fixtures/boms/confirmed-code-free.json` the same steps record a
`confirmed` claim check, no `format_policy` alert and the entry `verified`.

## 3. Old imports are re-marked (FR-005)

`tests/integration/test_claim_trust_legacy.py::test_legacy_import` opens a database written before this feature
(`tests/fixtures/db/legacy-import.db`, built by the test from a pre-003 schema), with a strict-policy model
whose imported code-free claim silenced the alert. After one `check` in which `format-check` fails
(recorded 503, exit code 2), the `format_policy` alert is open and names the rule. A manifest-registered
model in the same database keeps exactly its earlier alerts (FR-007).

## 4. Audit after a clean check (User Story 2)

`tests/integration/test_audit.py` performs, with recorded answers in which one source fails:

```bash
model-dependabot register tests/fixtures/manifests/example.toml
model-dependabot inventory audit example-detector-v1          # never checked
model-dependabot check example-detector-v1                     # one source fails (recorded)
model-dependabot inventory audit example-detector-v1 --json
```

Expected: before the check, findings say `not_yet_checked`; after it, the summary counts the gaps and the
failed source next to zero alerts, the statement is present, and `undeclared_kinds` lists any kind the
manifest lacks. The database file's SHA-256 is the same before and after each audit.

## 5. Discovery, offline (User Story 3)

```bash
model-dependabot discover tests/fixtures/projects/detector --json
model-dependabot discover tests/fixtures/projects/detector \
  --manifest tests/fixtures/projects/detector/model.toml -o /tmp/proposed.toml
model-dependabot register /tmp/proposed.toml --model-id proposed-check
```

Expected:

- packages from `requirements.lock.txt` are `declared-but-unverified` with hashes; `pyproject.toml`
  dependencies carry the gap `not locked`;
- `best.safetensors` (a pickle) is `verified` with `format: pickle`;
- the base model from `README.md` has the gap `no revision` and, with the manifest, `conflicts`;
- `link-out` (a symbolic link to `/etc`) and `../outside.txt` are under `skipped` as `outside the project`;
- `uv.lock` is skipped as `lock format not read in this version`;
- no request is made (the test fails on any network use), and every project file's hash and modification
  time is unchanged;
- `/tmp/proposed.toml` loads as a manifest; registering it records only the weight file and the lock, not
  the base model or datasets; a second `-o` to the same path without `--force` exits 1.

## 6. Discovery with hub lookups (User Story 4)

`tests/integration/test_discover_upstream.py` replays recorded hub model and dataset info:

Expected: the base model gets `proposed_revision` with the label "head at observation time, not
established as the training revision"; a refused dataset is `unavailable` with the reason; exit code 0.

## 7. Live checks (marked `live`, not in the default run)

```bash
uv run pytest -m live -k "format_check or discover"
```

Confirms that the hub answers a ranged `GET` on a `resolve` URL with `206` and `Content-Range`, through
its redirect, for one public safetensors file at a pinned commit (research A4).

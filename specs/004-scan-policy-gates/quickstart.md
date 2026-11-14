# Quickstart: validating feature 004

Run from the repository root after `uv sync`. Everything here runs offline: the weight files are
pickle opcode bytes built by `tests/fixtures/pickles/craft.py` into a scratch folder and only ever
disassembled by the scanner, never loaded. Shapes: [contracts/cli.md](contracts/cli.md),
[data-model.md](data-model.md). Each scenario names the integration test that performs it.

## 0. Set-up for the manual scenarios

```bash
export S="$(mktemp -d)"                       # outside the repository
export MD="uv run model-dependabot --db $S/md.db"
mkdir -p "$S/a" "$S/b" "$S/c"
# craft.py gains mixed(), protocol2_getattr(), two_dangerous() and unresolved() in this feature (research S12)
uv run python - <<'EOF'
import sys; sys.path.insert(0, "tests/fixtures/pickles")
import craft, os
S = os.environ["S"]
open(f"{S}/a/pose.pkl", "wb").write(craft.protocol2_getattr())
open(f"{S}/b/pose.pkl", "wb").write(craft.protocol2_getattr() + b"\x00")   # same globals, other bytes
open(f"{S}/c/mixed.pkl", "wb").write(craft.mixed())
EOF
for d in a b c; do
  f=$(ls $S/$d/*.pkl)
  printf '[model]\nid = "model-%s"\n\n[[weights]]\npath = "%s"\n' "$d" "$(basename "$f")" > $S/$d/model.toml
  $MD register $S/$d/model.toml
done
```

The trailing byte in `$S/b` lies after the pickle's `STOP`, so the scan of that file is incomplete;
scenario 2 excepts only `model-a`'s hash, and scenario 5 uses `model-b` as the incomplete case.

## 1. The automated suite

```bash
uv run pytest -q
uv run ruff check && uv run ruff format --check
```

Expected: all tests pass with no network access, including the registry test (every alert kind has one
rule ID and one page with the four headings; no ID in `tests/fixtures/rules/assigned.json` changed
meaning).

## 2. An exception covers one global in one exact file (User Story 1)

`tests/integration/test_exceptions.py`:

```bash
$MD check model-a --source picklescan
$MD check model-b --source picklescan
$MD alerts model-a --json        # a weight_file_scan alert (MDB101) for __builtin__.getattr
SHA=$(sha256sum "$S/a/pose.pkl" | cut -d' ' -f1)
$MD exception record --global __builtin__.getattr --sha256 "$SHA" --reason "reviewed" --by Owner
$MD check --all --source picklescan
$MD alerts model-a --json
$MD alerts model-b --json
$MD exception list --json
```

Expected:

- `model-a`: the alert is under `excepted` with `state: "excepted"`, its cause lists the exception and
  its evidence includes `exception:1`; `alerts` is empty (SC-001: 0 open);
- `model-b` (same global, other bytes): the alert is still under `alerts` (SC-001: 1 open);
- `exception list` shows exception 1 applying to `model-a` v1, in use.

Then:

```bash
cp $S/a/pose.pkl $S/c/again.pkl
printf '[model]\nid = "model-d"\n\n[[weights]]\npath = "again.pkl"\n' > $S/c/d.toml
$MD register $S/c/d.toml && $MD check model-d --source picklescan
$MD alerts model-d --json                      # excepted too: same bytes, other model
$MD exception revoke 1 --reason "re-review pending" --by Owner
$MD check --all --source picklescan
$MD alerts model-a --json                      # open again, same alert id, release recorded
$MD exception record --global __builtin__.getattr --sha256 "$SHA" --by Owner           # exit 1: no reason
$MD exception record --global __builtin__.getattr --sha256 "$SHA" --reason r --by Owner --expires 2020-01-01   # exit 1
```

An expiry passing between checks is tested with a fixed clock (`Store(now=...)`) in the same test file.

## 3. The strict globals policy (User Story 2)

`tests/integration/test_globals_policy.py`, on `model-c` (`collections.OrderedDict`, a fixture layer
class, `os.system`):

```bash
$MD policy model-c --globals strict --by Owner
$MD check model-c --source picklescan
$MD alerts model-c --json
```

Expected: one `weight_file_scan` alert (MDB101, HIGH) for `os.system`; one `globals_policy` alert (MDB104,
MODERATE) whose `unlisted` is `["model_dependabot_fixture.layers.CustomLayer", "os.system"]` (the
dangerous global is listed too, research D3) and which cites the file's SHA-256, `safe_list_version`
and the policy's `set_by` and `set_at`; nothing for `collections.OrderedDict`.

```bash
SHA_C=$(sha256sum "$S/c/mixed.pkl" | cut -d' ' -f1)
$MD exception record --global os.system --sha256 "$SHA_C" --reason "fixture" --by Owner
$MD check model-c --source picklescan
$MD alerts model-c --json
```

Expected: the `weight_file_scan` alert is under `excepted`; the `globals_policy` alert is still open
with `unlisted` `["model_dependabot_fixture.layers.CustomLayer"]` and `os.system` under `excepted`. One
exception covered both.

```bash
$MD policy model-c --globals default --by Owner
$MD check model-c --source picklescan
$MD history model-c --json      # the globals_policy alert cleared, cause "policy", the policy record as evidence
```

The same test covers: an exception for the layer class as well empties `unlisted` and closes the alert
with cause `exception` at that next check; a
safe list fixture with a higher version listing it closes it with cause `safe_list`; an incomplete scan
under strict keeps the file not clean and still records `scan_incomplete`.

## 4. Default policy changes nothing (SC-002, FR-007)

`tests/integration/test_default_equivalence.py` replays every weight-checking scenario of
`tests/integration/test_check_weights.py` and `tests/integration/test_register_from_record.py` and
asserts that the alerts and watch events equal `tests/fixtures/equivalence/pre-004-baseline.json`,
recorded once from the pre-004 build, row for row, and that every scanned file has a `file_scans` row
(research S10). A scenario with a `pathlib.PosixPath` global still gives a `scan_suspicious` watch event
and no alert.

## 5. The check overview (User Story 3), integration test only

The four-state run needs recorded answers for `osv`, `hf-scan` and `crossref`, which the manual set-up
of section 0 does not have, so this scenario runs only as `tests/integration/test_overview.py`. It
builds one run in which `osv` answers with nothing found, `hf-scan` raises an alert (recorded unsafe
verdict), `picklescan` meets an incomplete scan and `crossref` answers 503 (recorded), then calls
`run show` with the run id that `check` printed.

Expected: rows `passed`, `alerted`, `incomplete` and `failed` (with its reason) for those four sources,
with the counts of [contracts/cli.md](contracts/cli.md); exit code 2; `run show` prints the same
overview; a registered model with only an unpinned weight file reads `checked: false` with its reason.

The manual part: `$MD check --all --source picklescan --json` prints a run id `N`; `$MD run show N`
prints the same overview, with `picklescan` `incomplete` for `model-b`.

## 6. Rule IDs (User Story 4)

```bash
$MD alerts model-c
ls docs/rules/
```

Expected: each alert line shows its rule ID after the alert id (`#2 MDB104 MODERATE open …`); one page
per ID in `docs/rules/`, plus `README.md`; `uv run pytest tests/unit/test_rules.py` passes.

## 7. The gate (User Story 5)

`tests/contract/test_exit_codes.py` and `tests/integration/test_gate.py`. `model-a`'s scan is complete
and its HIGH `getattr` alert is open again after scenario 2's revocation; `model-b`'s scan is
incomplete:

```bash
$MD check model-a --source picklescan; echo $?                      # 0
$MD check model-a --source picklescan --fail-on CRITICAL; echo $?   # 0
$MD check model-a --source picklescan --fail-on high; echo $?       # 4, the alert listed under gate
$MD check model-a --source picklescan --fail-on SEVERE; echo $?     # 1
$MD check model-b --source picklescan --fail-on CRITICAL; echo $?   # 4: picklescan incomplete (FR-021)
$MD check model-a --source osv --fail-on CRITICAL --json; echo $?   # 4: model-a unchecked by osv (FR-021)
```

The exit 2 case (a failed source beats the gate) needs a recorded 503 and runs only in
`tests/contract/test_exit_codes.py`, as does an empty scope (`check --all --fail-on HIGH` on an empty
database exits 4 with `gate.empty_scope: true`).

Then record an exception for `__builtin__.getattr` on `model-a`'s hash and check again with
`--fail-on HIGH`: exit 0.

Held dismissal (FR-020, research S13), `tests/integration/test_dismissal_holds.py`, after revoking that
exception:

```bash
$MD check model-a --source picklescan                                  # the alert is open again
$MD alert dismiss ALERT_ID --reason risk_accepted --by Owner
$MD check model-a --source picklescan --fail-on HIGH --json; echo $?   # 0; ALERT_ID under dismissals_held
$MD alerts model-a --state all --json                                  # no new alert for the cause
```

The same test repeats the hold for an OSV package alert with an unchanged recorded record, for an
upstream alert with an unchanged recorded answer and for a `hub_scan` alert whose recorded hub answer
differs only in `downloads`, `likes` and `lastModified`. Then it gives a cause new evidence: a recorded
OSV record for the dismissed advisory with changed content opens a new alert whose cause has `reopens`
naming the dismissed one, and `--fail-on HIGH` exits 4. For a weight file the same bytes give the same
report, so only another scanner version (a recorded scan with another `scanner_version`) reopens it;
other bytes are another cause with its own key. Every row of the README exit-code table, run without
`--fail-on`, returns the same code as before this feature (SC-005).

## 8. Real-file acceptance check (T036)

Run once on 2026-11-14 on two real checkpoints supplied by the maintainer in an isolated folder outside
the repository: a pose-detection checkpoint (about 6 MB) and a change-detection checkpoint (about
300 MB). Neither file was loaded: each was scanned only through
`model_dependabot.sources.pickle_scan.scan_path` (static disassembly), and each was registered from a
manifest in a scratch folder outside the repository, with a database there. No copy, name or hash of
either file is kept in the repository.

```bash
$MD register SCRATCH/pose/model.toml
$MD policy pose --globals strict --by Owner
$MD check pose --source picklescan
$MD exception record --global __builtin__:getattr --sha256 HEX --reason "reviewed: attribute lookup" --by Owner
$MD check pose --source picklescan
# the same five commands for the change-detection checkpoint
```

Every command exited 0. What the static scans reported, and what the check showed (safe list version 1,
30 entries):

| | Pose detection | Change detection |
| :-- | :-- | :-- |
| globals reported (complete scan) | 31: 1 dangerous, 25 suspicious, 5 innocuous | 11: 1 dangerous, 3 suspicious, 7 innocuous |
| dangerous global | `__builtin__.getattr` | `__builtin__.getattr` |
| safe-listed globals seen | 8, among them `__builtin__.set`, `torch.Size` and `torch._utils._rebuild_parameter` | 9, among them `_codecs.encode` and `numpy.core.multiarray.scalar` |
| `weight_file_scan` alert before the exception | open (HIGH) | open (HIGH) |
| `globals_policy` unlisted before the exception | 23 | 2 |
| `weight_file_scan` alert after the exception | excepted | excepted |
| `globals_policy` unlisted after the exception | 22: framework layer and model classes | 1: a training framework's logging class |

Outcome: as expected. The exception for `__builtin__.getattr` in each file's hash made the HIGH alert
excepted and took the global off the `globals_policy` alert; no safe-listed global appeared in either
alert's list; the remaining framework classes stayed listed, as the strict policy intends. The safe-listed
globals the task names (`__builtin__.set`, `torch.Size`, `torch._utils._rebuild_parameter`,
`_codecs.encode`, `numpy.core.multiarray.scalar`) were each seen in one of the two files and were absent
from both lists.

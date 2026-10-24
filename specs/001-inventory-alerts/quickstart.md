# Quickstart: validating feature 001

Runnable checks that prove the feature end to end. Commands assume the repository root and a uv
environment; the [CLI contract](contracts/cli.md) defines every command.

## Prerequisites

- Python 3.12 and uv.
- `uv sync` (installs the tool and its test dependencies).

## 1. Offline test suite (no network)

```bash
uv run pytest
```

Expected: all tests pass with network access disabled; feed adapters run against recorded responses in
`tests/fixtures/` (constitution V).

## 2. Register the worked example

Write a [manifest](contracts/manifest.md) for a fine-tuned detector (weight files, a hash-locked lock
file, a pinned base-model revision, a dataset DOI), then:

```bash
uv run model-dependabot register example.toml
uv run model-dependabot inventory show example-detector-v1
uv run model-dependabot inventory export example-detector-v1 -o bom.json
```

Expected: every pinned item appears with its identifier and every gap with a reason (US1, SC-001);
`bom.json` validates against the CycloneDX 1.7 schema, and re-importing it gives the same entries (SC-005).

## 3. Package advisories

Register a manifest whose lock pins a package version with a known published advisory (for example an
old Pillow release), then run a check:

```bash
uv run model-dependabot check example-detector-v1
uv run model-dependabot alerts example-detector-v1 --json
```

Expected: one open alert per matching advisory, with severity, fixed version and evidence (US2, SC-002,
SC-003); an unaffected version produces no alert.

## 4. Weight files

Register a model with a PyTorch `.pt` checkpoint and an `.onnx` export. Expected: a `pickle_format`
watch event for the `.pt` file only, no alert unless the scan finds dangerous globals (US3). The test
suite covers the dangerous case with a crafted pickle fixture that is never loaded.

## 5. Auto-close

Register version 2 with the vulnerable package upgraded past the fixed version, then list the alerts
without running a check:

```bash
uv run model-dependabot register example-v2.toml --model-id example-detector-v1
uv run model-dependabot alerts example-detector-v1 --state all
```

Expected: the alert shows `fixed`, closed by version 2, straight after registration; no source is
consulted (US4, FR-014, SC-004).

## 6. Source failure

Run a check with a source unreachable (the test suite simulates this). Expected: exit code 2, and no
alert changes state (SC-007).

## 7. Scheduling

Run `uv run model-dependabot check --all` daily from the host scheduler:

- Linux: a cron line such as `15 2 * * * cd /srv/model-dependabot && uv run model-dependabot check --all`.
- Linux with systemd: a `model-dependabot.service` unit with `WorkingDirectory=/srv/model-dependabot`
  and `ExecStart=uv run model-dependabot check --all`, plus a `model-dependabot.timer` unit with
  `OnCalendar=*-*-* 02:15:00` and `Persistent=true`, enabled with `systemctl enable --now
  model-dependabot.timer`.
- Windows: a Task Scheduler task with the same command.

A daily run meets SC-006: an advisory published after one run is matched at the next, within one
scheduled interval, and an owner can run `check` at any time (FR-006).

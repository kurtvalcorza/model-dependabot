# model-dependabot

Dependency alerts for AI models. You describe a model in a small manifest; the tool records a pinned
inventory of what the model depends on (its weight files, the packages locked in its environment, the
base model it was fine-tuned from and its training data) and then checks that inventory against
published advisories and weight-file scans. It also watches what happens upstream: a training dataset or
a paper tied to it being retracted or removed, a licence changing and the base model being disabled or
no longer publicly available. When something it depends on becomes vulnerable, unsafe or unavailable it
raises an alert, and it closes the alert when a new version of the model fixes the cause or the source
withdraws or clears it.

It only reads. It never changes, deletes, retrains, re-exports or unpublishes a model or a file, and it
never writes to a model's repository (see [What it never does](#what-it-never-does)).

## Install

You need Python 3.12 or later and [uv](https://docs.astral.sh/uv/).

```bash
git clone <this repository> model-dependabot
cd model-dependabot
uv sync
uv run model-dependabot --help
```

`uv sync` creates a virtual environment in `.venv` with the pinned dependencies from `uv.lock`
(`packaging`, `jsonschema`, `picklescan` and `cvss`) and the test tools.

## The manifest

A model is registered from a TOML manifest. Paths are resolved relative to the manifest file.

```toml
[model]
id = "example-detector"            # required
name = "Example detector"
owner = "Model owner"

[[weights]]
path = "weights/best.pt"           # a local file: the tool hashes it

[[weights]]
hub = "hf:owner/model-repo"        # a file on the Hugging Face Hub
revision = "0123abcd..."           # the exact commit; without it the file is a gap
file = "model.safetensors"

[environment]
lock = "requirements.lock.txt"     # name==version lines with --hash options

[base_model]
hub = "hf:owner/base-model"
revision = "0123abcd..."

[[datasets]]
doi = "10.5555/example-dataset"
sha256 = "..."                     # optional
paper_doi = ["10.5555/example-paper"]   # optional: papers you tie to this dataset

[[datasets]]
hub = "hf:datasets/owner/name"     # a dataset on the Hugging Face Hub, without a DOI
revision = "0123abcd..."           # the exact commit; without it the dataset is a gap
```

A dataset has either `doi` or `hub`, not both. `paper_doi` lists the papers you say the dataset comes
with; they are checked for retractions too and are never guessed. Licences are not written in the
manifest: `register` records the licence each source declares for the base model and each dataset.

Only `model.id` is required. Anything missing or inexact is recorded as a gap with a reason (a hub file
without a revision, a lock line without `==` or without a hash) and registration still succeeds.
Unknown keys are an error, so a typo cannot silently drop a dependency. A hash-locked lock file can be
produced with `uv export --format requirements-txt` or `pip-compile --generate-hashes`. Environment
markers (`; sys_platform == "win32"` and the like) are not evaluated: every locked package is checked,
so a platform-only package can raise an alert even where it is never installed.

The full rules are in [`specs/001-inventory-alerts/contracts/manifest.md`](specs/001-inventory-alerts/contracts/manifest.md)
and, for `paper_doi` and hub datasets, [`specs/002-upstream-watch/contracts/manifest.md`](specs/002-upstream-watch/contracts/manifest.md).

## Commands

Every command takes `--db PATH` (default `./model-dependabot.db`) and `--json` for machine-readable
output; both may go before or after the command name.

| Command | What it does |
| :-- | :-- |
| `register MANIFEST.toml [--model-id ID]` | Registers a model, or with `--model-id` a new version of it. Hashes local files, pins hub files to their commit and records gaps. A new version re-evaluates the previous version's open alerts straight away: alerts whose cause is gone close as `fixed`, the rest carry forward |
| `import BOM.json --model-id ID` | Registers a version from an existing CycloneDX inventory |
| `inventory show ID [--version N]` | Lists the entries with their identifiers and the gaps with their reasons |
| `inventory export ID [--version N] -o FILE` | Writes the stored CycloneDX 1.7 inventory, validated against the official schema |
| `check (ID \| --all) [--scheduled] [--source ...]` | Runs the checks now and records a check run. Sources: `osv`, `picklescan`, `hf-scan`, `hf-hub`, `hf-takedowns`, `crossref`, `datacite`, `zenodo` and `figshare`; without `--source` every source runs. `--scheduled` (with `--all`) marks the run as scheduled; see [Scheduling](#scheduling) |
| `policy ID --format (default\|strict) --by NAME` | Sets the model's weight-format policy, recording who set it and when. Under `default` a format that can run code when loaded is a watch event; under `strict` a code-capable weight file with no code-free file beside it in the same version raises an alert. Takes effect at the next check |
| `alerts ID [--state open\|closed\|all]` | Lists alerts by severity (`CRITICAL`, `HIGH`, `MODERATE`, `LOW`, `UNKNOWN`), then the watch events, each with its evidence |
| `alert show ALERT_ID` | One alert with all its evidence; for a redacted response, both hashes and the fields removed |
| `alert dismiss ALERT_ID --reason REASON [--note TEXT] --by NAME` | Dismisses an alert; `REASON` is `not_used_at_runtime`, `risk_accepted`, `false_positive` or `fix_not_available` |
| `history ID` | Closed alerts with how they closed (`fixed`, `dismissed`, `withdrawn` or `cleared`), when and on what evidence |

Watch events are things worth knowing that are not alerts: a weight file in a format that can run code,
a scan that could not finish, a hub file whose hash no longer matches what was registered, a new revision
of the base model, a newer version of a dataset, a licence that cannot be recognised. They never turn
into alerts by repetition.

A package alert needs OSV's match and a local evaluation of the same OSV record to agree. The local
evaluation is a consistency check, not a second source: when the two disagree, or the record's ranges
cannot be read, the result is a watch event that says which. The hub's scan verdict describes the
repository's head commit; for a file pinned at another revision the head file's hash is compared with
the pinned one before a clean result is accepted.

### Upstream checks

| Alert | Raised when | Severity |
| :-- | :-- | :-- |
| `dataset_retracted` | Crossref lists a retraction, withdrawal or removal for the dataset DOI | `HIGH` |
| `paper_retracted` | The same for a paper tied to the dataset with `paper_doi` | `HIGH` |
| `dataset_removed` | Zenodo answers 410 with a tombstone, or the hub reports the dataset disabled | `HIGH` |
| `dataset_not_findable` | DataCite answers 404 for a DOI registered with DataCite | `HIGH` |
| `licence_changed` | The set of licences a source declares, normalised and in any order, differs from the recorded set | `HIGH` |
| `base_model_disabled` | The hub reports the base model disabled | `MODERATE` |
| `base_model_unavailable` | The hub has refused the base model in scheduled checks spanning at least 24 hours | `LOW` |

These severities are set by policy, and the alerts say so (`severity_origin: "policy"`). A retraction,
licence, disabled or unavailable alert closes as `cleared` when the source that reported it no longer shows
the cause in a successful, well-formed answer; a licence alert needs every source that reported the change
to answer so, and a source that failed or was not asked keeps it open. `withdrawn` is used only for an
OSV advisory marked withdrawn. Any of them closes as `fixed` when a new version no longer depends on the
item. A disabled or unavailable base model and a disabled hub dataset are states of the repository, and
a base model's or hub dataset's licence and a paper tied to a hub dataset are read for the repository, so
pinning another revision of the same repository keeps the alert open; an entry missing its pin (a gap)
never counts as a fix.

Licences are normalised against the SPDX licence list and exceptions list, version 3.29.0, vendored in
[`src/model_dependabot/licences/`](src/model_dependabot/licences/README.md) with their SHA-256 and a short
table of repository spellings. A spelling or case difference raises nothing; a licence that cannot be
recognised is a watch event, never an alert.

A first session:

```bash
uv run model-dependabot register model.toml
uv run model-dependabot inventory show example-detector
uv run model-dependabot check example-detector
uv run model-dependabot alerts example-detector
uv run model-dependabot alert show 1
```

The JSON shapes are in [`specs/001-inventory-alerts/contracts/cli.md`](specs/001-inventory-alerts/contracts/cli.md)
and [`specs/002-upstream-watch/contracts/cli.md`](specs/002-upstream-watch/contracts/cli.md).

### Exit codes

| Code | Meaning |
| :-- | :-- |
| 0 | Success. For `check`: the check completed, whether or not it found anything |
| 1 | Invalid input (manifest, inventory or arguments) |
| 2 | `check` finished but at least one source failed; alerts that depend on it were left unchanged |
| 3 | Unexpected error |

`check` never exits non-zero just because alerts exist, so a scheduler does not mistake findings for
failures. Scripts read the `--json` output instead.

## Scheduling

Run `check --all --scheduled` once a day; a new advisory or retraction then shows up as an alert within a
day. `--scheduled` supersedes feature 001's plain `check --all` for the scheduler: only scheduled runs count
towards the rule that a base model refused for at least 24 hours is no longer publicly available, so a
host already running `check --all` must add `--scheduled`. A plain `check --all` still runs every check
and records the run as on demand. Use absolute paths,
because schedulers do not start in the repository. The examples assume the repository is at
`/opt/model-dependabot` (or `C:\model-dependabot`) and the database at `/var/lib/model-dependabot/md.db`
(or `C:\model-dependabot\md.db`).

### cron

```cron
# m h dom mon dow  command
15 6 * * *  cd /opt/model-dependabot && uv run model-dependabot check --all --scheduled --db /var/lib/model-dependabot/md.db --json >> /var/log/model-dependabot.log 2>&1
```

### systemd timer

`/etc/systemd/system/model-dependabot.service`:

```ini
[Unit]
Description=model-dependabot daily check

[Service]
Type=oneshot
WorkingDirectory=/opt/model-dependabot
ExecStart=/usr/local/bin/uv run model-dependabot check --all --scheduled --db /var/lib/model-dependabot/md.db --json
```

`/etc/systemd/system/model-dependabot.timer`:

```ini
[Unit]
Description=Run model-dependabot once a day

[Timer]
OnCalendar=*-*-* 06:15:00
Persistent=true

[Install]
WantedBy=timers.target
```

Then `systemctl daemon-reload && systemctl enable --now model-dependabot.timer`. The output goes to the
journal (`journalctl -u model-dependabot`). Exit code 2 marks the run as failed in `systemctl status`,
which is what you want when a source could not be reached.

### Windows Task Scheduler

From PowerShell:

```powershell
$action = New-ScheduledTaskAction -Execute "uv.exe" `
    -Argument "run model-dependabot check --all --scheduled --db C:\model-dependabot\md.db --json" `
    -WorkingDirectory "C:\model-dependabot"
$trigger = New-ScheduledTaskTrigger -Daily -At 6:15am
Register-ScheduledTask -TaskName "model-dependabot" -Action $action -Trigger $trigger
```

The task's "Last Run Result" shows the exit code (0, 1, 2 or 3 as above).

## Sources

All requests are anonymous: no account, no token and no personal data. The User-Agent is the generic
`model-dependabot/<version>`, and the tool refuses a User-Agent that carries an email address. Requests
have timeouts, back off and retry on `429` and `5xx`, honour `Retry-After` and stay within each source's
published limits.

| Source | Used for | Requests |
| :-- | :-- | :-- |
| [OSV.dev](https://osv.dev) | Advisories for the locked PyPI packages | `POST /v1/querybatch` (a read-only query) and `GET /v1/vulns/{id}` |
| [Hugging Face Hub API](https://huggingface.co/docs/hub/api) | Pinning hub files and base models to a commit; the hub's own security scan of hosted weight files; whether the base model and hub datasets are disabled, gated, moved or refused, their licence and newest revision | `GET /api/models/...` and `GET /api/datasets/...` only |
| [Hub takedown log](https://huggingface.co/datasets/huggingface-legal/takedown-notices) | The notice date of a takedown naming a hub dataset (a notice date, not a removal date) | `GET` of the public `index.csv` |
| [doi.org](https://www.doi.org/) | Which agency registered each DOI | `GET /doiRA/{doi}` |
| [Crossref](https://www.crossref.org/documentation/retrieve-metadata/rest-api/) | Retractions, withdrawals, corrections and expressions of concern for Crossref DOIs | `GET /works/{doi}` |
| [DataCite](https://support.datacite.org/docs/api) | Whether a DataCite DOI is findable, its licences, newer versions and replacements | `GET /dois/{doi}` |
| [Zenodo](https://developers.zenodo.org/) | Removed records (410 with a tombstone), licences and newer versions | `GET /api/records/{id}` |
| [Figshare](https://docs.figshare.com/) | An article's licence, or that it is gone | `GET /v2/articles/{id}` |
| [picklescan](https://github.com/mmaitre314/picklescan) | Scanning local pickle-based weight files for dangerous imports | None: runs locally and never loads the file |

Severity comes from the advisory's own rating, else from its CVSS v3 or v4 vector (scored with the
`cvss` package), else `UNKNOWN`; the alert says which. A source that fails in a run is recorded as failed
and cannot open, change or close any alert in that run.

## The evidence store

Every alert and watch event links to its evidence: the source, the URL, when it was retrieved, the exact
identifier matched (for example `pkg:pypi/pillow@12.3.0` or `sha256:...`) and the SHA-256 of the raw
response. The database is one SQLite file (`--db`); the raw responses are kept as files in an `evidence/`
folder beside it, each named by its SHA-256, so any alert can be traced back to exactly what a source
said at the time. A recorded model version and its inventory are immutable. Back up the database and the
`evidence/` folder together.

Personal data is removed before a response is stored: the takedown log keeps only `date` and
`reported_content` (never the requesting party or the notice's file name), and the names of people in
Zenodo, Figshare, Crossref and DataCite answers (creators, contributors, authors, owners, citation text,
who removed a record) are dropped. Such evidence keeps the SHA-256 of the response as received
(`original_sha256`) beside the hash of the stored copy (`body_sha256`) and lists the fields removed
(`redacted_fields`), so it stays checkable.

## What it never does

- It never changes, deletes, retrains, re-exports or unpublishes a model or any file, and never writes
  to a model's repository. Registering and checking leave every weight file, the manifest and the lock
  file byte-for-byte unchanged (a test checks their SHA-256 and modification times).
- It never sends `PUT`, `PATCH` or `DELETE`. The only `POST` is OSV's read-only query.
- It never loads a weight file to inspect it: pickles are scanned as data, without running them.
- It never sends a token, an account name or personal data to a source; every upstream request is a
  `GET` or `HEAD`.
- It never stores the requesting party of a takedown or the names of people in a source's answer.
- It never guesses: a paper is checked only when you tie it to a dataset, a licence it cannot recognise
  is a watch event, and a base model is called unavailable only after scheduled refusals spanning 24 hours.
- It never closes an alert because a source failed to answer; missing data leaves alerts as they were.

The only files it writes are its own database, its `evidence/` folder and, when asked, the file named by
`inventory export -o`.

## Development

```bash
uv run pytest            # the offline suite; the network is blocked in tests
uv run pytest -m live    # a few smoke tests against the real sources
uv run ruff check
```

Tests run against recorded source responses in `tests/fixtures/`; `tools/record_fixtures.py` re-records
them. The live tests are left out of the default run.

## Background

- [`research/landscape.md`](research/landscape.md): the existing tools, standards and data feeds, each
  checked against primary sources.
- [`specs/001-inventory-alerts/`](specs/001-inventory-alerts/): the specification, plan, data model,
  contracts and validation record for this first feature.
- [`specs/002-upstream-watch/`](specs/002-upstream-watch/): the same for the upstream watch of base models
  and training datasets.

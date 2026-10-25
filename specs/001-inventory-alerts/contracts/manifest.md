# Contract: model manifest (registration input)

A small TOML file an owner writes or a training pipeline generates. The service reads it with Python's
built-in `tomllib` and computes every hash itself; values in the manifest are inputs, not trusted facts.

```toml
[model]
id = "example-detector-v1"
name = "Example object detector"
owner = "Model owner"

[[weights]]
path = "runs/train/best.pt"            # local file: hashed by the service

[[weights]]
hub = "hf:owner/model-repo"                 # a file on a model hub
revision = "0123abcd…"                       # exact commit; required for a pinned entry
file = "best.pt"

[environment]
lock = "requirements.lock.txt"       # hash-locked: name==version with --hash lines

[base_model]
hub = "hf:example-org/example-base-model"
revision = "0123456789abcdef0123456789abcdef01234567"

[[datasets]]
doi = "10.5281/zenodo.1234567"
sha256 = "0000000000000000000000000000000000000000000000000000000000000000"   # optional
```

## Rules

- `model.id` is required; everything else is optional, and anything missing or inexact becomes a gap with
  a reason (FR-003). Registration never fails because of a gap.
- A hub weight file without `revision` is a gap ("no revision"): its bytes could change.
- Lock entries are pinned only with `==` and at least one `--hash` (research R10).
- Unknown keys are an error (exit code 1), so typos do not silently drop dependencies.
- Paths are resolved relative to the manifest file.
- A local weight file must exist when the manifest is registered with `register` or recorded with
  `record`. With `register --from-record` it need not: its hash, format and scan come from the
  [registration record](registration-record.md), which must name the manifest's local weight files by
  their `path` exactly as written here, in the same order.

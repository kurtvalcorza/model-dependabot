# Contract: model manifest (registration input)

A small TOML file an owner writes or a training pipeline generates. The service reads it with Python's
built-in `tomllib` and computes every hash itself; values in the manifest are inputs, not trusted facts.

```toml
[model]
id = "rice-pest-r50-v5"
name = "Rice pest detector, RT-DETR r50 v5"
owner = "Model owner"

[[weights]]
path = "runs/run-r50v5/best.pt"            # local file: hashed by the service

[[weights]]
hub = "hf:owner/model-repo"                 # a file on a model hub
revision = "0123abcd…"                       # exact commit; required for a pinned entry
file = "best.pt"

[environment]
lock = "requirements-kaggle.lock.txt"       # hash-locked: name==version with --hash lines

[base_model]
hub = "hf:PekingU/rtdetr_r50vd"
revision = "df939e661d8c52e80608d1ec566561aabd25a4e7"

[[datasets]]
doi = "10.5281/zenodo.20066074"
sha256 = "f4a0409977e0615e34f3cf2b936a5ca9dd3a91b153d239e314334ea40c2537f7"   # optional
```

## Rules

- `model.id` is required; everything else is optional, and anything missing or inexact becomes a gap with
  a reason (FR-003). Registration never fails because of a gap.
- A hub weight file without `revision` is a gap ("no revision"): its bytes could change.
- Lock entries are pinned only with `==` and at least one `--hash` (research R10).
- Unknown keys are an error (exit code 1), so typos do not silently drop dependencies.
- Paths are resolved relative to the manifest file.

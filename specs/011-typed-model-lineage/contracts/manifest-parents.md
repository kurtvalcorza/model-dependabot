# Contract: the manifest's parent list (feature 011)

Extends `specs/001-inventory-alerts/contracts/manifest.md` (its `[base_model]` example at lines 23-25).
Parsed by `src/model_dependabot/manifest.py` (`load_manifest`, the `[base_model]` block at `:205-213`).

## Form

```toml
[[parents]]
hub = "hf:example-org/base-a"
revision = "0123456789abcdef0123456789abcdef01234567"
relationship = "merged-from"

[[parents]]
hub = "hf:example-org/base-b"
revision = "89abcdef0123456789abcdef0123456789abcdef"
relationship = "merged-from"

[[parents]]
model = "example-adapter-base"   # a model id registered in the same store
version = 2
relationship = "adapter-for"
```

| Key | Required | Value |
| :-- | :-- | :-- |
| `relationship` | yes | `fine-tuned-from`, `adapter-for`, `merged-from` or `quantized-from` |
| `hub` | one of `hub`, `model` | an `hf:owner/name` reference, as `[base_model].hub` |
| `revision` | no (with `hub`) | the exact commit; without it the gap "no revision", a non-commit "revision is not a commit" |
| `model` | one of `hub`, `model` | a registered model id |
| `version` | no (with `model`) | a positive integer; without it the gap "no version" |

## Rules

- `[base_model]` keeps its keys `hub` and `revision` and its behaviour (FR-003). It takes no
  `relationship`; its edge is `unspecified`. An owner who wants a type moves to `[[parents]]`.
- `[base_model]` and `[[parents]]` in one manifest: exit 1, message
  `use either [base_model] or [[parents]], not both`.
- A `relationship` outside the four types, `unspecified` included: exit 1, message
  `parents[<i>].relationship must be one of fine-tuned-from, adapter-for, merged-from, quantized-from`.
- A parent with both `hub` and `model`, or neither: exit 1, message
  `parents[<i>] needs exactly one of hub and model`.
- `revision` with `model`, or `version` with `hub`: exit 1 as an unknown combination
  (`parents[<i>].version needs model`; `parents[<i>].revision needs hub`).
- `version` that is not a positive integer: exit 1.
- Unknown keys in a `[[parents]]` table: exit 1, as everywhere in the manifest (`manifest.py:78-84`).
- A gap never fails registration (feature 001, FR-003).
- The same parent and type twice: one edge, problem `duplicate_parent`. The same parent under two types:
  two edges, problem `ambiguous_relationship`. A `model` reference that is not registered: gap
  `parent not registered`, resolved at each later check and audit. None of these fails registration.
- A registration record (feature 005) carries no lineage of its own: the parents are read from the
  manifest it is checked against, and their origin is `record`.

## Register output (text, additions)

```text
Registered example-merge v1
Entries (2):
  base_model   pkg:huggingface/example-org/base-a@0123…  example-org/base-a==0123…
  base_model   pkg:huggingface/example-org/base-b@89ab…  example-org/base-b==89ab…
Gaps (0):
Lineage (3 edges):
  merged-from      hf:example-org/base-a@0123…  origin manifest, owner
  merged-from      hf:example-org/base-b@89ab…  origin manifest, owner
  adapter-for      model:example-adapter-base@2  origin manifest, owner  [parent not registered]
Lineage problems (0):
```

The JSON payload gains `lineage: {edges: [...], problems: [...]}` with the audit's shapes
(contracts/edge-evidence.md). A legacy `[base_model]` manifest's `entries` and `gaps` are byte-identical
to today's; only the `lineage` key is new (FR-003 allows it).

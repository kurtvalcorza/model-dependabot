# Contract: CycloneDX ancestors with lineage (feature 011)

Extends `specs/001-inventory-alerts/contracts/inventory-profile.md` (the base model row at line 11 and
the property table at lines 19-25; FR-013 completes it with the rows below). Written by `export_bom`
and read by `import_bom` in `src/model_dependabot/inventory/cyclonedx.py` (`:272`, `:557`).

## Ancestor forms

One `metadata.component.pedigree.ancestors[]` component per edge, `type: "machine-learning-model"`,
`bom-ref: "base-model:<n + k>"` (k the edge's position, n the number of weight-file and package entries;
research L4).

A hub parent (as today, plus properties):

```json
{
  "type": "machine-learning-model",
  "bom-ref": "base-model:3",
  "name": "example-org/base-a",
  "version": "0123456789abcdef0123456789abcdef01234567",
  "purl": "pkg:huggingface/example-org/base-a@0123456789abcdef0123456789abcdef01234567",
  "properties": [
    {"name": "model-dependabot:relationship", "value": "merged-from"},
    {"name": "model-dependabot:edge-origin", "value": "manifest"}
  ]
}
```

A registered-model parent (no purl; FR-010a):

```json
{
  "type": "machine-learning-model",
  "bom-ref": "base-model:4",
  "name": "example-adapter-base",
  "properties": [
    {"name": "model-dependabot:parent-model", "value": "example-adapter-base"},
    {"name": "model-dependabot:parent-version", "value": "2"},
    {"name": "model-dependabot:relationship", "value": "adapter-for"},
    {"name": "model-dependabot:edge-origin", "value": "manifest"}
  ]
}
```

## New properties

| Property | On | Value |
| :-- | :-- | :-- |
| `model-dependabot:relationship` | every ancestor | `fine-tuned-from`, `adapter-for`, `merged-from`, `quantized-from` or `unspecified` |
| `model-dependabot:relationship-recorded` | ancestor whose imported relationship was unrecognised | the original value, kept as evidence (FR-012) |
| `model-dependabot:edge-origin` | every ancestor | `manifest`, `record` or `import`: the edge's origin in the exporting store |
| `model-dependabot:claimed-origin` | ancestor of an imported edge | the `edge-origin` the imported document stated, if any |
| `model-dependabot:parent-model` | registered-model ancestor | the parent's model id |
| `model-dependabot:parent-version` | registered-model ancestor | the parent's version, a decimal string |

Existing `model-dependabot:gap` is unchanged and carries the edge's gap. All are added to `PROPERTIES`
(`cyclonedx.py:68`).

## Import rules

1. At most 256 ancestors are read; beyond that, one `base_model` gap entry
   `more than 256 ancestors; <N> not read` (research P2).
2. Every edge is origin `import`, state `unverified`, whatever `edge-origin` says; a stated
   `edge-origin` becomes `claimed_origin` (FR-007, FR-011, D6). Nothing imported carries state `owner`.
3. No `relationship` property: `unspecified`. A value outside the five: `unspecified`, with the value in
   `relationship_recorded` (FR-012).
4. `parent-model` with `parent-version`: a registered-model reference, resolved by id and version in the
   importing store; unresolvable is the gap `parent not registered`; resolved stays `unverified`, is shown
   "resolved by id and version only" and carries no finding (FR-010a). `parent-model` without
   `parent-version`: gap `no version`.
5. Neither a `pkg:huggingface` purl nor `parent-model`: today's gap `no Hugging Face purl`
   (`cyclonedx.py:467-468`).
6. A hub ancestor becomes a `base_model` entry exactly as `_import_base_model` makes it today
   (`cyclonedx.py:463-486`) plus an edge row; two ancestors with one purl give one entry and, with one
   type, one edge (`duplicate_parent`) or, with two, two edges (`ambiguous_relationship`).

## Round trips (SC-002)

- Export, import, export: parent references, revisions, types and gaps equal; `edge-origin` becomes
  `import` and the first export's origin appears as `claimed-origin`; bom-refs are reassigned by index.
- Import of a third-party document, export: parent references, revisions, gaps and recognised types
  equal; unrecognised types are written `unspecified` with `relationship-recorded`; no duplicate
  bom-ref, including one parent under two types and a self-reference.
- Every export validates against the official CycloneDX 1.7 schema (`cyclonedx.validate`, `:130`).

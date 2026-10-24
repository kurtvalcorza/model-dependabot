# Contract: inventory profile (additions, CycloneDX 1.7)

Feature 001's [inventory profile](../../001-inventory-alerts/contracts/inventory-profile.md) stands. This
feature uses only standard CycloneDX 1.7 fields for its additions (research U11), so it adds no
`model-dependabot:` property.

| Inventory fact | CycloneDX location |
| :-- | :-- |
| Recorded licence of the base model | `licenses` on the `pedigree.ancestors[]` component: `{"license": {"id": "<SPDX id>"}}`, `{"license": {"name": "<as declared>"}}` for an unrecognised licence, or `{"expression": "<SPDX expression>"}` |
| Recorded licence of a dataset | `licenses` on the dataset component, as above |
| Paper tied to a dataset | `externalReferences[]` on the dataset component: `{"type": "citation", "url": "https://doi.org/<doi>"}` |
| Hub-hosted dataset | a `components[]` entry like 001's DOI datasets: `type: "data"`, `bom-ref: "hf-dataset:<owner>/<name>@<commit>"`, `data: [{"type": "dataset"}]`, `externalReferences[]` `{"type": "distribution", "url": "https://huggingface.co/datasets/<owner>/<name>"}`; `metadata.component.modelCard.modelParameters.datasets[]` refers to it with `{"ref": "hf-dataset:<owner>/<name>@<commit>"}` (CycloneDX 1.7's inline `componentData` allows no `externalReferences`; see 001's inventory profile) |

Rules:

- Exports validate against the official `bom-1.7.schema.json` (001 rule).
- Round trip: `export` then `import` yields the same licences, paper ties and hub datasets.
- An imported inventory without `licenses` is valid; the first successful check then sets the baseline
  (research U8).

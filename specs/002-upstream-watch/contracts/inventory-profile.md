# Contract: inventory profile (additions, CycloneDX 1.7)

Feature 001's [inventory profile](../../001-inventory-alerts/contracts/inventory-profile.md) stands. This
feature uses only standard CycloneDX 1.7 fields for its additions (research U11), so it adds no
`model-dependabot:` property.

| Inventory fact | CycloneDX location |
| :-- | :-- |
| Recorded licence of the base model | `licenses` on the `pedigree.ancestors[]` component: `{"license": {"id": "<SPDX id>"}}`, `{"license": {"name": "<as declared>"}}` for an unrecognised licence, or `{"expression": "<SPDX expression>"}` |
| Recorded licence of a dataset | `licenses` on the dataset component, as above |
| Paper tied to a dataset | `externalReferences[]` on the dataset component: `{"type": "citation", "url": "https://doi.org/<doi>"}` |
| Hub-hosted dataset | `metadata.component.modelCard.modelParameters.datasets[]`, `type: "dataset"`, `bom-ref: "hf-dataset:<owner>/<name>@<commit>"`, `externalReferences[]` `{"type": "distribution", "url": "https://huggingface.co/datasets/<owner>/<name>"}` |

Rules:

- Exports validate against the official `bom-1.7.schema.json` (001 rule).
- Round trip: `export` then `import` yields the same licences, paper ties and hub datasets.
- An imported inventory without `licenses` is valid; the first successful check then sets the baseline
  (research U8).

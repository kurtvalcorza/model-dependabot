# Contract: inventory profile (CycloneDX 1.7)

How each inventory entry is written in a CycloneDX 1.7 JSON document ([research.md](../research.md) R1).
Exports are validated against the official `bom-1.7.schema.json`; imports are read with the same mapping.

| Inventory entry | CycloneDX location | Identifier |
| :-- | :-- | :-- |
| The model version | `metadata.component`, `type: "machine-learning-model"`, `version: "<n>"` | `bom-ref: "model:<id>@<n>"` |
| Weight file | `components[]`, `type: "file"`, `hashes: [{alg: "SHA-256", content}]`; format and `can_run_code` in `properties` | the SHA-256 |
| Package | `components[]`, `type: "library"`, `purl: "pkg:pypi/<name>@<version>"`, lock hashes in `hashes` | the purl |
| Base model | `metadata.component.pedigree.ancestors[]`, `type: "machine-learning-model"`, `purl: "pkg:huggingface/<owner>/<name>@<commit>"` | the purl |
| Dataset | `metadata.component.modelCard.modelParameters.datasets[]` (`type: "dataset"`), DOI in `externalReferences` and as `bom-ref: "doi:<doi>"`, optional SHA-256 in `hashes` | the DOI |
| Gap | the entry is written with what is known plus property `model-dependabot:gap = "<reason>"` | none |

Rules:

- Project-specific values use `properties` with the `model-dependabot:` prefix and are listed here; no
  other custom fields (constitution II).
- Round trip: `export` then `import` yields the same entries and identifiers (SC-005).
- Imported documents may be CycloneDX 1.5, 1.6 or 1.7; entries the mapping cannot read become gaps
  rather than errors.

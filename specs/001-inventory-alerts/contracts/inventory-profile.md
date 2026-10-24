# Contract: inventory profile (CycloneDX 1.7)

How each inventory entry is written in a CycloneDX 1.7 JSON document ([research.md](../research.md) R1).
Exports are validated against the official `bom-1.7.schema.json`; imports are read with the same mapping.

| Inventory entry | CycloneDX location | Identifier |
| :-- | :-- | :-- |
| The model version | `metadata.component`, `type: "machine-learning-model"`, `version: "<n>"` | `bom-ref: "model:<id>@<n>"` |
| Weight file | `components[]`, `type: "file"`, `name` (the path relative to the manifest, or the file's path in the hub repository), `hashes: [{alg: "SHA-256", content}]`; properties `model-dependabot:format`, `model-dependabot:can-run-code` and `model-dependabot:size`; a hub-hosted file also has `externalReferences[]` `type: "distribution"` with its download URL at the pinned revision, and properties `model-dependabot:hub-repo`, `model-dependabot:hub-revision` and `model-dependabot:hub-file` | the SHA-256 |
| Package | `components[]`, `type: "library"`, `purl: "pkg:pypi/<name>@<version>"`, lock hashes in `hashes` | the purl |
| Base model | `metadata.component.pedigree.ancestors[]`, `type: "machine-learning-model"`, `purl: "pkg:huggingface/<owner>/<name>@<commit>"` | the purl |
| Dataset | a `components[]` entry, `type: "data"`, `bom-ref: "doi:<doi>"`, `data: [{"type": "dataset"}]`, the DOI URL `https://doi.org/<doi>` as an `externalReferences` entry of type `distribution`, optional SHA-256 in `hashes`; `metadata.component.modelCard.modelParameters.datasets[]` refers to it with `{"ref": "doi:<doi>"}` (the inline `componentData` form allows neither `hashes` nor `externalReferences` in CycloneDX 1.7; import reads both forms) | the DOI |
| Gap | the entry is written with what is known plus property `model-dependabot:gap = "<reason>"` | none |

Custom properties (the complete list; constitution II):

| Property | On | Value |
| :-- | :-- | :-- |
| `model-dependabot:format` | weight file | The classified format, for example `pytorch-zip`, `pickle`, `joblib`, `safetensors`, `onnx` or `gguf` (research R4) |
| `model-dependabot:can-run-code` | weight file | `true` or `false` (FR-002) |
| `model-dependabot:size` | weight file | Size in bytes, as a decimal string (FR-002); CycloneDX has no file-size field |
| `model-dependabot:hub-repo` | hub-hosted weight file | The hub repository, `owner/name` |
| `model-dependabot:hub-revision` | hub-hosted weight file | The full commit the file is pinned to (the model-info `sha`, or `X-Repo-Commit` when a response carries one; research R5) |
| `model-dependabot:hub-file` | hub-hosted weight file | The file's path in the repository, the key for the hub scan verdict (research R5) |
| `model-dependabot:gap` | any entry | The gap reason (FR-003) |

Hub location is split this way because CycloneDX has no fields for a repository and revision on a
`file` component; the `distribution` external reference carries the same location as a URL for other
tools, and import reads the three properties first. The model's format policy (FR-021) is not part of
the inventory: it can change after registration and is stored with the model, not the version.

Rules:

- Project-specific values use `properties` with the `model-dependabot:` prefix and are listed above; no
  other custom fields (constitution II).
- Round trip: `export` then `import` yields the same entries and identifiers (SC-005).
- Imported documents may be CycloneDX 1.5, 1.6 or 1.7; entries the mapping cannot read become gaps
  rather than errors.

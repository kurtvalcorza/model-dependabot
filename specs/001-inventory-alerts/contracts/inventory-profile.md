# Contract: inventory profile (CycloneDX 1.7)

How each inventory entry is written in a CycloneDX 1.7 JSON document ([research.md](../research.md) R1).
Exports are validated against the official `bom-1.7.schema.json`; imports are read with the same mapping.

| Inventory entry | CycloneDX location | Identifier |
| :-- | :-- | :-- |
| The model version | `metadata.component`, `type: "machine-learning-model"`, `version: "<n>"` | `bom-ref: "model:<id>@<n>"` |
| Weight file | `components[]`, `type: "file"`, `name` (the path relative to the manifest, or the file's path in the hub repository), `hashes: [{alg: "SHA-256", content}]`; properties `model-dependabot:format`, `model-dependabot:can-run-code` and `model-dependabot:size`; a hub-hosted file also has `externalReferences[]` `type: "distribution"` with its download URL at the pinned revision, and properties `model-dependabot:hub-repo`, `model-dependabot:hub-revision` and `model-dependabot:hub-file` | the SHA-256 |
| Package | `components[]`, `type: "library"`, `purl: "pkg:pypi/<name>@<version>"`, lock hashes in `hashes`; property `model-dependabot:marker` when the lock marker is recorded (issue #34) | the purl |
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
| `model-dependabot:relationship` | every ancestor (feature 011) | `fine-tuned-from`, `adapter-for`, `merged-from`, `quantized-from` or `unspecified` |
| `model-dependabot:relationship-recorded` | ancestor whose imported relationship was unrecognised | The original value, kept as evidence |
| `model-dependabot:edge-origin` | every ancestor | `manifest`, `record` or `import`: the edge's origin in the exporting store |
| `model-dependabot:claimed-origin` | ancestor of an imported edge | The `edge-origin` the imported document stated, if any |
| `model-dependabot:parent-model` | ancestor naming a registered model | The parent's model id (the ancestor has no purl) |
| `model-dependabot:parent-version` | ancestor naming a registered model | The parent's version, a decimal string |
| `model-dependabot:marker` | package whose lock marker is recorded (issue #34) | The environment marker as stored (normalised by `packaging`), or `none` for a lock line with no marker. Absent when the marker is not recorded |

Hub location is split this way because CycloneDX has no fields for a repository and revision on a
`file` component; the `distribution` external reference carries the same location as a URL for other
tools, and import reads the three properties first. The model's format policy (FR-021) is not part of
the inventory: it can change after registration and is stored with the model, not the version.

Rules:

- Project-specific values use `properties` with the `model-dependabot:` prefix and are listed above; no
  other custom fields (constitution II).
- Round trip: `export` then `import` yields the same entries and identifiers (SC-005).
  A package's lock marker (issue #28) round-trips in each of its three states (issue #34): a
  marker is written as stored, a lock line with none as `none`, and a marker that is not recorded
  (null) writes no property. On import the value is a third party's: `none` reads as no marker
  (`""`), a value `packaging` reads as a marker is stored normalised, and anything else (an empty or
  missing value, `None`, text that is not a marker, a marker too deeply nested to parse) is not
  recorded (null), never no marker, and never fails the import. A marker the lock gave but
  `packaging` cannot read is stored as written; it is exported so, and a re-import reads it as not
  recorded. An imported entry with no readable marker property keeps the advisory view's
  limitation.
- Imported documents may be CycloneDX 1.5, 1.6 or 1.7; entries the mapping cannot read become gaps
  rather than errors.
- Two dataset components sharing one `bom-ref` are imported as one dataset entry, their hashes and
  paper DOIs joined, as a dataset listed twice in a manifest is (review F-03, 2026-11-03). An
  inventory that fails CycloneDX 1.7 validation on `register` or `import` is refused with exit code 1.
- A weight file whose `model-dependabot:format` and `model-dependabot:can-run-code` do not fit its file
  name is refused, not imported, as `register --from-record` refuses one ([registration
  record](registration-record.md)): the class must be the one the name gives, or `pytorch-zip` (only the
  bytes show a zip); a code-free name may also be `pickle` or `unknown`, which its bytes give a renamed
  pickle or zip. A document that claims a `.pt` file is `safetensors` would otherwise keep a
  code-capable file from ever being scanned. Amended 2026-10-31 after review (F8); the code-free
  allowance amended 2026-11-03 after review (F-02).

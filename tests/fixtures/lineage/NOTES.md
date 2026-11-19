# lineage fixtures (feature 011)

Written by hand for feature 011 (T003, T004); no source was asked. Repositories are
`example-org/*` with made-up 40-hex revisions: no hub answer is recorded for them, so a test that
checks one derives its answer from `hf_upstream/model-normal` (`derive_upstream`, `extra`). The
chain's grandparent names `sd-concepts-library/dyoudim-style`, whose recorded answer is
`hf_upstream/model-disabled`. The 300-ancestor document is built by the test that needs it.

Manifests:

- `merge-two.toml`: two merged-from hub parents in different repositories, each with a commit (US1 AS1)
- `adapter-no-revision.toml`: one adapter-for hub parent without a revision: the gap 'no revision' (US1 AS2)
- `bad-relationship.toml`: a relationship outside the four types: exit 1 (US1 AS4)
- `unspecified-relationship.toml`: the internal value 'unspecified' written in a manifest: exit 1 (FR-002)
- `both-forms.toml`: [base_model] and [[parents]] together: exit 1 (US1 AS5, FR-004)
- `hub-and-model.toml`: a parent with both hub and model: exit 1
- `four-types.toml`: one parent of each type; the adapter-for one is the registered model example-adapter-base v1 (SC-002)
- `duplicate.toml`: the same repository, revision and type twice: one edge, duplicate_parent (US4 AS2)
- `ambiguous.toml`: the same repository and revision under two types: ambiguous_relationship (US4 AS3)
- `same-repo-two-revisions.toml`: two revisions of one repository: two entries, one alert per cause (US3 AS2, FR-024)
- `cycle-a.toml`: example-cycle-a v1 fine-tuned from example-cycle-b v1
- `cycle-b.toml`: example-cycle-b v1 fine-tuned from example-cycle-a v1 and merged from example-cycle-c v1: with cycle-a a cycle of length 2, with cycle-a and cycle-c also one of length 3
- `cycle-c.toml`: example-cycle-c v1 fine-tuned from example-cycle-a v1 (closes the cycle of length 3)
- `self.toml`: example-self v1 fine-tuned from example-self v1: a cycle of length 1
- `same-model-v2.toml`: registered as version 2 of example-cont, fine-tuned from version 1: not a cycle (US4 AS6)
- `chain-grandparent.toml`: example-grand, fine-tuned from the hub model sd-concepts-library/dyoudim-style at bb36f39d9eede01cc139dc4fadd193f1e4879fe3, whose recorded answer (hf_upstream/model-disabled) is disabled
- `chain-parent.toml`: example-mid v1, fine-tuned from example-grand v1
- `chain-child.toml`: example-child v1, an adapter for example-mid v1
- `merge-one-parent.toml`: a merged-from model with one parent: the audit note 'merge with one parent'

CycloneDX 1.7 documents (imported with `--model-id`):

- `third-party-two-untyped.json`: two pkg:huggingface ancestors, no properties (US2 AS2)
- `same-purl-twice.json`: two ancestors with one purl, no properties: two entries, one edge declared twice
- `two-no-purl.json`: two ancestors without purl or parent-model: two gap entries and two edges (review R2)
- `unrecognised-type.json`: model-dependabot:relationship = distilled-from: unspecified, value kept (US2 AS3)
- `claims-manifest.json`: model-dependabot:edge-origin = manifest: origin import, claimed origin manifest (US2 AS4)
- `one-parent-two-types.json`: one purl under two types: two edges, ambiguous_relationship, unique bom-refs
- `self-reference.json`: an ancestor naming the document's own model id and version (example-self-bom v1)
- `registered-no-version.json`: a registered-model reference without parent-version: edge gap 'no version', no entry

# Contract: inventory profile additions (feature 003)

Extends [001's profile](../../001-inventory-alerts/contracts/inventory-profile.md) and
[002's](../../002-upstream-watch/contracts/inventory-profile.md).

## Export

One documented custom property on weight-file components, because CycloneDX has no field for where a
format classification came from (constitution II):

| Property | Values | Meaning |
| :-- | :-- | :-- |
| `model-dependabot:format-origin` | `bytes`, `name`, `record`, `import` | where `model-dependabot:format` and `model-dependabot:can-run-code` came from ([data-model.md](../data-model.md), Inventory entry) |

It is omitted for legacy entries, which have no recorded origin.

## Import

- `model-dependabot:format-origin` in an imported document is ignored: whatever it says, the claims of an
  imported weight component are stored with origin `import` (FR-002). A BOM exported by this tool and
  imported elsewhere is therefore a third-party claim there too.
- `model-dependabot:format` and `model-dependabot:can-run-code` are still read and still must fit the file
  name (`class_fits_name`, review F8). A code-free claim is stored as given but counts under the strict
  policy only once `format-check` confirms it.
- When the component's file is present locally, inside the document's directory, it is classified from its
  bytes at import (research A5): bytes win, the entry is stored with origin `bytes`, and a claim the bytes
  contradict is recorded as a `contradicted` claim check with both values as evidence.

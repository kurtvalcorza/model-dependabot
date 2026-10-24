# Vendored CycloneDX schemas

These JSON Schema files validate every inventory this tool exports (research R1). They are copied
unchanged from the CycloneDX specification repository.

| | |
| :-- | :-- |
| Repository | https://github.com/CycloneDX/specification |
| Tag | `1.7.2` |
| Commit | `349314a9d7671d7d2ca5b711a725f49a73979da6` |
| Source URL | `https://raw.githubusercontent.com/CycloneDX/specification/349314a9d7671d7d2ca5b711a725f49a73979da6/schema/<file>` |
| Retrieved | 2026-10-24 |
| Licence | Apache License 2.0, as stated in the repository's `LICENSE` file |

| File | `$id` |
| :-- | :-- |
| `bom-1.7.schema.json` | `http://cyclonedx.org/schema/bom-1.7.schema.json` |
| `spdx.schema.json` | `http://cyclonedx.org/schema/spdx.schema.json` |
| `jsf-0.82.schema.json` | `http://cyclonedx.org/schema/jsf-0.82.schema.json` |

SHA-256 hashes are in `SHA256SUMS`; check them with `sha256sum -c SHA256SUMS` from this directory.

`bom-1.7.schema.json` also refers to `cryptography-defs.schema.json` from two properties under
`cryptoProperties`. That file is not vendored: inventories written by this tool do not use
`cryptoProperties`, so validation never reaches those references.

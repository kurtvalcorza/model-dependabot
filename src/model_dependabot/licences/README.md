# Vendored SPDX licence list

`spdx-licenses-3.29.0.json` is the SPDX licence list in JSON, used to normalise declared licences
(research U8). It is vendored unchanged so the default test run needs no network.

| Fact | Value |
| :-- | :-- |
| Source URL | https://raw.githubusercontent.com/spdx/license-list-data/v3.29.0/json/licenses.json |
| Repository | https://github.com/spdx/license-list-data |
| Tag | `v3.29.0` |
| `licenseListVersion` | `3.29.0` |
| Release date | 2026-09-16 (`releaseDate` in the file: `2026-09-16T00:00:00Z`) |
| Licences | 740 entries in `licenses` (32 of them marked `isDeprecatedLicenseId`) |
| Size | 339,359 bytes |
| SHA-256 | `47d1cc681abe31166b342b6cc4aab13a6ba8ea5c48794697fe3bf8b1dbaf509a` (also in `SHA256SUMS`) |
| Downloaded | 2026-10-24, anonymously, with the generic User-Agent `model-dependabot/0.1.0` |

## SPDX exceptions list

`spdx-exceptions-3.29.0.json` is `json/exceptions.json` of the same tag, vendored unchanged and renamed
with its version like the licence list. `<licence> WITH <exception>` expressions are normalised against it,
matching exception identifiers ignoring case; an unknown exception leaves the expression unrecognised.

| Fact | Value |
| :-- | :-- |
| Source URL | https://raw.githubusercontent.com/spdx/license-list-data/v3.29.0/json/exceptions.json |
| `licenseListVersion` | `3.29.0` (`releaseDate` `2026-09-16T00:00:00Z`) |
| Exceptions | 86 entries in `exceptions` (1 of them marked `isDeprecatedLicenseId`) |
| Size | 41,420 bytes |
| SHA-256 | `59ee7c150de521d635cbf9367b8cf543b8da6781ea3ac1c073d305524f84ada2` (also in `SHA256SUMS`) |
| Downloaded | 2026-10-24, anonymously, with the generic User-Agent `model-dependabot/0.1.0` |

## Data licence, as the repository states it

The repository has no licence file at tag `v3.29.0`. Its `README.md` ("Licensing Information") says:

> Other than the README and related documentation, all data in this repository is generated. The source
> of the data is the [license list XML Repository](https://github.com/spdx/license-list-XML).
> [LicenseListPublisher](https://github.com/spdx/LicenseListPublisher) is the tool used to publish the
> data. Please see the respective repositories for licensing information.

So the data licence is the one of `spdx/license-list-XML`. GitHub's licence detection reports
`NOASSERTION` for that repository; its licence terms were not confirmed when this file was vendored.

## Checking

`upstream/licences.py` checks both files against `SHA256SUMS` when it loads the lists and refuses a file
that does not match. To update, download the new tag's `json/licenses.json` and `json/exceptions.json`,
rename them with the new version,
update `SHA256SUMS` and this table, and re-run the tests.

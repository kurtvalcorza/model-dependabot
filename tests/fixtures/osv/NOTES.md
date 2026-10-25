# OSV.dev fixtures

Recorded on 2026-10-24 (03:5x UTC) with `uv run python tools/record_fixtures.py osv`: anonymous, no
token, User-Agent `model-dependabot/0.1.0`. `POST /v1/querybatch` is the only POST; every other
request is a GET.

| Recording | Request | Notes |
| :-- | :-- | :-- |
| `querybatch-vulnerable` | `POST /v1/querybatch` for `pillow==12.3.0` and `validators==0.12.2` | Trimmed: OSV answered 41 advisories for pillow 12.3.0 and 2 for validators 0.12.2; only `GHSA-24rc-8hj2-v98c` and `GHSA-cp9v-662q-vvx9` were kept (the JSON was re-serialised compactly) |
| `querybatch-pillow-13.0.0` | `POST /v1/querybatch` for `pillow==13.0.0` | Byte-exact: no advisory |
| `vuln-GHSA-cp9v-662q-vvx9` | `GET /v1/vulns/GHSA-cp9v-662q-vvx9` | Byte-exact. Alias CVE-2026-112405; `database_specific.severity` HIGH; CVSS v4 vector; range introduced 12.0.0, fixed 13.0.0 |
| `vuln-GHSA-24rc-8hj2-v98c` | `GET /v1/vulns/GHSA-24rc-8hj2-v98c` | Byte-exact. Alias CVE-2026-96638; `database_specific.severity` MODERATE; CVSS v3.1 vector; range introduced 9.1.0, fixed 13.0.0 |
| `vuln-PYSEC-2019-64` | `GET /v1/vulns/PYSEC-2019-64` | Byte-exact. Withdrawn 2023-03-14T07:01:09.371407Z; validators, introduced 0.12.2, fixed 0.12.6; no severity |

How the versions were chosen: the live query on 2026-10-24 confirmed the suggested pair. `pillow==12.3.0`
is affected (41 advisories, every one with `fixed` 13.0.0) and `pillow==13.0.0` is unaffected (an empty
result).

How the withdrawn advisory was found: OSV has no search by withdrawal, so the PyPI export
`https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip` (downloaded the same day, not kept)
was read and its records with a `withdrawn` field listed (622 of them); PYSEC-2019-64 is the smallest
one with an ECOSYSTEM range. The live query for `validators==0.12.2` does **not** return it: OSV leaves
withdrawn records out of query answers. A withdrawal is therefore seen by fetching the advisory of an
open alert by its id, which the service does on every check.

The tests derive further states from these recordings in a temporary directory (an earlier state with
no advisory, the withdrawn record before its withdrawal, a record with a changed severity and fixed
version); each derivation is written out in the test that makes it. Only `content-type` is kept from
the response headers.

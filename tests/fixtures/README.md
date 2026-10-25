# Recorded responses

Every fixture here is a real response recorded by `tools/record_fixtures.py`, run by hand with anonymous
requests, the generic User-Agent and no token. The tests replay them through `RecordedFetcher`; the default
test run makes no network calls.

- Each response is a body file beside a `NAME.meta.json` sidecar that dates it (`retrieved_at`) and names the
  request (`method`, `url`), the status and the kept headers.
- Fixtures for the upstream sources (`crossref/`, `datacite/`, `zenodo/`, `figshare/`, `doi_ra/`,
  `hf_upstream/`, `hf_takedowns/`) are stored **redacted** (research U10): the fields that can name a person
  are removed before the body is written, and the sidecar keeps `original_sha256` (the response as received),
  `body_sha256` (the stored body) and `redacted_fields`.
- Every field that can name a person is removed by a U10 rule, never trimmed by hand. Anything else trimmed
  from a body the tests do not need is listed in the sidecar's `trimmed` and in the folder's `NOTES.md`,
  which also says how each identifier was found.

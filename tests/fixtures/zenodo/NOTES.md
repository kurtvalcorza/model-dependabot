# zenodo fixtures

Recorded 2026-10-24 by `tools/record_fixtures.py upstream`
(anonymous, generic User-Agent, no token, redacted per research U10).

- record-3242074: Zenodo record 3242074 (named in tasks T019)
- older-version: record 8176941, the first hit of `records?q=resource_type.type:dataset&all_versions=true&size=25&sort=mostviewed` whose `metadata.relations.version[0].is_last` is false ({"index": 3, "is_last": false, "parent": {"pid_type": "recid", "pid_value": "4417809"}}); `links.latest` is https://zenodo.org/api/records/8176941/versions/latest
- older-version-latest: GET https://zenodo.org/api/records/8176941/versions/latest answered HTTP 301 with `redirected_to` https://zenodo.org/api/records/18180184
- deleted: record 12584226, the first row with removal_reason 'duplicate' in the first 256 KiB of https://zenodo.org/api/exporter/biosyslit/records-deleted.csv.gz/6db8cb6a-f4ff-4a56-92c6-d400d000140e (listed by `GET /api/exporter`); the dump itself was not stored

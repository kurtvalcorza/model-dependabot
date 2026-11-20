# Database fixtures

`schema-pre-003.sql` is the store's `SCHEMA` as it was on `main` at `308e323`, before feature 003,
written out with `uv run python -c "from model_dependabot.store import SCHEMA; ..."` on 2026-11-13
before any 003 change was made. Tests build a database written by the tool before 003 from it
(`tests/unit/test_store_assurance_schema.py`, the legacy-import and audit tests), so the on-open
back-fill and the audit's read-only open are tested against the real old schema, not a guess.

`schema-pre-004.sql` is the store's `SCHEMA` as it was on `main` at `c07c14d`, before feature 004,
written out the same way on 2026-11-13 before any 004 code change, followed by a few rows the tool
could have written then: one model with one version and one pickle weight entry, one check run with
its target, one evidence row, an open `weight_file_scan` alert and a dismissed `format_policy` alert.
`tests/integration/test_migration_004.py` opens it to test the feature 004 upgrade.

`schema-pre-011.sql` is the store's `SCHEMA` as it was on `main` at `6e146c1`, before feature 011,
written out the same way on 2026-11-20 before any 011 code change, followed by rows the tool could
have written then: one model with version 1 (origin `manifest`) and version 2 (legacy, null origin),
each with one pinned `base_model` entry, one check run with its target, one evidence row, an open
`base_model_disabled` alert and one watch event. `tests/integration/test_migration_011.py` opens it
to test the feature 011 upgrade and the read-only synthesis of legacy edges.

`schema-pre-028.sql` is the store's `SCHEMA` as it was on `main` at `0c2a5ee`, before issue #28 (lock
markers), written out the same way on 2026-11-20 before any #28 code change, followed by rows the tool
could have written then: one model with an `import` version 1 and a `manifest` version 2, each holding
`pillow==9.0.0`, one check run with its target, one evidence row and an open `package_advisory` alert.
`tests/integration/test_migration_028.py` opens it to test the upgrade and a read-only open.

# Database fixtures

`schema-pre-003.sql` is the store's `SCHEMA` as it was on `main` at `308e323`, before feature 003,
written out with `uv run python -c "from model_dependabot.store import SCHEMA; ..."` on 2026-11-13
before any 003 change was made. Tests build a database written by the tool before 003 from it
(`tests/unit/test_store_assurance_schema.py`, the legacy-import and audit tests), so the on-open
back-fill and the audit's read-only open are tested against the real old schema, not a guess.

# Lock-file fixtures

- `uv-export-trimmed.txt`: generated on 2026-10-24 in this repository with
  `uv export --format requirements-txt --frozen` (uv-generated, hash-locked) and trimmed from 15 entries
  to 5 (`-e .`, `attrs`, `colorama`, `jsonschema`, `packaging`); the kept lines are byte-for-byte as
  uv wrote them.
- `hand-made-gaps.txt`: written by hand for the gap cases (no `==`, no hash, a wildcard version, an
  unnormalised name, spaces around `==`, a single-line hash, an option line). Its hashes are
  placeholders.

# Hugging Face fixtures

Recorded on 2026-10-24 (02:59 UTC) with `uv run python tools/record_fixtures.py hf`: anonymous, no
token, User-Agent `model-dependabot/0.1.0`. The repository `openai-community/gpt2` was at commit
`607a30d783dfa663caf39e06633721c8d4cfcd7e`, taken from the model-info `sha` field.

| Recording | Request | Notes |
| :-- | :-- | :-- |
| `gpt2-model-info` | `GET /api/models/openai-community/gpt2/revision/<commit>` | Trimmed: the `spaces`, `widgetData`, `cardData` and `transformersInfo` keys were removed and the JSON re-indented; every other key is as served |
| `gpt2-tree` | `GET /api/models/openai-community/gpt2/tree/<commit>` | Byte-exact, not trimmed (17 entries) |
| `missing-repo-tree` | `GET /api/models/model-dependabot-fixture/does-not-exist/tree/<commit>` | Byte-exact; the hub answers 401 for a repository that does not exist or is private |

Only `content-type`, `etag` and `x-repo-commit` headers are kept. Neither API response carried an
`X-Repo-Commit` header (all response header names were checked live on the same day), so the
revision of a hub file comes from the model-info `sha`; `X-Repo-Commit` is used when a response
has it.

## Security status (research R5)

Recorded on 2026-10-24 (04:24 UTC) with `uv run python tools/record_fixtures.py hf-scan`:
anonymous, no token, User-Agent `model-dependabot/0.1.0`. Byte-exact, not trimmed.

| Recording | Request | Notes |
| :-- | :-- | :-- |
| `eicar-security` | `GET /api/models/mcpotato/42-eicar-street?securityStatus=true` | A public test repository for the hub's scanners, at commit `8fb61c4d511e9aaff0ea55396a124aa292830efc`; real `unsafe` verdicts for `model_broken_X.pkl`, `danger.dat` and `eicar_test_file`, `caution` for `build_pickles.py`; `pytorch_model.bin` is not listed (clean) |
| `eicar-tree-expand` | `GET /api/models/mcpotato/42-eicar-street/tree/<commit>?expand=true` | Each file's `securityFileStatus` (per-scanner results) and, for LFS files, `lfs.oid` |
| `gpt2-security` | `GET /api/models/openai-community/gpt2?securityStatus=true` | A real clean answer: `scansDone` true, no `filesWithIssues` |

Only metadata is recorded; no file of the test repository is downloaded. The files with real
`unsafe` verdicts are outside LFS, so the hub gives no SHA-256 for them and a verdict for them can
never match an inventory hash. The unsafe verdict for a file whose SHA-256 matches
(`pytorch_model.bin`, LFS, `f9343d7d…0e20`), and the pending, missing, unrecognised, caution and
mismatched answers, are derived from these recordings in each test by the `derive_hf` fixture
(`tests/conftest.py`), like `derive_osv`. That fixture also derives the plain tree and revision
answers that registering a file of this repository needs.

The `expand=true` tree answer is not stable: on the same day one anonymous request returned the
entries without `securityFileStatus` (only `lastCommit`), and a repeat returned it. The adapter
then reports no per-scanner results, and the verdict still comes from `securityRepoStatus`.

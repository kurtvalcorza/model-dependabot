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

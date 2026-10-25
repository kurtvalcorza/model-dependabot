# hf_takedowns fixtures

Recorded 2026-10-24 by `tools/record_fixtures.py upstream`
(anonymous, generic User-Agent, no token, redacted per research U10).

- index-redirect: https://huggingface.co/datasets/huggingface-legal/takedown-notices/resolve/main/index.csv answers 307 to the target
- index: the redirect target, recorded at its own URL https://huggingface.co/api/resolve-cache/datasets/huggingface-legal/takedown-notices/ab924c52c724af95331ee579af0cb12afacdebad/index.csv?%2Fdatasets%2Fhuggingface-legal%2Ftakedown-notices%2Fresolve%2Fmain%2Findex.csv=&etag=%22acebe0c6427ff86f743a2a0989b8dfe384afce47%22
- index: 67 data rows; columns ['date', 'reported_content'] (`requesting_entity` and `file` removed by the
  U10 rule; re-derived on 2026-10-24 from the stored recording, with no new download)

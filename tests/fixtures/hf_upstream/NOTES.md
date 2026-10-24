# hf_upstream fixtures

Recorded 2026-10-24 by `tools/record_fixtures.py upstream`
(anonymous, generic User-Agent, no token, redacted per research U10).

- model-normal: openai-community/gpt2
- model-gated: meta-llama/Llama-3.1-8B
- model-missing: model-dependabot-fixture/does-not-exist
- dataset-disabled: yavon/muxue (HTTP 200)
- dataset-missing: model-dependabot-fixture/does-not-exist (HTTP 401)
- dataset-moved: the_pile_books3 (HTTP 307)
- dataset-moved-target: https://huggingface.co/api/datasets/defunct-datasets/the_pile_books3?expand[]=disabled&expand[]=gated&expand[]=private&expand[]=cardData&expand[]=sha (HTTP 200)
- disabled-model search: 51 model-like paths in index.csv
- model-disabled: sd-concepts-library/dyoudim-style, a model path from index.csv; answers 200 with disabled: true

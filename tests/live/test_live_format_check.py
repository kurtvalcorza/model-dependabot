"""Live check of the ranged hub read that ``format-check`` relies on (T010, research A4).

The hub must answer a ranged ``GET`` of a ``resolve`` URL with ``206`` and ``Content-Range``,
through its redirect to a storage host that the SEC-02 redirect rules accept. Marked ``live``:

    uv run pytest -m live -k format_check

If this fails, research A4 no longer holds: record it and revise the research before changing
the adapter. The recordings in ``tests/fixtures/format_check`` come from
``tools/record_fixtures.py format-check``.
"""

from __future__ import annotations

import pytest

from model_dependabot.inventory.build import classify_lead
from model_dependabot.sources.fetcher import UrlFetcher, _content_range

pytestmark = pytest.mark.live

GPT2 = "openai-community/gpt2"
GPT2_COMMIT = "607a30d783dfa663caf39e06633721c8d4cfcd7e"
LEAD = 1 << 20
SIZE = 548_105_171  # the tree's lfs.size for model.safetensors at that commit


def test_the_hub_answers_a_ranged_read_with_206_after_its_redirect() -> None:
    url = f"https://huggingface.co/{GPT2}/resolve/{GPT2_COMMIT}/model.safetensors"
    response = UrlFetcher().get_range(url, LEAD)
    assert response.status == 206
    assert response.redirected_from == url  # followed under the SEC-02 rules
    assert len(response.body) == LEAD
    assert _content_range(response.headers.get("Content-Range")) == (0, LEAD - 1, SIZE)
    assert classify_lead("model.safetensors", response.body, SIZE) == ("safetensors", False)

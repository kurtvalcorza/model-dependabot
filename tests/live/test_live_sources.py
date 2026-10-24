"""Live smoke tests: one request to OSV.dev and one to the Hugging Face API (T052).

They catch a change in a source's answer format that the recorded fixtures cannot. They use the
network, anonymously and with the generic User-Agent of ``UrlFetcher`` only, so they are marked
``live`` and left out of the default run (``addopts = "-m 'not live'"``). Run them on purpose:

    uv run pytest -m live

A failure here means a source changed; record it and re-record the fixtures with
``tools/record_fixtures.py`` rather than editing them by hand.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from model_dependabot.sources.fetcher import DEFAULT_USER_AGENT, UrlFetcher
from model_dependabot.sources.hf import HuggingFace
from model_dependabot.sources.osv import OsvClient

pytestmark = pytest.mark.live

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
PILLOW = "pkg:pypi/pillow@12.3.0"
GPT2 = "openai-community/gpt2"
GPT2_COMMIT = "607a30d783dfa663caf39e06633721c8d4cfcd7e"


def test_user_agent_is_generic() -> None:
    assert DEFAULT_USER_AGENT.startswith("model-dependabot/")
    assert "@" not in DEFAULT_USER_AGENT


def test_osv_querybatch_answers_in_the_recorded_format() -> None:
    entry = {
        "kind": "package",
        "pinned": True,
        "name": "pillow",
        "version": "12.3.0",
        "identifier": PILLOW,
    }
    answer = OsvClient(UrlFetcher()).query([entry])
    assert answer.response is not None
    assert answer.response.status == 200
    recorded = json.loads((FIXTURES / "osv" / "querybatch-vulnerable.json").read_text("utf-8"))
    recorded_ids = {vuln["id"] for vuln in recorded["results"][0]["vulns"]}
    # Advisories are added over time, rarely removed: the recorded ones must still be listed.
    assert recorded_ids <= set(answer.matches[PILLOW])


def test_hub_tree_at_a_pinned_commit_matches_the_recording() -> None:
    result = HuggingFace(UrlFetcher()).tree(GPT2, GPT2_COMMIT)
    assert result.gap_reason is None
    recorded = json.loads((FIXTURES / "hf" / "gpt2-tree.json").read_text("utf-8"))
    weights = next(item for item in recorded if item["path"] == "model.safetensors")
    live = result.files["model.safetensors"]
    assert live.sha256 == weights["lfs"]["oid"]
    assert live.size == weights["lfs"]["size"]
    assert set(result.files) == {item["path"] for item in recorded if item["type"] == "file"}

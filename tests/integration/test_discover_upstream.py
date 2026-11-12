"""Discovery with hub lookups (T049; US4, quickstart section 6, FR-021, research A11).

The hub's answers are the recordings in ``tests/fixtures/hf_upstream``: the detector card names
``openai-community/gpt2`` (``model-normal``), ``yavon/muxue`` (``dataset-disabled``, HTTP 200) and
``model-dependabot-fixture/does-not-exist`` (``dataset-missing``, HTTP 401).
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from model_dependabot.cli import EXIT_OK, main, make_handlers
from model_dependabot.sources import hf
from model_dependabot.sources.fetcher import RecordedFetcher, Response

NOW = datetime(2026, 11, 13, 9, 0, tzinfo=UTC)
GPT2 = "openai-community/gpt2"
GPT2_SHA = "607a30d783dfa663caf39e06633721c8d4cfcd7e"
LABEL = "head at observation time, not established as the training revision"


class Counting(RecordedFetcher):
    """A ``RecordedFetcher`` that lists every URL asked for."""

    def __init__(self, root: Path) -> None:
        super().__init__(root)
        self.asked: list[str] = []

    def get(self, url: str, *, follow_redirects: bool = True) -> Response:
        self.asked.append(url)
        return super().get(url, follow_redirects=follow_redirects)

    def head(self, url: str, *, follow_redirects: bool = True) -> Response:
        self.asked.append(url)
        return super().head(url, follow_redirects=follow_redirects)

    def post(self, url: str, body: bytes) -> Response:
        self.asked.append(url)
        return super().post(url, body)

    def get_range(self, url: str, length: int) -> Response:
        self.asked.append(url)
        return super().get_range(url, length)


@pytest.fixture
def discover(
    detector_project: Path, capsys: pytest.CaptureFixture[str]
) -> Callable[..., tuple[int, Any]]:
    def run(fetcher: Counting, *argv: str) -> tuple[int, Any]:
        handlers = make_handlers(fetcher=fetcher, now=lambda: NOW)
        code = main(["discover", str(detector_project), *argv, "--json"], handlers=handlers)
        return code, json.loads(capsys.readouterr().out)

    return run


def items(result: dict[str, Any], kind: str) -> dict[str, dict[str, Any]]:
    return {c["identity"]["hub_repo"]: c for c in result["candidates"] if c["kind"] == kind}


def test_without_upstream_no_request_is_made(
    discover: Callable[..., tuple[int, Any]], derive_upstream: Callable[..., Path]
) -> None:
    fetcher = Counting(derive_upstream())
    code, result = discover(fetcher)
    assert code == EXIT_OK
    assert fetcher.asked == []
    assert result["upstream"] is False
    assert all("proposed_revision" not in c for c in result["candidates"])


def test_with_upstream_only_the_named_hub_identities_are_read(
    discover: Callable[..., tuple[int, Any]], derive_upstream: Callable[..., Path]
) -> None:
    fetcher = Counting(derive_upstream())
    code, result = discover(fetcher, "--upstream")
    assert code == EXIT_OK
    assert result["upstream"] is True
    assert sorted(fetcher.asked) == sorted(
        [
            hf.model_info_url(GPT2),
            hf.dataset_info_url("yavon/muxue"),
            hf.dataset_info_url("model-dependabot-fixture/does-not-exist"),
        ]
    )
    base = items(result, "base_model")[GPT2]
    assert base["proposed_revision"] == {
        "revision": GPT2_SHA,
        "observed_at": "2026-10-24T05:47:46Z",
        "label": LABEL,
    }
    assert base["identity"]["revision"] is None  # the hub's head is never the identity
    assert base["gaps"] == ["no revision"]
    assert base["upstream"]["licence"] == "mit"
    assert base["upstream"]["spdx"] == "MIT"
    assert base["upstream"]["url"] == hf.model_info_url(GPT2)

    datasets = items(result, "dataset")
    refused = datasets["model-dependabot-fixture/does-not-exist"]
    assert refused["status"] == "unavailable"
    assert "the hub refused the dataset lookup (HTTP 401)" in refused["gaps"]
    reachable = datasets["yavon/muxue"]
    assert reachable["status"] == "declared-but-unverified"
    assert reachable["proposed_revision"]["label"] == LABEL


def test_a_failed_lookup_is_unavailable_and_discovery_still_completes(
    discover: Callable[..., tuple[int, Any]], derive_upstream: Callable[..., Path]
) -> None:
    fetcher = Counting(derive_upstream(errors={"hf_upstream/model-normal": "timed out"}))
    code, result = discover(fetcher, "--upstream")
    assert code == EXIT_OK
    base = items(result, "base_model")[GPT2]
    assert base["status"] == "unavailable"
    assert any(gap.startswith("the model lookup failed") for gap in base["gaps"])
    assert "proposed_revision" not in base

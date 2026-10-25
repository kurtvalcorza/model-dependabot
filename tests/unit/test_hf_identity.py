"""A hub answer for another repository is unreadable, never the requested repository's state.

The recorded model and dataset info, security status and revision answers carry the repository as
``id`` (and model answers as ``modelId`` too), spelt as the hub spells it; tree answers are lists
and carry no repository. A 200 answer whose ``id`` names another repository, compared ignoring case
because the hub treats repository ids so, is read like any other unreadable answer: the source fails
or the verdict is unrecognised, so nothing opens or closes on it (data-model.md, Identity and
clearance). An answer with no ``id`` is read as before.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from model_dependabot.sources import hf
from model_dependabot.sources.fetcher import Headers, Response, SourceFailedError

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
NOW = datetime(2026, 10, 25, 6, 0, tzinfo=UTC)
COMMIT = "607a30d783dfa663caf39e06633721c8d4cfcd7e"


def recorded(directory: str, name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / directory / f"{name}.json").read_text(encoding="utf-8"))


def answer(info: Any, url: str = "https://huggingface.co/api/x") -> Response:
    return Response(200, json.dumps(info).encode(), url, NOW, Headers())


class OneAnswer:
    def __init__(self, response: Response) -> None:
        self.response = response

    def get(self, url: str, *, follow_redirects: bool = True) -> Response:
        return self.response

    def post(self, url: str, body: bytes) -> Response:
        raise AssertionError("not used")


def test_recorded_answers_name_their_repository_in_id() -> None:
    assert recorded("hf_upstream", "model-normal")["id"] == "openai-community/gpt2"
    assert recorded("hf_upstream", "dataset-disabled")["id"] == "yavon/muxue"
    assert recorded("hf", "gpt2-security")["id"] == "openai-community/gpt2"
    assert recorded("hf", "gpt2-model-info")["id"] == "openai-community/gpt2"
    assert isinstance(recorded("hf", "gpt2-tree"), list)


def test_model_info_for_another_repository_fails_the_source() -> None:
    info = recorded("hf_upstream", "model-normal")
    with pytest.raises(SourceFailedError, match="openai-community/gpt2"):
        hf.parse_model("someone/renamed-model", answer(info))


def test_model_info_matching_ignoring_case_is_read() -> None:
    info = recorded("hf_upstream", "model-normal")
    model = hf.parse_model("OpenAI-Community/GPT2", answer(info))
    assert model.outcome == "reachable"
    assert model.sha == info["sha"]


def test_model_info_with_another_model_id_fails_the_source() -> None:
    info = recorded("hf_upstream", "model-normal")
    del info["id"]
    info["modelId"] = "someone/else"
    with pytest.raises(SourceFailedError):
        hf.parse_model("openai-community/gpt2", answer(info))


def test_model_info_without_an_id_is_read_as_before() -> None:
    info = recorded("hf_upstream", "model-normal")
    del info["id"]
    assert hf.parse_model("someone/any", answer(info)).outcome == "reachable"


def test_a_non_text_id_fails_the_source() -> None:
    info = recorded("hf_upstream", "model-normal")
    info["id"] = 42
    with pytest.raises(SourceFailedError):
        hf.parse_model("openai-community/gpt2", answer(info))


def test_dataset_info_for_another_repository_fails_the_source() -> None:
    info = recorded("hf_upstream", "dataset-disabled")
    with pytest.raises(SourceFailedError, match="yavon/muxue"):
        hf.parse_dataset("someone/dataset", answer(info))


def test_dataset_info_for_the_moved_target_is_read_at_its_own_name() -> None:
    info = recorded("hf_upstream", "dataset-moved-target")
    dataset = hf.parse_dataset("Defunct-Datasets/The_Pile_Books3", answer(info))
    assert dataset.outcome == "reachable"


def test_dataset_info_without_an_id_is_read_as_before() -> None:
    info = recorded("hf_upstream", "dataset-disabled")
    del info["id"]
    assert hf.parse_dataset("someone/dataset", answer(info)).disabled is True


def test_security_status_for_another_repository_is_unrecognised() -> None:
    info = recorded("hf", "eicar-security")
    status = hf.HubSecurity(OneAnswer(answer(info))).status("someone/other")
    assert status.state == hf.UNRECOGNISED
    assert status.reason is not None and "mcpotato/42-eicar-street" in status.reason
    verdict = hf.HubSecurity(OneAnswer(answer(info))).verdict(status, "pytorch_model.bin")
    assert verdict.state == hf.UNRECOGNISED


def test_security_status_matching_ignoring_case_is_answered() -> None:
    info = recorded("hf", "eicar-security")
    status = hf.HubSecurity(OneAnswer(answer(info))).status("MCPotato/42-EICAR-street")
    assert status.state == "answered"


def test_revision_for_another_repository_is_a_gap() -> None:
    info = recorded("hf", "gpt2-model-info")
    result = hf.HuggingFace(OneAnswer(answer(info))).revision("someone/other", COMMIT)
    assert result.commit is None
    assert result.gap_reason is not None and "openai-community/gpt2" in result.gap_reason


def test_revision_header_does_not_hide_another_repository() -> None:
    info = recorded("hf", "gpt2-model-info")
    response = Response(
        200, json.dumps(info).encode(), "https://x", NOW, Headers({"X-Repo-Commit": COMMIT})
    )
    result = hf.HuggingFace(OneAnswer(response)).revision("someone/other", COMMIT)
    assert result.commit is None


def test_revision_matching_ignoring_case_is_read() -> None:
    info = recorded("hf", "gpt2-model-info")
    result = hf.HuggingFace(OneAnswer(answer(info))).revision("OpenAI-Community/gpt2", COMMIT)
    assert (result.commit, result.gap_reason) == (COMMIT, None)

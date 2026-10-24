"""Hugging Face tree hashes and revisions from recorded responses (T015, research R5)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from model_dependabot.sources.fetcher import RecordedFetcher
from model_dependabot.sources.hf import HuggingFace, parse_hub, resolve_url

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "hf"
REPO = "openai-community/gpt2"
MISSING = "model-dependabot-fixture/does-not-exist"
COMMIT = "607a30d783dfa663caf39e06633721c8d4cfcd7e"
SAFETENSORS_SHA256 = "248dfc3911869ec493c76e65bf2fcf7f615828b0254c12b473182f0f81d3a707"


@pytest.fixture
def hub() -> HuggingFace:
    return HuggingFace(RecordedFetcher(FIXTURES))


def test_hub_references_are_parsed() -> None:
    assert parse_hub("hf:openai-community/gpt2") == "openai-community/gpt2"
    for bad in ("openai-community/gpt2", "hf:gpt2", "hf:a/b/c", "gh:a/b", "hf:"):
        with pytest.raises(ValueError):
            parse_hub(bad)


def test_the_tree_gives_sha256_from_lfs_oid_and_size(hub: HuggingFace) -> None:
    tree = hub.tree(REPO, COMMIT)
    assert tree.gap_reason is None
    model = tree.files["model.safetensors"]
    assert model.sha256 == SAFETENSORS_SHA256
    assert model.size == 548105171
    assert model.git_oid == "44b36d6e32d13c8fb28b0feab0ac8bfefa7efeda"


def test_a_file_outside_lfs_has_no_sha256(hub: HuggingFace) -> None:
    config = hub.tree(REPO, COMMIT).files["config.json"]
    assert config.sha256 is None
    assert config.git_oid == "10c66461e4c109db5a2196bff4bb59be30396ed8"


def test_directories_are_not_files(hub: HuggingFace) -> None:
    assert "onnx" not in hub.tree(REPO, COMMIT).files


def test_the_revision_comes_from_model_info(hub: HuggingFace) -> None:
    result = hub.revision(REPO, COMMIT)
    assert (result.commit, result.gap_reason) == (COMMIT, None)


def test_x_repo_commit_takes_precedence_over_the_body(tmp_path: Path) -> None:
    other = "1" * 40
    url = f"https://huggingface.co/api/models/{REPO}/revision/{COMMIT}"
    (tmp_path / "info.json").write_text(json.dumps({"sha": COMMIT}))
    meta = {
        "method": "GET",
        "url": url,
        "status": 200,
        "headers": {"X-Repo-Commit": other},
        "retrieved_at": "2026-10-24T00:00:00Z",
        "body_file": "info.json",
    }
    (tmp_path / "info.meta.json").write_text(json.dumps(meta))
    result = HuggingFace(RecordedFetcher(tmp_path)).revision(REPO, COMMIT)
    assert result.commit == other


def test_a_401_is_a_gap_not_an_error(hub: HuggingFace) -> None:
    tree = hub.tree(MISSING, COMMIT)
    assert tree.files == {}
    assert tree.gap_reason is not None
    assert "401" in tree.gap_reason


def test_hub_file_combines_tree_and_revision(hub: HuggingFace) -> None:
    found = hub.hub_file(REPO, COMMIT, "model.safetensors")
    assert found.gap_reason is None
    assert found.commit == COMMIT
    assert found.file is not None
    assert found.file.sha256 == SAFETENSORS_SHA256


def test_hub_file_gaps(hub: HuggingFace) -> None:
    assert hub.hub_file(REPO, COMMIT, "absent.bin").gap_reason == "file not found at revision"
    assert hub.hub_file(REPO, COMMIT, "config.json").gap_reason == "no SHA-256 from the hub"
    assert "401" in (hub.hub_file(MISSING, COMMIT, "model.safetensors").gap_reason or "")


def test_an_unreachable_hub_is_a_gap(tmp_path: Path) -> None:
    url = f"https://huggingface.co/api/models/{REPO}/tree/{COMMIT}"
    meta = {"method": "GET", "url": url, "error": "timeout after 4 attempts"}
    (tmp_path / "t.meta.json").write_text(json.dumps(meta))
    found = HuggingFace(RecordedFetcher(tmp_path)).hub_file(REPO, COMMIT, "model.safetensors")
    assert found.gap_reason is not None
    assert "not reachable" in found.gap_reason


def test_only_the_recorded_get_requests_are_made(hub: HuggingFace) -> None:
    hub.hub_file(REPO, COMMIT, "model.safetensors")
    fetcher = hub.fetcher
    assert isinstance(fetcher, RecordedFetcher)
    assert {method for method, _, _ in fetcher.requests} == {"GET"}


def test_the_download_url_is_at_the_pinned_revision() -> None:
    assert resolve_url(REPO, COMMIT, "onnx/decoder_model.onnx") == (
        f"https://huggingface.co/{REPO}/resolve/{COMMIT}/onnx/decoder_model.onnx"
    )

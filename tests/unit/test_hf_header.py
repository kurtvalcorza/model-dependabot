"""Reading a hub file's header at its pinned commit (T012; FR-002a, FR-002b, research A4).

The real answers are recorded in ``tests/fixtures/format_check``; refusals, server errors, a cut-off
answer, a long header and a forged file are derived from them by ``derive_format_check``.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from pathlib import Path

import pytest

from conftest import (
    FORGED_COMMIT,
    FORGED_REPO,
    FORMAT_CHECK_FIXTURES,
    GATED_COMMIT,
    GATED_REPO,
    GGUF_COMMIT,
    GGUF_FILE,
    GGUF_REPO,
    GGUF_SHA256,
    GPT2_COMMIT,
    GPT2_PICKLE,
    GPT2_REPO,
    GPT2_SAFETENSORS,
    ZIP_COMMIT,
    ZIP_REPO,
    ZIP_SHA256,
    recorded_body,
    resolve,
    tree_item,
    tree_url,
)
from model_dependabot.sources.fetcher import RecordedFetcher, SourceFailedError
from model_dependabot.sources.hf import HEADER_LEAD, HEADER_LIMIT, HuggingFace

LONG_REPO = "model-dependabot-fixture/long-header"
LONG_COMMIT = "1" * 40


def _hub(root: Path = FORMAT_CHECK_FIXTURES) -> tuple[HuggingFace, RecordedFetcher]:
    fetcher = RecordedFetcher(root)
    return HuggingFace(fetcher), fetcher


def _ranged(fetcher: RecordedFetcher) -> list[str]:
    return [url for _, url, _ in fetcher.requests if "/resolve/" in url]


@pytest.mark.parametrize(
    ("repo", "commit", "file", "sha256", "expected"),
    [
        (GPT2_REPO, GPT2_COMMIT, "model.safetensors", GPT2_SAFETENSORS, ("safetensors", False)),
        (GPT2_REPO, GPT2_COMMIT, "pytorch_model.bin", GPT2_PICKLE, ("pickle", True)),
        (GGUF_REPO, GGUF_COMMIT, GGUF_FILE, GGUF_SHA256, ("gguf", False)),
        (ZIP_REPO, ZIP_COMMIT, "pytorch_model.bin", ZIP_SHA256, ("pytorch-zip", True)),
    ],
)
def test_the_header_is_classified_with_the_rules_for_local_files(
    repo: str, commit: str, file: str, sha256: str, expected: tuple[str, bool]
) -> None:
    hub, _ = _hub()
    read = hub.read_header(repo, commit, file, sha256)
    assert read.identity == "confirmed"
    assert read.hub_sha256 == sha256
    assert (read.format, read.can_run_code) == expected
    assert read.reason is None
    assert read.status == 206
    assert read.url == resolve(repo, commit, file)


def test_the_read_records_what_evidence_needs_and_no_weight_bytes() -> None:
    hub, _ = _hub()
    read = hub.read_header(GPT2_REPO, GPT2_COMMIT, "model.safetensors", GPT2_SAFETENSORS)
    lead = recorded_body("gpt2-safetensors-range-1")
    assert read.content_range == "bytes 0-1048575/548105171"
    assert read.total_size == 548_105_171
    assert read.lead_length == HEADER_LEAD == len(lead)
    assert read.lead_sha256 == hashlib.sha256(lead).hexdigest()
    summary = read.summary()
    assert summary == {
        "url": resolve(GPT2_REPO, GPT2_COMMIT, "model.safetensors"),
        "tree_url": tree_url(GPT2_REPO, GPT2_COMMIT),
        "commit": GPT2_COMMIT,
        "file": "model.safetensors",
        "hub_sha256": GPT2_SAFETENSORS,
        "status": 206,
        "content_range": "bytes 0-1048575/548105171",
        "total_size": 548_105_171,
        "lead_sha256": read.lead_sha256,
        "lead_length": HEADER_LEAD,
        "measured_format": "safetensors",
        "measured_can_run_code": False,
        "identity": "confirmed",
        "reason": None,
    }
    assert len(json.dumps(summary)) < 2000  # a summary, never the bytes


def test_a_hash_that_differs_from_the_tree_contradicts_the_identity() -> None:
    hub, fetcher = _hub()
    read = hub.read_header(GPT2_REPO, GPT2_COMMIT, "model.safetensors", "e" * 64)
    assert read.identity == "contradicted"
    assert read.hub_sha256 == GPT2_SAFETENSORS
    assert "e" * 64 in str(read.reason) and GPT2_SAFETENSORS in str(read.reason)
    assert _ranged(fetcher) == []  # the hub's file is not the pinned one: its header says nothing


def test_a_file_missing_from_the_tree_is_unreadable_not_a_failure() -> None:
    hub, fetcher = _hub()
    read = hub.read_header(GPT2_REPO, GPT2_COMMIT, "absent.safetensors", GPT2_SAFETENSORS)
    assert read.identity == "unreadable"
    assert read.reason == "file not found at revision"
    assert _ranged(fetcher) == []


def test_a_file_the_hub_gives_no_sha256_for_is_unreadable() -> None:
    hub, _ = _hub()
    read = hub.read_header(GATED_REPO, GATED_COMMIT, "gated_file.txt", "e" * 64)
    assert read.identity == "unreadable"
    assert read.reason == "no SHA-256 from the hub"


@pytest.mark.parametrize("status", [401, 403, 404])
def test_a_refused_tree_is_unreadable(status: int, derive_format_check: Callable) -> None:
    root = derive_format_check(
        {
            "tree": {
                "url": tree_url(GPT2_REPO, GPT2_COMMIT),
                "status": status,
                "range": None,
                "body": "refused",
            }
        }
    )
    hub, fetcher = _hub(root)
    read = hub.read_header(GPT2_REPO, GPT2_COMMIT, "model.safetensors", GPT2_SAFETENSORS)
    assert read.identity == "unreadable"
    assert f"HTTP {status}" in str(read.reason)
    assert _ranged(fetcher) == []


def _gated_tree() -> dict:
    return {
        "url": tree_url(GATED_REPO, GATED_COMMIT),
        "status": 200,
        "range": None,
        "body": json.dumps([tree_item("gated_file.txt", "d" * 64, 10)]),
    }


def test_the_recorded_refusal_of_the_ranged_read_is_unreadable(
    derive_format_check: Callable,
) -> None:
    """The gated test repository's real 401, with a tree derived to list a hash for its file."""
    hub, _ = _hub(derive_format_check({"gated-tree": _gated_tree()}))
    read = hub.read_header(GATED_REPO, GATED_COMMIT, "gated_file.txt", "d" * 64)
    assert read.identity == "confirmed"
    assert read.format is None and read.can_run_code is None
    assert read.status == 401
    assert "HTTP 401" in str(read.reason)


@pytest.mark.parametrize("status", [403, 404])
def test_a_refused_ranged_read_is_unreadable(status: int, derive_format_check: Callable) -> None:
    url = resolve(GATED_REPO, GATED_COMMIT, "gated_file.txt")
    root = derive_format_check(
        {"gated-tree": _gated_tree(), "range": {"url": url, "status": status, "body": "no"}}
    )
    hub, _ = _hub(root)
    read = hub.read_header(GATED_REPO, GATED_COMMIT, "gated_file.txt", "d" * 64)
    assert read.format is None
    assert f"HTTP {status}" in str(read.reason)


def _long_header(length: int, *, data: int = 4) -> bytes:
    header = b'{"w":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}'.ljust(length, b" ")
    return length.to_bytes(8, "little") + header + b"\x00" * data


def _long(content: bytes, *, second: bool) -> dict[str, dict]:
    url = resolve(LONG_REPO, LONG_COMMIT, "model.safetensors")
    total = len(content)
    specs = {
        "long-tree": {
            "url": tree_url(LONG_REPO, LONG_COMMIT),
            "status": 200,
            "range": None,
            "body": json.dumps([tree_item("model.safetensors", "c" * 64, total)]),
        },
        "long-range": {
            "url": url,
            "status": 206,
            "headers": {"Content-Range": f"bytes 0-{HEADER_LEAD - 1}/{total}"},
            "body": content[:HEADER_LEAD],
        },
    }
    if second:
        needed = int.from_bytes(content[:8], "little") + 8
        specs["long-range-2"] = {
            "url": url,
            "range": f"bytes=0-{needed - 1}",
            "status": 206,
            "headers": {"Content-Range": f"bytes 0-{needed - 1}/{total}"},
            "body": content[:needed],
        }
    return specs


def test_a_header_longer_than_the_lead_is_read_with_one_more_range(
    derive_format_check: Callable,
) -> None:
    content = _long_header(3 * HEADER_LEAD // 2)
    hub, fetcher = _hub(derive_format_check(_long(content, second=True)))
    read = hub.read_header(LONG_REPO, LONG_COMMIT, "model.safetensors", "c" * 64)
    assert (read.format, read.can_run_code) == ("safetensors", False)
    assert len(_ranged(fetcher)) == 2
    assert read.lead_length == 8 + 3 * HEADER_LEAD // 2


def test_a_header_over_the_limit_is_unreadable_and_not_read(derive_format_check: Callable) -> None:
    length = HEADER_LIMIT  # 8 + length is over the limit
    content = length.to_bytes(8, "little") + b"{" + b" " * (HEADER_LEAD - 9)
    specs = _long(content, second=False)
    specs["long-range"]["headers"] = {"Content-Range": f"bytes 0-{HEADER_LEAD - 1}/{2 * length}"}
    specs["long-tree"]["body"] = json.dumps([tree_item("model.safetensors", "c" * 64, 2 * length)])
    hub, fetcher = _hub(derive_format_check(specs))
    read = hub.read_header(LONG_REPO, LONG_COMMIT, "model.safetensors", "c" * 64)
    assert read.format is None
    assert "longer than" in str(read.reason)
    assert len(_ranged(fetcher)) == 1


def test_a_server_that_ignores_the_range_gives_its_size_in_content_length(
    derive_format_check: Callable,
) -> None:
    content = _long_header(64)
    url = resolve(LONG_REPO, LONG_COMMIT, "model.safetensors")
    specs = _long(content, second=False)
    specs["long-range"] = {
        "url": url,
        "status": 200,
        "headers": {"Content-Length": str(len(content))},
        "body": content,
    }
    hub, _ = _hub(derive_format_check(specs))
    read = hub.read_header(LONG_REPO, LONG_COMMIT, "model.safetensors", "c" * 64)
    assert (read.format, read.can_run_code) == ("safetensors", False)
    assert read.status == 200
    assert read.total_size == len(content)


def test_a_forged_code_free_name_shows_the_pickle_it_is(derive_format_check: Callable) -> None:
    hub, _ = _hub(derive_format_check())
    read = hub.read_header(FORGED_REPO, FORGED_COMMIT, "model.safetensors", GPT2_PICKLE)
    assert read.identity == "confirmed"
    assert (read.format, read.can_run_code) == ("pickle", True)


def test_identity_only_reads_no_header() -> None:
    hub, fetcher = _hub()
    read = hub.read_header(GPT2_REPO, GPT2_COMMIT, "pytorch_model.bin", GPT2_PICKLE, header=False)
    assert read.identity == "confirmed"
    assert read.format is None
    assert _ranged(fetcher) == []


@pytest.mark.parametrize(
    "spec",
    [
        {"status": 503, "body": "busy"},
        {"error": "URLError: Connection reset by peer after 4 attempts"},
        # Cut off mid-read: the answer promises 1 MiB and ends after ten bytes.
        {
            "status": 206,
            "headers": {"Content-Range": "bytes 0-1048575/548105171"},
            "body": b"\x00" * 10,
        },
    ],
)
def test_network_and_server_errors_fail_the_source(
    spec: dict, derive_format_check: Callable
) -> None:
    hop = resolve(GPT2_REPO, GPT2_COMMIT, "model.safetensors")
    hub, _ = _hub(derive_format_check({"range": {"url": hop, **spec}}))
    with pytest.raises(SourceFailedError):
        hub.read_header(GPT2_REPO, GPT2_COMMIT, "model.safetensors", GPT2_SAFETENSORS)


@pytest.mark.parametrize("spec", [{"status": 503, "body": "busy"}, {"error": "timed out"}])
def test_a_failed_tree_fails_the_source(spec: dict, derive_format_check: Callable) -> None:
    root = derive_format_check(
        {"tree": {"url": tree_url(GPT2_REPO, GPT2_COMMIT), "range": None, **spec}}
    )
    hub, _ = _hub(root)
    with pytest.raises(SourceFailedError):
        hub.read_header(GPT2_REPO, GPT2_COMMIT, "model.safetensors", GPT2_SAFETENSORS)

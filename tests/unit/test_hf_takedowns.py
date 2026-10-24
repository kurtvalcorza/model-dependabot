"""The hub's public takedown log (T025; FR-005, research U5, U10)."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from model_dependabot.lifecycle import run_check
from model_dependabot.sources.fetcher import RecordedFetcher
from model_dependabot.sources.hf_takedowns import (
    INDEX_URL,
    NOTICE_LABEL,
    TakedownIndex,
    matches,
    parse_index,
)
from model_dependabot.store import Store

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
MOMENT = datetime(2026, 10, 24, 8, 0, tzinfo=UTC)
SHA = "9408684b4d7410bf12651eff99ad6da74d746811"
FULL_LOG = (
    "date,requesting_entity,reported_content,file\n"
    "2026-09-04,Fixture Requester Ltd,yavon/muxue,2026/2026-09-04-fixture-requester.pdf\n"
)


def test_the_requesting_entity_and_file_columns_are_dropped_when_read() -> None:
    assert parse_index(FULL_LOG.encode("utf-8")) == [
        {"date": "2026-09-04", "reported_content": "yavon/muxue"}
    ]


def test_the_recorded_log_reads_67_rows_of_date_and_reported_content() -> None:
    log = TakedownIndex(RecordedFetcher(FIXTURES / "hf_takedowns")).read()
    assert len(log.notices) == 67
    assert {tuple(sorted(row)) for row in log.notices} == {("date", "reported_content")}
    assert log.response.url == INDEX_URL


@pytest.mark.parametrize(
    ("reported", "repo", "expected"),
    [
        ("pytorch/silero_tts", "pytorch/silero_tts", True),
        (" Pytorch/Silero_TTS ", "pytorch/silero_tts", True),
        ("pytorch/silero_tts", "pytorch/silero", False),
        ("datasets/pytorch/silero_tts", "pytorch/silero_tts", False),
        ("https://huggingface.co/pytorch/silero_tts", "pytorch/silero_tts", False),
        ("Multiple", "multiple", False),
        ("multiple", "multiple", False),
        (" Multiple", "multiple", False),
    ],
)
def test_a_row_matches_only_by_the_bare_owner_name_path(
    reported: str, repo: str, expected: bool
) -> None:
    assert matches(reported, repo) is expected


def test_rows_reading_multiple_never_match_in_any_spelling() -> None:
    log = TakedownIndex(RecordedFetcher(FIXTURES / "hf_takedowns")).read()
    spellings = {
        row["reported_content"] for row in log.notices if "ultiple" in row["reported_content"]
    }
    assert spellings == {"Multiple", "multiple", " Multiple"}
    assert all(not log.find(spelling) for spelling in ("Multiple", "multiple"))


def test_a_match_yields_only_the_notice_date_and_reported_content() -> None:
    log = TakedownIndex(RecordedFetcher(FIXTURES / "hf_takedowns")).read()
    assert log.find("pytorch/silero_tts") == [
        {"notice_date": "2022-06-28", "reported_content": "pytorch/silero_tts"}
    ]
    assert NOTICE_LABEL == "notice date, not removal date"


def _store(tmp_path: Path) -> Store:
    return Store(tmp_path / "md.db", now=lambda: MOMENT)


def _hub_dataset(repo: str, sha: str = SHA) -> dict[str, Any]:
    return {
        "kind": "dataset",
        "identifier": f"hf-dataset:{repo}@{sha}",
        "pinned": True,
        "hub_repo": repo,
        "hub_revision": sha,
    }


def _register(store: Store, model_id: str, entries: list[dict[str, Any]]) -> None:
    store.add_model(model_id)
    store.add_version(model_id, {}, "0" * 64, entries)


def _log_requests(fetcher: RecordedFetcher) -> list[str]:
    return [url for _, url, _ in fetcher.requests if url == INDEX_URL]


def test_the_log_is_read_once_per_run_and_never_stored_with_dropped_columns(
    derive_upstream: Callable[..., Path], tmp_path: Path
) -> None:
    root = derive_upstream(
        changes={"hf_takedowns/index": lambda text: FULL_LOG},
        extra={
            "second": {
                "url": "https://huggingface.co/api/datasets/owner/second?expand[]=disabled"
                "&expand[]=gated&expand[]=private&expand[]=cardData&expand[]=sha",
                "status": 200,
                "body": {"id": "owner/second", "disabled": False, "gated": False, "sha": SHA},
            }
        },
    )
    fetcher = RecordedFetcher(root)
    with _store(tmp_path) as store:
        _register(store, "one", [_hub_dataset("yavon/muxue")])
        _register(store, "two", [_hub_dataset("owner/second")])
        outcome = run_check(store, fetcher, ["one", "two"], ["hf-hub", "hf-takedowns"])
        assert outcome.sources == {"hf-hub": "ok", "hf-takedowns": "ok"}
        assert len(_log_requests(fetcher)) == 1
        assert store.takedown_notices() == [
            {"date": "2026-09-04", "reported_content": "yavon/muxue"}
        ]
        (alert,) = store.alerts_for("one", ["open"])
        (notice,) = [
            e for e in store.alert_evidence(alert["alert_id"]) if e["source"] == "hf-takedowns"
        ]
        assert notice["url"] == INDEX_URL
        assert notice["detail"] == {
            "notice_date": "2026-09-04",
            "reported_content": "yavon/muxue",
            "label": NOTICE_LABEL,
        }
        assert {"file", "requesting_entity"} <= set(notice["redacted_fields"])
        dump = b"".join(
            store.read_body(e["body_sha256"]) for e in store.alert_evidence(alert["alert_id"])
        )
    assert b"Fixture Requester" not in dump and b"fixture-requester" not in dump
    assert b"Fixture Requester" not in (tmp_path / "md.db").read_bytes()


def test_the_log_is_not_read_when_no_hub_dataset_is_in_scope(
    derive_upstream: Callable[..., Path], tmp_path: Path
) -> None:
    fetcher = RecordedFetcher(derive_upstream())
    with _store(tmp_path) as store:
        _register(store, "doi-only", [{"kind": "dataset", "identifier": "10.1/x", "pinned": True}])
        outcome = run_check(store, fetcher, ["doi-only"], ["hf-hub", "hf-takedowns"])
    assert outcome.sources == {"hf-hub": "ok", "hf-takedowns": "ok"}
    assert _log_requests(fetcher) == []

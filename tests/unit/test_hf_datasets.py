"""Hub dataset info: disabled, refused, moved (T024; FR-005, research U5)."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from model_dependabot.sources.fetcher import RecordedFetcher
from model_dependabot.sources.hf import HuggingFace, dataset_info_url

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
EXPAND = "expand[]=disabled&expand[]=gated&expand[]=private&expand[]=cardData&expand[]=sha"


def hub(root: Path = FIXTURES / "hf_upstream") -> tuple[HuggingFace, RecordedFetcher]:
    fetcher = RecordedFetcher(root)
    return HuggingFace(fetcher), fetcher


def test_the_dataset_info_url_asks_for_the_watched_fields() -> None:
    expected = f"https://huggingface.co/api/datasets/yavon/muxue?{EXPAND}"
    assert dataset_info_url("yavon/muxue") == expected


def test_disabled_true_is_recorded_with_gated_sha_and_licence() -> None:
    dataset = hub()[0].dataset("yavon/muxue")
    assert dataset.outcome == "reachable"
    assert dataset.disabled is True
    assert dataset.gated == "false"
    assert dataset.sha == "9408684b4d7410bf12651eff99ad6da74d746811"
    assert dataset.licence == "apache-2.0"


@pytest.mark.parametrize("status", [401, 403, 404])
def test_401_403_and_404_are_refused(derive_upstream: Callable[..., Path], status: int) -> None:
    url = dataset_info_url("owner/refused")
    root = derive_upstream(
        extra={"refused": {"url": url, "status": status, "body": {"error": "refused"}}}
    )
    dataset = hub(root)[0].dataset("owner/refused")
    assert (dataset.outcome, dataset.response.status, dataset.disabled) == ("refused", status, None)


def test_the_recorded_401_is_refused() -> None:
    assert hub()[0].dataset("model-dependabot-fixture/does-not-exist").outcome == "refused"


def test_a_307_to_another_namespace_is_redirected_with_the_target_and_not_followed() -> None:
    client, fetcher = hub()
    dataset = client.dataset("the_pile_books3")
    assert dataset.outcome == "redirected"
    assert dataset.response.status == 307
    assert dataset.moved_to == "defunct-datasets/the_pile_books3"
    assert dataset.response.redirected_to == dataset_info_url("defunct-datasets/the_pile_books3")
    assert [url for _, url, _ in fetcher.requests] == [dataset_info_url("the_pile_books3")]


def test_a_licence_list_of_one_reads_as_that_licence() -> None:
    dataset = hub()[0].dataset("defunct-datasets/the_pile_books3")
    assert (dataset.disabled, dataset.licence) == (False, "mit")

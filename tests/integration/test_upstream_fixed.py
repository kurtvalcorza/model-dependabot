"""A newer version that no longer depends on the item fixes the new alert kinds (T053; FR-015).

The base-model alerts come from real checks against answers derived from the recorded hub answer for
``openai-community/gpt2`` (``hf_upstream/model-normal``): ``disabled: true`` opens
``base_model_disabled`` and a changed ``cardData.license`` opens ``licence_changed``. The dataset
alerts are opened in the store with the cause shapes the checks write, since only the inventories
are compared when a version is registered (no source is consulted).
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from model_dependabot.lifecycle import dismiss_alert, reevaluate_version, run_check
from model_dependabot.sources.fetcher import RecordedFetcher
from model_dependabot.store import Store

MOMENT = datetime(2026, 10, 24, 6, 0, tzinfo=UTC)
GPT2 = "openai-community/gpt2"
GPT2_SHA = "607a30d783dfa663caf39e06633721c8d4cfcd7e"
PURL = f"pkg:huggingface/openai-community/gpt2@{GPT2_SHA}"
DOI = "10.5281/zenodo.3242074"
PAPER = "10.1016/j.example.2020.01.001"
HUB = "hf-dataset:yavon/muxue@0123456789abcdef0123456789abcdef01234567"

BASE = {
    "kind": "base_model",
    "identifier": PURL,
    "pinned": True,
    "name": GPT2,
    "version": GPT2_SHA,
    "recorded_licence": "MIT",
    "licence_form": "spdx",
}
DOI_DATASET = {"kind": "dataset", "identifier": DOI, "pinned": True, "paper_dois": [PAPER]}
HUB_DATASET = {
    "kind": "dataset",
    "identifier": HUB,
    "pinned": True,
    "hub_repo": "yavon/muxue",
    "hub_revision": "0123456789abcdef0123456789abcdef01234567",
}
DATASET_CAUSES = {
    "dataset_retracted": {"identifier": DOI, "dataset": DOI},
    "paper_retracted": {"identifier": DOI, "dataset": DOI, "paper_doi": PAPER},
    "dataset_not_findable": {"identifier": DOI, "dataset": DOI},
    "dataset_removed": {"identifier": HUB, "dataset": HUB},
}


@pytest.fixture
def store(tmp_path: Path) -> Iterator[Store]:
    with Store(tmp_path / "md.db", now=lambda: MOMENT) as opened:
        opened.add_model("m")
        opened.add_version("m", {}, "0" * 64, [BASE, DOI_DATASET, HUB_DATASET])
        yield opened


def disabled_with_licence(licence: str) -> Callable[[dict[str, Any]], dict[str, Any]]:
    def change(body: dict[str, Any]) -> dict[str, Any]:
        body["cardData"]["license"] = licence
        return body | {"disabled": True}

    return change


def open_everything(store: Store, derive: Callable[..., Path]) -> dict[str, int]:
    root = derive(changes={"hf_upstream/model-normal": disabled_with_licence("cc-by-nc-4.0")})
    run_check(store, RecordedFetcher(root), ["m"], ("hf-hub",))
    for kind, cause in DATASET_CAUSES.items():
        store.insert_alert(
            model_id="m",
            kind=kind,
            cause_key=f"{kind}:{cause['identifier']}:{cause.get('paper_doi', '')}",
            cause=cause,
            severity="HIGH",
            severity_origin="policy",
            opened_in_version=1,
            evidence_ids=[],
        )
    store.insert_alert(
        model_id="m",
        kind="base_model_unavailable",
        cause_key=f"base_model_unavailable:{PURL}",
        cause={"identifier": PURL, "base_model": PURL},
        severity="LOW",
        severity_origin="policy",
        opened_in_version=1,
        evidence_ids=[],
    )
    opened = {a["kind"]: a["alert_id"] for a in store.alerts_for("m", ["open"])}
    assert set(opened) >= {"base_model_disabled", "licence_changed", *DATASET_CAUSES}
    return opened


def states(store: Store) -> dict[str, tuple[str, int | None]]:
    return {
        a["kind"]: (a["state"], a["closed_by_version"])
        for a in store.alerts_for("m", None)
        if a["kind"] != "pickle_format"
    }


def test_a_version_without_the_items_fixes_every_new_kind(
    store: Store, derive_upstream: Callable[..., Path]
) -> None:
    open_everything(store, derive_upstream)
    version = store.add_version("m", {}, "1" * 64, [])
    result = reevaluate_version(store, "m", version)
    assert result["carried_forward"] == []
    assert set(states(store).values()) == {("fixed", 2)}
    for alert in store.alerts_for("m", ["fixed"]):
        assert store.alert_evidence(alert["alert_id"])[-1]["source"] == "inventory"


def test_a_version_that_still_depends_on_them_carries_them_forward(
    store: Store, derive_upstream: Callable[..., Path]
) -> None:
    open_everything(store, derive_upstream)
    opened = [a["alert_id"] for a in store.alerts_for("m", ["open"])]
    version = store.add_version("m", {}, "1" * 64, [BASE, DOI_DATASET, HUB_DATASET])
    result = reevaluate_version(store, "m", version)
    assert result["fixed"] == []
    assert sorted(result["carried_forward"]) == sorted(opened)
    assert {a["current_version"] for a in store.alerts_for("m", ["open"])} == {2}


def test_untying_the_paper_fixes_only_the_paper_alert(
    store: Store, derive_upstream: Callable[..., Path]
) -> None:
    open_everything(store, derive_upstream)
    untied = DOI_DATASET | {"paper_dois": []}
    version = store.add_version("m", {}, "1" * 64, [BASE, untied, HUB_DATASET])
    reevaluate_version(store, "m", version)
    found = states(store)
    assert found["paper_retracted"] == ("fixed", 2)
    assert found["dataset_retracted"] == ("open", None)


def test_alert_dismiss_works_on_the_new_kinds(
    store: Store, derive_upstream: Callable[..., Path]
) -> None:
    opened = open_everything(store, derive_upstream)
    for kind in ("base_model_disabled", "licence_changed", "dataset_removed"):
        dismissed = dismiss_alert(store, opened[kind], reason="risk_accepted", by="Owner")
        assert dismissed["state"] == "dismissed"
        assert dismissed["dismissal_reason"] == "risk_accepted"

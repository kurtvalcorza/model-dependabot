"""Hub model info for the base model (T042; research U7, FR-011 to FR-013).

Every answer is a recording under ``tests/fixtures/hf_upstream`` or a state derived from one in the
test: ``model-normal`` (``openai-community/gpt2``), ``model-gated`` (``meta-llama/Llama-3.1-8B``,
``gated: "manual"``), ``model-missing`` (HTTP 401) and ``model-disabled``
(``sd-concepts-library/dyoudim-style``, HTTP 200 with ``disabled: true``).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from conftest import fixture_json
from model_dependabot.lifecycle import run_check
from model_dependabot.sources import hf
from model_dependabot.sources.fetcher import RecordedFetcher, SourceFailedError
from model_dependabot.store import Store

GPT2 = "openai-community/gpt2"
GPT2_SHA = "607a30d783dfa663caf39e06633721c8d4cfcd7e"
GATED = "meta-llama/Llama-3.1-8B"
MISSING = "model-dependabot-fixture/does-not-exist"
DISABLED = "sd-concepts-library/dyoudim-style"
PURL = f"pkg:huggingface/openai-community/gpt2@{GPT2_SHA}"
MOMENT = datetime(2026, 10, 24, 6, 0, tzinfo=UTC)


def _read(root: Path, repo: str) -> hf.HubModel:
    return hf.read_model(RecordedFetcher(root), repo)


def test_a_normal_model_reads_every_expanded_field(derive_upstream: Callable[..., Path]) -> None:
    model = _read(derive_upstream(), GPT2)
    assert model.outcome == "reachable"
    assert (model.disabled, model.gated, model.private) == (False, "false", False)
    assert model.sha == GPT2_SHA
    assert model.licence == "mit"
    assert model.last_modified == "2024-02-19T10:57:45.000Z"
    assert model.card == {"language": "en", "tags": ["exbert"], "license": "mit"}
    assert model.new_version is None
    assert model.unrecognised is None


def test_the_gated_model_reads_manual(derive_upstream: Callable[..., Path]) -> None:
    model = _read(derive_upstream(), GATED)
    assert (model.outcome, model.gated, model.licence) == ("reachable", "manual", "llama3.1")


def test_the_disabled_model_reads_disabled(derive_upstream: Callable[..., Path]) -> None:
    model = _read(derive_upstream(), DISABLED)
    assert (model.outcome, model.disabled, model.unrecognised) == ("reachable", True, None)


@pytest.mark.parametrize("status", [401, 403, 404])
def test_401_403_and_404_are_refused(status: int, derive_upstream: Callable[..., Path]) -> None:
    body = fixture_json("hf_upstream/model-missing")
    extra = {"m": {"url": hf.model_info_url(MISSING), "status": status, "body": body}}
    model = _read(derive_upstream(extra=extra), MISSING)
    assert (model.outcome, model.response.status) == ("refused", status)
    assert model.disabled is None


def test_the_recorded_401_is_refused(derive_upstream: Callable[..., Path]) -> None:
    assert _read(derive_upstream(), MISSING).outcome == "refused"


@pytest.mark.parametrize("status", [500, 502, 503])
def test_a_5xx_is_a_source_failure(status: int, derive_upstream: Callable[..., Path]) -> None:
    extra = {"m": {"url": hf.model_info_url(GPT2), "status": status, "body": "busy"}}
    with pytest.raises(SourceFailedError):
        _read(derive_upstream(extra=extra), GPT2)


@pytest.mark.parametrize("reason", ["timed out", "connection refused"])
def test_a_timeout_or_connection_error_is_a_source_failure(
    reason: str, derive_upstream: Callable[..., Path]
) -> None:
    with pytest.raises(SourceFailedError):
        _read(derive_upstream(errors={"hf_upstream/model-normal": reason}), GPT2)


def test_the_new_version_pointer_is_read(derive_upstream: Callable[..., Path]) -> None:
    def pointer(body: dict[str, Any]) -> dict[str, Any]:
        body["cardData"]["new_version"] = "openai-community/gpt2-large"
        return body

    model = _read(derive_upstream(changes={"hf_upstream/model-normal": pointer}), GPT2)
    assert model.new_version == "openai-community/gpt2-large"


def test_the_card_hash_leaves_out_licence_fields_and_new_version() -> None:
    card = {"language": "en", "tags": ["exbert"]}
    canonical = json.dumps(card, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    noisy = card | {"license": "mit", "license_name": "x", "license_link": "y", "new_version": "z"}
    assert hf.card_hash(card) == expected
    assert hf.card_hash(noisy) == expected
    assert hf.card_hash({"tags": ["exbert"], "language": "en"}) == expected
    assert hf.card_hash(card | {"language": "de"}) != expected


def test_the_observation_stores_the_card_hash_and_pointer(
    tmp_path: Path, derive_upstream: Callable[..., Path]
) -> None:
    with Store(tmp_path / "md.db", now=lambda: MOMENT) as store:
        _register(store)
        run_check(store, RecordedFetcher(derive_upstream()), ["m"], ("hf-hub",))
        [observation] = store.observations(PURL, "hf-hub")
    card = fixture_json("hf_upstream/model-normal")["cardData"]
    assert observation["card_hash"] == hf.card_hash(card)
    assert observation["new_version_pointer"] is None


def _register(store: Store) -> None:
    store.add_model("m")
    entry = {"kind": "base_model", "identifier": PURL, "pinned": True, "name": GPT2}
    store.add_version("m", {}, "0" * 64, [entry | {"version": GPT2_SHA}])


@pytest.mark.parametrize("value", ["true", 1, {"reason": "x"}])
def test_a_disabled_answer_of_another_shape_is_a_watch_event_not_an_alert(
    value: object, tmp_path: Path, derive_upstream: Callable[..., Path]
) -> None:
    """U7's fail-safe: only HTTP 200 with ``disabled: true`` (the recorded shape) opens an alert."""

    def shape(body: dict[str, Any]) -> dict[str, Any]:
        return body | {"disabled": value}

    root = derive_upstream(changes={"hf_upstream/model-normal": shape})
    assert _read(root, GPT2).unrecognised is not None
    with Store(tmp_path / "md.db", now=lambda: MOMENT) as store:
        _register(store)
        run_check(store, RecordedFetcher(root), ["m"], ("hf-hub",))
        assert store.alerts_for("m") == []
        [event] = [e for e in store.watch_events("m") if e["entry_identifier"] == PURL]
        [observation] = store.observations(PURL, "hf-hub")
        assert event["detail"]["disabled"] == value
        assert event["detail"]["reason"] == hf.UNRECOGNISED_DISABLED
        assert [e["evidence_id"] for e in event["evidence"]] == [observation["evidence_ref"]]

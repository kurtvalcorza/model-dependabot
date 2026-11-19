"""The advisory view over alerts the real lifecycle raised (review round 1, M10-R4).

The fixture store of ``tests/fixtures/advice/build.py`` writes alerts through the ``Store`` API.
Here a real ``hf-hub`` check, on the recorded answer for ``openai-community/gpt2``
(``hf_upstream/model-normal``) changed to ``disabled: true`` with another licence, raises
``base_model_disabled`` (MDB501) and ``licence_changed`` (MDB401), as
``tests/integration/test_upstream_fixed.py`` does. If the lifecycle ever renames a cause key the
resolver reads, these views stop resolving and this test fails.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from model_dependabot.assurance.advice import advice_view
from model_dependabot.lifecycle import run_check
from model_dependabot.sources.fetcher import RecordedFetcher
from model_dependabot.store import Store

MOMENT = datetime(2026, 10, 24, 6, 0, tzinfo=UTC)
GPT2 = "openai-community/gpt2"
GPT2_SHA = "607a30d783dfa663caf39e06633721c8d4cfcd7e"
BASE = {
    "kind": "base_model",
    "identifier": f"pkg:huggingface/{GPT2}@{GPT2_SHA}",
    "pinned": True,
    "name": GPT2,
    "version": GPT2_SHA,
    "recorded_licence": "MIT",
    "licence_form": "spdx",
}


def _disabled(body: dict[str, Any]) -> dict[str, Any]:
    body["cardData"]["license"] = "cc-by-nc-4.0"
    return body | {"disabled": True}


def test_real_base_model_alerts_resolve_to_the_declared_base_model(
    tmp_path: Path, derive_upstream: Callable[..., Path]
) -> None:
    root = derive_upstream(changes={"hf_upstream/model-normal": _disabled})
    with Store(tmp_path / "md.db", now=lambda: MOMENT) as store:
        store.add_model("m")
        store.add_version("m", {}, "0" * 64, [BASE], origin="manifest")
        run_check(store, RecordedFetcher(root), ["m"], ("hf-hub",))
        raised = {a["kind"]: a for a in store.alerts_for("m", ["open"])}
        assert {"base_model_disabled", "licence_changed"} <= set(raised)
        for kind in ("base_model_disabled", "licence_changed"):
            view = advice_view(store, raised[kind])
            entry = view["entry"]
            assert (entry["status"], entry["kind"]) == ("resolved", "base_model"), kind
            assert view["relationship"]["value"] == "declared base model", kind
            assert entry["in_current_version"] is True, kind
            evidence = {e["evidence_id"] for e in store.alert_evidence(raised[kind]["alert_id"])}
            assert view["established"], kind
            for statement in view["established"]:
                assert set(statement["evidence_ids"]) <= evidence, kind
            assert "not recorded" not in " ".join(s["text"] for s in view["review_steps"]), kind

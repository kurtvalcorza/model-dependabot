"""``alerts``, ``alert show`` and ``history`` for the new kinds (T054, T055; contracts/cli.md).

Offline. The base-model alerts come from a scheduled ``check`` against answers derived from the
recorded hub answer for ``openai-community/gpt2`` (``disabled: true`` and a changed licence). The
dataset alerts and the redacted takedown-log evidence are written to the store in the shapes the
checks write; the redacted fields are the ones research U10 drops from the takedown log.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from model_dependabot.cli import EXIT_OK, main, make_handlers
from model_dependabot.sources.fetcher import RecordedFetcher
from model_dependabot.store import Store

GPT2 = "openai-community/gpt2"
GPT2_SHA = "607a30d783dfa663caf39e06633721c8d4cfcd7e"
PURL = f"pkg:huggingface/openai-community/gpt2@{GPT2_SHA}"
DOI = "10.5281/zenodo.3242074"
HUB = "hf-dataset:yavon/muxue@0123456789abcdef0123456789abcdef01234567"
NEW_KINDS = {
    "dataset_retracted",
    "paper_retracted",
    "dataset_removed",
    "dataset_not_findable",
    "licence_changed",
    "base_model_disabled",
    "base_model_unavailable",
}
EVIDENCE_KEYS = {
    "source",
    "url",
    "retrieved_at",
    "matched_identifier",
    "original_sha256",
    "body_sha256",
    "redacted_fields",
}
Invoke = Callable[..., tuple[int, Any]]


def change(body: dict[str, Any]) -> dict[str, Any]:
    body["cardData"]["license"] = "cc-by-nc-4.0"
    return body | {"disabled": True}


@pytest.fixture
def cli(
    tmp_path: Path, derive_upstream: Callable[..., Path], capsys: pytest.CaptureFixture[str]
) -> Invoke:
    db = tmp_path / "db" / "md.db"
    db.parent.mkdir()
    with Store(db) as store:
        store.add_model("m")
        base = {
            "kind": "base_model",
            "identifier": PURL,
            "pinned": True,
            "name": GPT2,
            "version": GPT2_SHA,
            "recorded_licence": "MIT",
            "licence_form": "spdx",
        }
        store.add_version("m", {}, "0" * 64, [base])
    root = derive_upstream(changes={"hf_upstream/model-normal": change})
    handlers = make_handlers(fetcher=RecordedFetcher(root))

    def invoke(*argv: str, as_json: bool = True) -> tuple[int, Any]:
        code = main([*argv, "--db", str(db), *(["--json"] if as_json else [])], handlers=handlers)
        out = capsys.readouterr().out
        return code, (json.loads(out) if out.strip() else None) if as_json else out

    assert invoke("check", "--all", "--scheduled", "--source", "hf-hub")[0] == EXIT_OK
    with Store(db) as store:
        received = b"date,requesting_entity,file,reported_content\n2026-09-04,X,y.pdf,yavon/muxue\n"
        evidence = store.add_evidence(
            source="hf-takedowns",
            url="https://huggingface.co/datasets/huggingface-legal/takedown-notices/resolve/main/index.csv",
            retrieved_at=datetime(2026, 10, 24, 2, 15, tzinfo=UTC),
            matched_identifier=HUB,
            body=b"date,reported_content\n2026-09-04,yavon/muxue\n",
            original_sha256=hashlib.sha256(received).hexdigest(),
            redacted_fields=["file", "requesting_entity"],
        )
        causes = {
            "dataset_removed": {"identifier": HUB, "dataset": HUB, "host": "huggingface"},
            "dataset_retracted": {"identifier": DOI, "dataset": DOI},
            "paper_retracted": {"identifier": DOI, "dataset": DOI, "paper_doi": "10.1/p"},
            "dataset_not_findable": {"identifier": DOI, "dataset": DOI},
            "base_model_unavailable": {"identifier": PURL, "base_model": PURL},
        }
        for kind, cause in causes.items():
            store.insert_alert(
                model_id="m",
                kind=kind,
                cause_key=f"{kind}:{cause['identifier']}",
                cause=cause,
                severity="LOW" if kind == "base_model_unavailable" else "HIGH",
                severity_origin="policy",
                opened_in_version=1,
                evidence_ids=[evidence],
            )
    return invoke


def by_kind(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {alert["kind"]: alert for alert in payload["alerts"]}


def test_alerts_json_lists_every_new_kind_with_policy_severity_and_the_trigger(
    cli: Invoke,
) -> None:
    code, payload = cli("alerts", "m")
    assert code == EXIT_OK
    alerts = by_kind(payload)
    assert set(alerts) == NEW_KINDS
    for alert in alerts.values():
        assert alert["severity_origin"] == "policy"
        for evidence in alert["evidence"]:
            assert set(evidence) >= EVIDENCE_KEYS
    assert alerts["base_model_disabled"]["severity"] == "MODERATE"
    assert alerts["licence_changed"]["severity"] == "HIGH"
    assert payload["last_check"]["trigger"] == "scheduled"
    assert payload["last_check"]["sources"] == {"hf-hub": "ok"}


def test_alert_show_displays_both_hashes_and_the_redacted_fields(cli: Invoke) -> None:
    _, payload = cli("alerts", "m")
    removed = by_kind(payload)["dataset_removed"]
    code, shown = cli("alert", "show", str(removed["alert_id"]))
    assert code == EXIT_OK
    (evidence,) = shown["evidence"]
    assert evidence["redacted_fields"] == ["file", "requesting_entity"]
    assert evidence["original_sha256"] != evidence["body_sha256"]
    code, text = cli("alert", "show", str(removed["alert_id"]), as_json=False)
    assert code == EXIT_OK
    assert evidence["original_sha256"] in text
    assert evidence["body_sha256"] in text
    assert "redacted: file, requesting_entity" in text


def test_the_text_output_shows_a_location_for_every_new_kind(cli: Invoke) -> None:
    code, text = cli("alerts", "m", as_json=False)
    assert code == EXIT_OK
    assert "None" not in text
    for kind in NEW_KINDS:
        line = next(line for line in text.splitlines() if f" {kind} " in line)
        assert PURL in line or DOI in line or HUB in line
    assert "MIT -> CC-BY-NC-4.0" in text
    assert "paper 10.1/p" in text


def test_history_lists_closed_new_kinds_with_how_they_closed(cli: Invoke, tmp_path: Path) -> None:
    _, payload = cli("alerts", "m")
    alerts = by_kind(payload)
    closing = {
        "base_model_unavailable": "cleared",
        "licence_changed": "cleared",
        "dataset_retracted": "withdrawn",
    }
    with Store(tmp_path / "db" / "md.db") as store:
        for kind, state in closing.items():
            store.close_alert(alerts[kind]["alert_id"], state=state)
    code, history = cli("history", "m")
    assert code == EXIT_OK
    assert {item["kind"]: item["outcome"] for item in history["history"]} == closing
    code, text = cli("history", "m", as_json=False)
    assert code == EXIT_OK
    assert "None" not in text
    assert text.count("by its source") == 3

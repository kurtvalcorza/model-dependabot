"""Claim states in the view (T024, FR-013, feature 003 decision D6)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from model_dependabot.assurance.advice import advice_view
from model_dependabot.store import Store

NOW = datetime(2026, 11, 20, 9, 0, tzinfo=UTC)


def view(db: Path, alert_id: int) -> dict:
    with Store(db, now=lambda: NOW) as store:
        alert = store.get_alert(alert_id)
        assert alert is not None
        return advice_view(store, alert)


def test_an_imported_claim_is_unverified_and_never_established(
    advice_db: tuple[Path, dict[str, int]],
) -> None:
    db, ids = advice_db
    advice = view(db, ids["imported_package"])
    assert [(c["field"], c["origin"], c["verification"]) for c in advice["claims"]] == [
        ("sha256", "import", "unverified")
    ]
    hashes = advice["claims"][0]["value"]
    for statement in advice["established"]:
        assert not any(value in statement["text"] for value in hashes)


def test_a_contradicted_claim_shows_that_state_and_is_not_established(
    advice_db: tuple[Path, dict[str, int]],
) -> None:
    db, ids = advice_db
    build_ids = ids
    with Store(db, now=lambda: NOW) as store:
        store.add_model("contradicted-model")
        entry = {
            "kind": "weight_file",
            "identifier": "sha256:" + "e5" * 32,
            "pinned": True,
            "location": "weights/claimed.safetensors",
            "format": "safetensors",
            "can_run_code": False,
        }
        store.add_version("contradicted-model", {}, "7" * 64, [entry], origin="import")
        evidence = store.add_evidence(
            source="format-check",
            url="",
            retrieved_at=NOW,
            matched_identifier=entry["identifier"],
            body=b"{}",
        )
        store.add_claim_check(
            model_id="contradicted-model",
            version=1,
            entry_identifier=entry["identifier"],
            claim="code_free",
            run_id=None,
            outcome="contradicted",
            measured_format="pickle",
            measured_can_run_code=True,
            reason="the bytes are a pickle",
            evidence_id=evidence,
        )
        alert_id = store.insert_alert(
            model_id="contradicted-model",
            kind="format_policy",
            cause_key=f"format_policy:{'e5' * 32}",
            cause={"identifier": entry["identifier"], "location": entry["location"]},
            severity="HIGH",
            severity_origin="policy",
            opened_in_version=1,
            evidence_ids=[evidence],
        )
        alert = store.get_alert(alert_id)
        assert alert is not None
        advice = advice_view(store, alert)
    states = {c["field"]: c["verification"] for c in advice["claims"]}
    assert states["format"] == "contradicted" and states["can_run_code"] == "contradicted"
    assert all("safetensors" not in s["text"] for s in advice["established"])
    assert build_ids  # the fixture store's own alerts are untouched


def test_an_owner_version_s_claims_read_owner(advice_db: tuple[Path, dict[str, int]]) -> None:
    db, ids = advice_db
    advice = view(db, ids["package_advisory"])
    assert {c["verification"] for c in advice["claims"]} == {"owner"}

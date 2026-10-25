"""Storage additions for the upstream watch (data-model.md, tasks T008)."""

from __future__ import annotations

import hashlib
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from model_dependabot.store import ALERT_KINDS, ALERT_STATES, ENTRY_FIELDS, WATCH_KINDS, Store

NOW = datetime(2026, 10, 24, 2, 15, 0, tzinfo=UTC)

OBSERVATION_FIELDS = {
    "run_id",
    "source",
    "item",
    "http_status",
    "redirected_to",
    "outcome",
    "disabled",
    "gated",
    "head_revision",
    "declared_licence",
    "licence_form",
    "card_hash",
    "new_version_pointer",
    "updates",
    "removal",
    "evidence_ref",
}

NEW_ALERT_KINDS = {
    "dataset_retracted",
    "paper_retracted",
    "dataset_removed",
    "dataset_not_findable",
    "licence_changed",
    "base_model_disabled",
    "base_model_unavailable",
}
NEW_WATCH_KINDS = {
    "base_model_new_revision",
    "base_model_new_version_pointer",
    "gating_changed",
    "card_changed",
    "base_model_refused",
    "dataset_new_version",
    "dataset_replaced",
    "dataset_moved",
    "dataset_unreachable",
    "paper_not_found",
    "licence_unrecognised",
    "licence_missing",
    "upstream_notice",
}


@pytest.fixture
def store(tmp_path: Path) -> Store:
    with Store(tmp_path / "db.sqlite", now=lambda: NOW) as opened:
        yield opened


def test_a_fresh_database_has_the_new_tables(store: Store) -> None:
    assert {"upstream_observations", "doi_routing", "takedown_notices"} <= store.tables()
    assert store.columns("upstream_observations") >= OBSERVATION_FIELDS
    assert {"doi", "agency", "repository", "repository_id", "looked_up_at"} <= store.columns(
        "doi_routing"
    )


def test_the_takedown_table_has_no_requesting_entity_and_no_file(store: Store) -> None:
    # Owner ruling: the log's ``file`` column can name the requesting party, so it is not kept.
    assert store.columns("takedown_notices") == {"notice_id", "date", "reported_content"}


def test_takedown_notices_refuse_a_requesting_entity_or_a_file(store: Store) -> None:
    store.replace_takedown_notices([{"date": "2026-09-04", "reported_content": "owner/name"}])
    assert store.takedown_notices() == [{"date": "2026-09-04", "reported_content": "owner/name"}]
    with pytest.raises(ValueError, match="requesting_entity"):
        store.replace_takedown_notices(
            [{"date": "d", "requesting_entity": "x", "reported_content": "r"}]
        )
    with pytest.raises(ValueError, match="file"):
        store.replace_takedown_notices([{"date": "d", "reported_content": "r", "file": "f.md"}])
    assert store.takedown_notices() == [{"date": "2026-09-04", "reported_content": "owner/name"}]
    store.replace_takedown_notices([])
    assert store.takedown_notices() == []


def test_evidence_records_both_hashes_and_the_redacted_fields(store: Store) -> None:
    columns = store.columns("evidence")
    assert {"original_sha256", "body_sha256", "redacted_fields"} <= columns
    evidence_id = store.add_evidence(
        source="zenodo",
        url="https://zenodo.org/api/records/1",
        retrieved_at=NOW,
        matched_identifier="10.5281/zenodo.1",
        body=b"{}",
        original_sha256="b" * 64,
        redacted_fields=["note", "removed_by"],
    )
    record = store.get_evidence(evidence_id)
    assert record["original_sha256"] == "b" * 64
    assert record["body_sha256"] == hashlib.sha256(b"{}").hexdigest()
    assert record["redacted_fields"] == ["note", "removed_by"]


def test_001_evidence_has_equal_hashes_and_no_redacted_fields(store: Store) -> None:
    evidence_id = store.add_evidence(
        source="osv",
        url="https://api.osv.dev/v1/vulns/X",
        retrieved_at=NOW,
        matched_identifier="pkg:pypi/x@1",
        body=b'{"id":"X"}',
    )
    record = store.get_evidence(evidence_id)
    assert record["original_sha256"] == record["body_sha256"]
    assert record["redacted_fields"] == []


def test_check_runs_record_their_trigger(store: Store) -> None:
    assert "trigger" in store.columns("check_runs")
    scheduled = store.start_check_run(scope="all", trigger="scheduled")
    default = store.start_check_run(scope="all")
    assert store.get_check_run(scheduled)["trigger"] == "scheduled"
    assert store.get_check_run(default)["trigger"] == "on_demand"
    with pytest.raises(sqlite3.IntegrityError):
        store.start_check_run(scope="all", trigger="sometimes")


def test_doi_routing_is_lower_case_and_cached(store: Store) -> None:
    store.set_routing("10.5281/ZENODO.3242074", agency="DataCite")
    routing = store.get_routing("10.5281/zenodo.3242074")
    assert routing["doi"] == "10.5281/zenodo.3242074"
    assert routing["agency"] == "DataCite"
    assert routing["looked_up_at"] == "2026-10-24T02:15:00Z"
    store.set_routing("10.5281/zenodo.3242074", repository="zenodo", repository_id="3242074")
    routing = store.get_routing("10.5281/ZENODO.3242074")
    assert (routing["agency"], routing["repository"], routing["repository_id"]) == (
        "DataCite",
        "zenodo",
        "3242074",
    )
    assert store.get_routing("10.1/unknown") is None


def test_doi_routing_repository_is_zenodo_figshare_or_other(store: Store) -> None:
    store.set_routing("10.1/x", agency="DataCite", repository="other")
    with pytest.raises(sqlite3.IntegrityError):
        store.set_routing("10.1/y", agency="DataCite", repository="dryad")


def test_observations_are_stored_and_read_in_order(store: Store) -> None:
    run = store.start_check_run(scope="all", trigger="scheduled")
    first = store.add_observation(
        run_id=run,
        source="hf-hub",
        item="hf-dataset:o/n@" + "a" * 40,
        http_status=200,
        outcome="reachable",
        disabled=False,
        gated="false",
        head_revision="a" * 40,
    )
    second = store.add_observation(
        run_id=run,
        source="hf-hub",
        item="hf-dataset:o/n@" + "a" * 40,
        http_status=200,
        outcome="reachable",
        disabled=True,
        gated="manual",
        updates=[{"type": "x"}],
        removal={"notice_date": "2026-09-04"},
    )
    rows = store.observations("hf-dataset:o/n@" + "a" * 40, "hf-hub")
    assert [row["observation_id"] for row in rows] == [first, second]
    assert rows[1]["disabled"] is True and rows[0]["disabled"] is False
    assert rows[1]["updates"] == [{"type": "x"}]
    assert rows[1]["removal"] == {"notice_date": "2026-09-04"}
    assert rows[1]["trigger"] == "scheduled"
    previous = store.previous_observation("hf-dataset:o/n@" + "a" * 40, "hf-hub", second)
    assert previous["observation_id"] == first
    assert store.previous_observation("hf-dataset:o/n@" + "a" * 40, "hf-hub", first) is None


def test_observation_outcome_is_one_of_the_five(store: Store) -> None:
    run = store.start_check_run(scope="all")
    with pytest.raises(sqlite3.IntegrityError):
        store.add_observation(
            run_id=run, source="zenodo", item="10.1/x", http_status=500, outcome="failed"
        )


def test_the_new_alert_and_watch_kinds_and_no_new_state() -> None:
    assert set(ALERT_KINDS) >= NEW_ALERT_KINDS
    assert set(WATCH_KINDS) >= NEW_WATCH_KINDS
    assert ALERT_STATES == ("open", "fixed", "dismissed", "withdrawn", "cleared")


def test_a_new_kind_alert_closes_as_cleared(store: Store) -> None:
    store.add_model("m")
    store.add_version("m", {}, "0" * 64, [])
    alert_id = store.insert_alert(
        model_id="m",
        kind="base_model_unavailable",
        cause_key="base_model_unavailable:p",
        cause={},
        severity="LOW",
        severity_origin="policy",
        opened_in_version=1,
        evidence_ids=[],
    )
    store.close_alert(alert_id, state="cleared")
    assert store.get_alert(alert_id)["state"] == "cleared"


def test_inventory_entries_carry_licences_and_paper_dois(store: Store) -> None:
    assert {"recorded_licence", "licence_form", "paper_dois"} <= set(ENTRY_FIELDS)
    entry = dict.fromkeys(ENTRY_FIELDS)
    entry |= {
        "kind": "dataset",
        "identifier": "10.1/x",
        "pinned": True,
        "recorded_licence": "CC-BY-4.0",
        "licence_form": "spdx",
        "paper_dois": ["10.1/p"],
    }
    store.add_model("m")
    store.add_version("m", {}, "0" * 64, [entry])
    stored = store.entries("m", 1)[0]
    assert stored["recorded_licence"] == "CC-BY-4.0"
    assert stored["licence_form"] == "spdx"
    assert stored["paper_dois"] == ["10.1/p"]

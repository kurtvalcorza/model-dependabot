"""Tests for the SQLite store and the content-addressed evidence store.

See data-model.md and research R6.
"""

from __future__ import annotations

import hashlib
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from model_dependabot.store import Store

NOW = datetime(2026, 10, 24, 8, 0, 0, tzinfo=UTC)
INVENTORY = {"bomFormat": "CycloneDX", "specVersion": "1.7", "version": 1, "components": []}
WEIGHT = {
    "kind": "weight_file",
    "identifier": "sha256:" + "ab" * 32,
    "pinned": True,
    "location": "weights/model.safetensors",
    "size": 1024,
    "format": "safetensors",
    "can_run_code": False,
}
PACKAGE = {
    "kind": "package",
    "identifier": "pkg:pypi/pillow@12.3.0",
    "pinned": True,
    "name": "pillow",
    "version": "12.3.0",
    "hashes": ["sha256:" + "cd" * 32],
}
GAP = {"kind": "package", "identifier": None, "pinned": False, "gap_reason": "no exact version"}


@pytest.fixture
def store(tmp_path: Path) -> Store:
    with Store(tmp_path / "model-dependabot.db", now=lambda: NOW) as opened:
        yield opened


@pytest.fixture
def model(store: Store) -> str:
    store.add_model("example-model", name="Example", owner="Owner")
    store.add_version("example-model", INVENTORY, "11" * 32, [WEIGHT, PACKAGE, GAP])
    return "example-model"


def test_schema_has_every_table_of_the_data_model(store: Store) -> None:
    expected = {
        "models",
        "model_versions",
        "inventory_entries",
        "advisories",
        "check_runs",
        "evidence",
        "alerts",
        "watch_events",
    }
    assert expected <= store.tables()


@pytest.mark.parametrize(
    ("table", "columns"),
    [
        (
            "models",
            {
                "model_id",
                "name",
                "owner",
                "format_policy",
                "format_policy_set_by",
                "format_policy_set_at",
                "created_at",
            },
        ),
        (
            "model_versions",
            {"model_id", "version", "registered_at", "manifest_sha256", "inventory"},
        ),
        (
            "inventory_entries",
            {
                "model_id",
                "version",
                "kind",
                "identifier",
                "pinned",
                "gap_reason",
                "location",
                "size",
                "format",
                "can_run_code",
                "hub_repo",
                "hub_revision",
                "hub_file",
                "name",
                "package_version",
                "hashes",
            },
        ),
        (
            "advisories",
            {
                "source",
                "advisory_id",
                "aliases",
                "modified",
                "withdrawn",
                "severity",
                "severity_origin",
                "affected",
                "evidence_id",
            },
        ),
        ("check_runs", {"run_id", "started_at", "finished_at", "scope", "sources"}),
        (
            "evidence",
            {
                "evidence_id",
                "source",
                "url",
                "retrieved_at",
                "matched_identifier",
                "body_sha256",
                "detail",
            },
        ),
        (
            "alerts",
            {
                "alert_id",
                "model_id",
                "opened_in_version",
                "current_version",
                "kind",
                "cause_key",
                "cause",
                "severity",
                "severity_origin",
                "state",
                "opened_at",
                "closed_at",
                "closed_by_version",
                "dismissal_reason",
                "dismissed_by",
                "note",
            },
        ),
        (
            "watch_events",
            {
                "model_id",
                "version",
                "entry_identifier",
                "kind",
                "detail",
                "first_seen",
                "last_seen",
            },
        ),
    ],
)
def test_tables_have_the_data_model_fields(store: Store, table: str, columns: set[str]) -> None:
    assert columns <= store.columns(table)


def test_models_default_to_the_default_format_policy(store: Store) -> None:
    store.add_model("m", name="M", owner="O")
    model = store.get_model("m")
    assert model["format_policy"] == "default"
    assert model["created_at"] == "2026-10-24T08:00:00Z"


def test_versions_are_numbered_in_registration_order(store: Store, model: str) -> None:
    assert store.add_version(model, INVENTORY, "22" * 32, [WEIGHT]) == 2
    assert store.latest_version(model) == 2
    first = store.get_version(model, 1)
    assert first["inventory"] == INVENTORY
    assert first["manifest_sha256"] == "11" * 32
    assert first["registered_at"] == "2026-10-24T08:00:00Z"


def test_entries_are_stored_with_their_fields(store: Store, model: str) -> None:
    entries = store.entries(model, 1)
    assert len(entries) == 3
    weight = next(e for e in entries if e["kind"] == "weight_file")
    assert weight["identifier"] == WEIGHT["identifier"]
    assert weight["pinned"] is True
    assert weight["can_run_code"] is False
    assert weight["size"] == 1024
    package = next(e for e in entries if e["identifier"] == PACKAGE["identifier"])
    assert package["name"] == "pillow"
    assert package["version"] == "12.3.0"
    assert package["hashes"] == PACKAGE["hashes"]
    gap = next(e for e in entries if not e["pinned"])
    assert gap["gap_reason"] == "no exact version"


def test_an_unpinned_entry_needs_a_gap_reason(store: Store) -> None:
    store.add_model("m", name="M", owner="O")
    with pytest.raises(sqlite3.IntegrityError):
        store.add_version("m", INVENTORY, "33" * 32, [{"kind": "package", "pinned": False}])
    assert store.latest_version("m") is None


def test_entry_kind_is_checked(store: Store) -> None:
    store.add_model("m", name="M", owner="O")
    with pytest.raises(sqlite3.IntegrityError):
        store.add_version("m", INVENTORY, "33" * 32, [{**WEIGHT, "kind": "notebook"}])


def test_a_recorded_version_cannot_be_updated(store: Store, model: str) -> None:
    # FR-005: a change is a new model version, never an edit.
    with pytest.raises(sqlite3.DatabaseError, match="immutable"):
        store.conn.execute(
            "UPDATE model_versions SET inventory = '{}' WHERE model_id = ?", (model,)
        )
    with pytest.raises(sqlite3.DatabaseError, match="immutable"):
        store.conn.execute("DELETE FROM model_versions WHERE model_id = ?", (model,))
    with pytest.raises(sqlite3.DatabaseError, match="immutable"):
        store.conn.execute("UPDATE inventory_entries SET pinned = 0, gap_reason = 'x'")
    with pytest.raises(sqlite3.DatabaseError, match="immutable"):
        store.conn.execute("DELETE FROM inventory_entries")
    assert store.get_version(model, 1)["inventory"] == INVENTORY


def test_evidence_bodies_are_files_named_by_sha256(store: Store) -> None:
    body = b'{"id":"GHSA-xxxx-xxxx-xxxx"}'
    digest = hashlib.sha256(body).hexdigest()
    evidence_id = store.add_evidence(
        source="osv.dev",
        url="https://api.osv.dev/v1/vulns/GHSA-xxxx-xxxx-xxxx",
        retrieved_at=NOW,
        matched_identifier="pkg:pypi/pillow@12.3.0",
        body=body,
        detail={"local_match": True},
    )
    record = store.get_evidence(evidence_id)
    assert record["body_sha256"] == digest
    assert record["retrieved_at"] == "2026-10-24T08:00:00Z"
    assert record["detail"] == {"local_match": True}
    path = store.evidence_dir / digest
    assert path.read_bytes() == body
    assert store.read_body(digest) == body


def test_the_same_body_is_stored_once(store: Store) -> None:
    for _ in range(2):
        store.add_evidence(
            source="osv.dev", url="u", retrieved_at=NOW, matched_identifier="i", body=b"same"
        )
    assert [p.name for p in store.evidence_dir.iterdir()] == [hashlib.sha256(b"same").hexdigest()]


def test_a_tampered_body_is_detected(store: Store) -> None:
    digest = store.put_body(b"original")
    (store.evidence_dir / digest).write_bytes(b"changed")
    with pytest.raises(ValueError, match="SHA-256"):
        store.read_body(digest)


def open_alert(store: Store, model: str, cause_key: str) -> int:
    evidence_id = store.add_evidence(
        source="osv.dev", url="u", retrieved_at=NOW, matched_identifier="i", body=b"b"
    )
    return store.insert_alert(
        model_id=model,
        kind="package_advisory",
        cause_key=cause_key,
        cause={"advisory_id": "GHSA-1", "package": "pillow"},
        severity="HIGH",
        severity_origin="database_specific",
        opened_in_version=1,
        evidence_ids=[evidence_id],
    )


def test_at_most_one_open_alert_per_model_and_cause(store: Store, model: str) -> None:
    open_alert(store, model, "package_advisory:GHSA-1:pillow")
    with pytest.raises(sqlite3.IntegrityError):
        open_alert(store, model, "package_advisory:GHSA-1:pillow")


def test_another_cause_or_model_may_have_its_own_open_alert(store: Store, model: str) -> None:
    store.add_model("other", name="Other", owner="O")
    store.add_version("other", INVENTORY, "44" * 32, [PACKAGE])
    open_alert(store, model, "package_advisory:GHSA-1:pillow")
    open_alert(store, model, "package_advisory:GHSA-2:pillow")
    open_alert(store, "other", "package_advisory:GHSA-1:pillow")


def test_a_closed_alert_does_not_block_a_new_open_one(store: Store, model: str) -> None:
    first = open_alert(store, model, "package_advisory:GHSA-1:pillow")
    store.close_alert(first, state="withdrawn")
    second = open_alert(store, model, "package_advisory:GHSA-1:pillow")
    assert store.get_alert(first)["state"] == "withdrawn"
    assert store.get_alert(first)["closed_at"] == "2026-10-24T08:00:00Z"
    assert store.get_alert(second)["state"] == "open"
    assert len(store.get_alert(second)["evidence_ids"]) == 1


def test_alert_state_and_kind_are_checked(store: Store, model: str) -> None:
    alert_id = open_alert(store, model, "package_advisory:GHSA-1:pillow")
    with pytest.raises(sqlite3.IntegrityError):
        store.close_alert(alert_id, state="resolved")
    with pytest.raises(sqlite3.IntegrityError):
        store.insert_alert(
            model_id=model,
            kind="guess",
            cause_key="guess:x",
            cause={},
            severity="LOW",
            severity_origin="policy",
            opened_in_version=1,
            evidence_ids=[],
        )


def test_dismissal_reason_must_be_listed(store: Store, model: str) -> None:
    alert_id = open_alert(store, model, "package_advisory:GHSA-1:pillow")
    with pytest.raises(sqlite3.IntegrityError):
        store.close_alert(alert_id, state="dismissed", dismissal_reason="bored", dismissed_by="P")
    store.close_alert(
        alert_id, state="dismissed", dismissal_reason="risk_accepted", dismissed_by="P"
    )
    assert store.get_alert(alert_id)["dismissal_reason"] == "risk_accepted"


def test_check_runs_record_each_source(store: Store) -> None:
    run_id = store.start_check_run(scope="all")
    store.finish_check_run(run_id, {"osv": "ok", "hf-scan": "failed: timeout"})
    run = store.get_check_run(run_id)
    assert run["sources"] == {"osv": "ok", "hf-scan": "failed: timeout"}
    assert run["started_at"] == run["finished_at"] == "2026-10-24T08:00:00Z"


def test_watch_event_kind_is_checked(store: Store, model: str) -> None:
    with pytest.raises(sqlite3.IntegrityError):
        store.conn.execute(
            "INSERT INTO watch_events (model_id, version, entry_identifier, kind, detail,"
            " first_seen, last_seen) VALUES (?, 1, 'x', 'rumour', '{}', 't', 't')",
            (model,),
        )


def test_the_store_survives_reopening(tmp_path: Path) -> None:
    path = tmp_path / "db" / "model-dependabot.db"
    with Store(path, now=lambda: NOW) as first:
        first.add_model("m", name="M", owner="O")
        first.add_version("m", INVENTORY, "55" * 32, [WEIGHT])
    with Store(path, now=lambda: NOW) as second:
        assert second.latest_version("m") == 1
        assert second.evidence_dir == path.parent / "evidence"

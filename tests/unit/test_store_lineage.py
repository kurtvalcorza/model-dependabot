"""The ``lineage_edges`` table and its store methods (T009, data-model.md, Lineage edge)."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from model_dependabot.lineage.edges import new_edge
from model_dependabot.store import Store

NOW = datetime(2026, 11, 20, 9, 0, tzinfo=UTC)
A = "0123456789abcdef0123456789abcdef01234567"
PURL = f"pkg:huggingface/example-org/base-a@{A}"
BASE = {"kind": "base_model", "identifier": PURL, "pinned": True, "name": "example-org/base-a"}


def edge(**fields: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "position": 0,
        "parent_kind": "hub",
        "parent_repo": "example-org/base-a",
        "parent_revision": A,
        "relationship": "fine-tuned-from",
        "origin": "manifest",
        "state": "owner",
        "source_key": "parents[0]",
        "entry_identifier": PURL,
    }
    return new_edge(**(values | fields))


@pytest.fixture
def store(tmp_path: Path) -> Iterator[Store]:
    with Store(tmp_path / "md.db", now=lambda: NOW) as opened:
        opened.add_model("m")
        yield opened


def test_an_edge_row_can_be_neither_updated_nor_deleted(store: Store) -> None:
    store.add_version("m", {}, "0" * 64, [BASE | {"version": A}], edges=[edge()])
    with pytest.raises(sqlite3.DatabaseError, match="immutable"):
        store.conn.execute("UPDATE lineage_edges SET relationship = 'adapter-for'")
    with pytest.raises(sqlite3.DatabaseError, match="immutable"):
        store.conn.execute("DELETE FROM lineage_edges")


def test_a_second_row_with_the_same_identity_is_refused(store: Store) -> None:
    with pytest.raises(sqlite3.IntegrityError):
        store.add_version("m", {}, "0" * 64, [], edges=[edge(), edge(position=1)])
    assert store.latest_version("m") is None  # all or nothing


def test_edges_without_a_parent_identity_are_kept_apart_by_source_key(store: Store) -> None:
    gaps = [
        edge(
            position=index,
            parent_repo=None,
            parent_revision=None,
            entry_identifier=None,
            relationship="unspecified",
            origin="import",
            state="unverified",
            gap_reason="no Hugging Face purl",
            source_key=f"ancestors[{index}]",
        )
        for index in range(2)
    ]
    version = store.add_version("m", {}, "0" * 64, [], origin="import", edges=gaps)
    assert [e["source_key"] for e in store.edges("m", version)] == ["ancestors[0]", "ancestors[1]"]


def test_the_state_verified_is_refused_and_nothing_is_recorded(store: Store) -> None:
    with pytest.raises(sqlite3.IntegrityError):
        entries = [BASE | {"version": A}]
        store.add_version("m", {}, "0" * 64, entries, edges=[edge(state="verified")])
    assert store.latest_version("m") is None
    assert store.conn.execute("SELECT count(*) FROM inventory_entries").fetchone()[0] == 0


def test_stored_edges_come_back_in_position_order_with_their_version_and_time(
    store: Store,
) -> None:
    second = edge(
        position=1,
        parent_kind="model",
        parent_repo=None,
        parent_revision=None,
        parent_model_id="base",
        parent_version=2,
        relationship="adapter-for",
        source_key="parents[1]",
        entry_identifier=None,
    )
    version = store.add_version("m", {}, "0" * 64, [], edges=[second, edge()])
    first, then = store.edges("m", version)
    assert (first["position"], then["position"]) == (0, 1)
    assert (then["parent_model_id"], then["parent_version"]) == ("base", 2)
    assert first["recorded_at"] == "2026-11-20T09:00:00Z"
    assert (first["model_id"], first["version"]) == ("m", version)
    assert isinstance(first["edge_id"], int)


@pytest.mark.parametrize(
    ("origin", "state"),
    [("manifest", "owner"), ("record", "owner"), ("import", "unverified"), (None, "unverified")],
)
def test_a_version_without_rows_reads_synthesised_edges(
    store: Store, origin: str | None, state: str
) -> None:
    version = store.add_version("m", {}, "f" * 64, [BASE | {"version": A}], origin=origin)
    [synthesised] = store.edges("m", version)
    assert synthesised["relationship"] == "unspecified"
    assert (synthesised["origin"], synthesised["state"]) == (origin, state)
    assert (synthesised["source_key"], synthesised["source_sha256"]) == ("base_model", "f" * 64)
    assert (synthesised["parent_repo"], synthesised["parent_revision"]) == ("example-org/base-a", A)
    assert synthesised["entry_identifier"] == PURL
    assert store.conn.execute("SELECT count(*) FROM lineage_edges").fetchone()[0] == 0


def test_version_exists_answers_by_id_and_version(store: Store) -> None:
    store.add_version("m", {}, "0" * 64, [])
    assert store.version_exists("m", 1)
    assert not store.version_exists("m", 2)
    assert not store.version_exists("other", 1)
    assert store.all_edges() == {("m", 1): []}

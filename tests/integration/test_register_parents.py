"""Registering typed parents (T019, US1 AS1 to AS5, contracts/manifest-parents.md)."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from lineage_support import A, B, Cli, manifest
from model_dependabot.store import Store


@pytest.fixture
def cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> Cli:
    return Cli(tmp_path, capsys)


def test_two_merged_from_parents_register_two_pinned_edges(cli: Cli) -> None:
    payload = cli.ok("register", manifest("merge-two"))
    assert [e["identifier"] for e in payload["entries"]] == [
        f"pkg:huggingface/example-org/base-a@{A}",
        f"pkg:huggingface/example-org/base-b@{B}",
    ]
    edges = payload["lineage"]["edges"]
    assert [(e["parent"]["repo"], e["parent"]["revision"]) for e in edges] == [
        ("example-org/base-a", A),
        ("example-org/base-b", B),
    ]
    assert {(e["relationship"], e["origin"], e["state"], e["gap"]) for e in edges} == {
        ("merged-from", "manifest", "owner", None)
    }
    assert payload["lineage"]["problems"] == []
    shown = cli.ok("inventory", "show", "example-merge")
    assert shown["lineage"]["edges"] == edges


def test_an_adapter_without_a_revision_registers_with_the_gap(cli: Cli) -> None:
    payload = cli.ok("register", manifest("adapter-no-revision"))
    [edge] = payload["lineage"]["edges"]
    assert (edge["relationship"], edge["gap"]) == ("adapter-for", "no revision")
    assert [g["gap_reason"] for g in payload["gaps"]] == ["no revision"]


@pytest.mark.parametrize(
    ("name", "message"),
    [
        ("bad-relationship", "parents[0].relationship must be one of"),
        ("unspecified-relationship", "parents[0].relationship must be one of"),
        ("both-forms", "use either [base_model] or [[parents]], not both"),
        ("hub-and-model", "parents[0] needs exactly one of hub and model"),
    ],
)
def test_an_invalid_parent_list_exits_1_and_records_nothing(
    cli: Cli, name: str, message: str
) -> None:
    code, error = cli.run("register", manifest(name))
    assert code == 1
    assert message in str(error)
    assert not cli.db.exists() or Store(cli.db).model_ids() == []


def test_an_unregistered_model_parent_registers_with_the_gap(cli: Cli) -> None:
    payload = cli.ok("register", manifest("four-types"))
    model_edge = payload["lineage"]["edges"][3]
    assert (model_edge["parent"], model_edge["gap"], model_edge["resolved"]) == (
        {"kind": "model", "model_id": "example-adapter-base", "version": 1},
        "parent not registered",
        False,
    )
    [problem] = payload["lineage"]["problems"]
    assert problem["kind"] == "parent_not_registered"
    code, text = cli.run("inventory", "show", "example-four", as_json=False)
    assert code == 0
    assert "Lineage (4 edges):" in text
    assert "  adapter-for      model:example-adapter-base@1  origin manifest, owner" in text
    assert "[parent not registered]" in text


def test_a_registration_record_gives_origin_record_and_the_record_sha256(
    cli: Cli, tmp_path: Path
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    shutil.copy(manifest("merge-two"), project / "model.toml")
    record = tmp_path / "record.json"
    made = cli.ok("record", str(project / "model.toml"), "--out", str(record))
    payload = cli.ok("register", str(project / "model.toml"), "--from-record", str(record))
    edges = payload["lineage"]["edges"]
    assert {(e["origin"], e["state"]) for e in edges} == {("record", "owner")}
    assert {e["source"]["sha256"] for e in edges} == {made["record_sha256"]}
    assert {e["source"]["file"] for e in edges} == {"record.json"}

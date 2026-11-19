"""Lineage problems through register, audit and check (T033, US4 AS1 to AS6, FR-021)."""

from __future__ import annotations

from pathlib import Path

import pytest

from lineage_support import Cli, manifest


@pytest.fixture
def cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> Cli:
    return Cli(tmp_path, capsys)


def _kinds(payload: dict) -> list[str]:
    return [problem["kind"] for problem in payload["lineage"]["problems"]]


def test_a_mutual_pair_forms_its_cycle_after_the_second_registration(cli: Cli) -> None:
    first = cli.ok("register", manifest("cycle-a"))
    assert _kinds(first) == ["parent_not_registered"]
    second = cli.ok("register", manifest("cycle-b"))
    assert _kinds(second) == ["cycle", "parent_not_registered"]  # example-cycle-c is not there
    assert second["lineage"]["problems"][0]["models"] == ["example-cycle-a@1", "example-cycle-b@1"]
    audit = cli.ok("inventory", "audit", "example-cycle-a")
    assert _kinds(audit) == ["cycle"]
    code, checked = cli.run("check", "example-cycle-a", "--source", "picklescan")
    assert code == 0
    [model] = checked["models"]
    assert [p["kind"] for p in model["lineage"]["problems"]] == ["cycle"]
    assert model["opened"] == [] and model["watch_events"] == []
    code, text = cli.run("check", "example-cycle-a", "--source", "picklescan", as_json=False)
    assert code == 0
    assert (
        "  lineage problem cycle: example-cycle-a v1 -> example-cycle-b v1 -> example-cycle-a v1"
        in text
    )


def test_a_cycle_of_three_and_a_self_reference(cli: Cli) -> None:
    cli.ok("register", manifest("cycle-a"))
    cli.ok("register", manifest("cycle-b"))
    third = cli.ok("register", manifest("cycle-c"))
    cycles = [p["models"] for p in third["lineage"]["problems"] if p["kind"] == "cycle"]
    assert cycles == [["example-cycle-a@1", "example-cycle-b@1", "example-cycle-c@1"]]
    own = cli.ok("register", manifest("self"))
    assert own["lineage"]["problems"][0]["models"] == ["example-self@1"]


def test_duplicate_and_ambiguous_parents_register_with_their_problem(cli: Cli) -> None:
    duplicate = cli.ok("register", manifest("duplicate"))
    assert len(duplicate["lineage"]["edges"]) == 1
    assert _kinds(duplicate) == ["duplicate_parent"]
    ambiguous = cli.ok("register", manifest("ambiguous"))
    assert len(ambiguous["lineage"]["edges"]) == 2
    assert _kinds(ambiguous) == ["ambiguous_relationship"]
    assert len(ambiguous["entries"]) == 1


def test_an_unregistered_reference_resolves_once_its_parent_registers(
    cli: Cli, tmp_path: Path
) -> None:
    child = cli.ok("register", manifest("chain-child"))
    assert _kinds(child) == ["parent_not_registered"]
    parent = tmp_path / "mid.toml"
    parent.write_text('[model]\nid = "example-mid"\n', encoding="utf-8")
    cli.ok("register", str(parent))
    audit = cli.ok("inventory", "audit", "example-child")
    assert _kinds(audit) == []
    [edge] = audit["lineage"]["edges"]
    assert (edge["resolved"], edge["gap"]) == (True, None)


def test_version_2_fine_tuned_from_version_1_is_no_problem(cli: Cli, tmp_path: Path) -> None:
    first = tmp_path / "cont.toml"
    first.write_text('[model]\nid = "example-cont"\n', encoding="utf-8")
    cli.ok("register", str(first))
    second = cli.ok("register", manifest("same-model-v2"), "--model-id", "example-cont")
    assert second["version"] == 2
    assert _kinds(second) == []
    assert _kinds(cli.ok("inventory", "audit", "example-cont")) == []

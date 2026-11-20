"""Findings travel along known, relevant edges (T038, US3 AS1 to AS6, SC-003, FR-014 to FR-020).

Hub answers are the recorded ones of ``tests/fixtures/hf_upstream``: ``model-disabled`` answers
for ``sd-concepts-library/dyoudim-style`` with ``disabled: true``.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from lineage_support import Cli, manifest
from model_dependabot.store import Store

DYOUDIM = "sd-concepts-library/dyoudim-style"
SHA = "bb36f39d9eede01cc139dc4fadd193f1e4879fe3"
TYPES = ("fine-tuned-from", "adapter-for", "merged-from", "quantized-from")
FILE = "sha256:" + "c" * 64


@pytest.fixture
def cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> Cli:
    return Cli(tmp_path, capsys)


@pytest.fixture
def hub(derive_upstream: Callable[..., Path]) -> Path:
    return derive_upstream()


def _manifest(tmp_path: Path, model_id: str, parents: list[str], name: str = "") -> str:
    path = tmp_path / f"{model_id}{name}.toml"
    path.write_text(f'[model]\nid = "{model_id}"\n' + "".join(parents), encoding="utf-8")
    return str(path)


def _hub_parent(revision: str, relationship: str) -> str:
    return (
        f'[[parents]]\nhub = "hf:{DYOUDIM}"\nrevision = "{revision}"\n'
        f'relationship = "{relationship}"\n'
    )


def _model_parent(model_id: str, relationship: str) -> str:
    return f'[[parents]]\nmodel = "{model_id}"\nversion = 1\nrelationship = "{relationship}"\n'


def _alerts(cli: Cli, model_id: str) -> list[dict[str, Any]]:
    return cli.ok("alerts", model_id)["alerts"]


def _inherited(cli: Cli, model_id: str) -> list[dict[str, Any]]:
    events = cli.ok("alerts", model_id)["watch_events"]
    return [event for event in events if event["kind"] == "lineage_inherited"]


def test_a_disabled_parent_opens_one_alert_citing_the_edge(cli: Cli, hub: Path) -> None:
    cli.ok("register", manifest("chain-grandparent"))
    cli.ok("check", "example-grand", "--source", "hf-hub", root=hub)
    [alert] = _alerts(cli, "example-grand")
    assert (alert["kind"], alert["severity"]) == ("base_model_disabled", "MODERATE")
    assert alert["cause"]["edges"] == [
        {
            "relationship": "fine-tuned-from",
            "origin": "manifest",
            "state": "owner",
            "revision": SHA,
            "source_key": "parents[0]",
        }
    ]
    assert [e["source"] for e in alert["evidence"]] == ["hf-hub"]
    _, text = cli.run("alerts", "example-grand", as_json=False)
    assert f"      via fine-tuned-from edge (manifest, owner) at {SHA}" in text


@pytest.mark.parametrize("count", [1, 2, 3, 4])
def test_n_edges_to_one_repository_open_exactly_one_alert(
    cli: Cli, hub: Path, tmp_path: Path, count: int
) -> None:
    revisions = [SHA, "1" * 40, "2" * 40, "3" * 40][:count]
    parents = [_hub_parent(revision, TYPES[i]) for i, revision in enumerate(revisions)]
    cli.ok("register", _manifest(tmp_path, "example-many", parents))
    cli.ok("check", "example-many", "--source", "hf-hub", root=hub)
    [alert] = _alerts(cli, "example-many")
    assert [edge["revision"] for edge in alert["cause"]["edges"]] == revisions
    assert [edge["relationship"] for edge in alert["cause"]["edges"]] == list(TYPES[:count])


def test_a_legacy_base_model_edge_is_named_unspecified(cli: Cli, hub: Path, tmp_path: Path) -> None:
    path = tmp_path / "legacy.toml"
    path.write_text(
        f'[model]\nid = "example-legacy"\n[base_model]\nhub = "hf:{DYOUDIM}"\nrevision = "{SHA}"\n',
        encoding="utf-8",
    )
    cli.ok("register", str(path))
    cli.ok("check", "example-legacy", "--source", "hf-hub", root=hub)
    [alert] = _alerts(cli, "example-legacy")
    assert [edge["relationship"] for edge in alert["cause"]["edges"]] == ["unspecified"]


def test_a_grandparents_finding_reaches_the_grandchild_as_transitive(cli: Cli, hub: Path) -> None:
    for name in ("chain-grandparent", "chain-parent", "chain-child"):
        cli.ok("register", manifest(name))
    cli.ok("check", "--all", "--source", "hf-hub", root=hub)
    [grand_alert] = _alerts(cli, "example-grand")
    assert _alerts(cli, "example-mid") == [] and _alerts(cli, "example-child") == []
    [direct] = _inherited(cli, "example-mid")
    assert direct["detail"]["reach"] == "direct"
    assert direct["detail"]["parent_alert"]["alert_id"] == grand_alert["alert_id"]
    [transitive] = _inherited(cli, "example-child")
    detail = transitive["detail"]
    assert detail["reach"] == "transitive"
    assert [(hop["child"], hop["parent"], hop["relationship"]) for hop in detail["paths"][0]] == [
        ("example-child@1", "example-mid@1", "adapter-for"),
        ("example-mid@1", "example-grand@1", "fine-tuned-from"),
    ]
    key = f"base_model_disabled:pkg:huggingface/{DYOUDIM}"
    assert detail["parent_alert"]["cause_key"] == key
    assert transitive["identifier"] == f"model:example-grand@1/{key}"


def _registered_parent(cli: Cli, tmp_path: Path) -> int:
    """example-base v1 with a weight file and an open weight_file_scan alert."""
    cli.ok("register", _manifest(tmp_path, "example-base", []))
    with Store(cli.db) as store:
        evidence = store.add_evidence(
            source="picklescan",
            url="file:///weights/model.pt",
            retrieved_at=store.now(),
            matched_identifier=FILE,
            body=b"{}",
        )
        store.add_version(
            "example-base",
            {},
            "0" * 64,
            [{"kind": "weight_file", "identifier": FILE, "pinned": True, "location": "m.pt"}],
            origin="manifest",
        )
        return store.insert_alert(
            model_id="example-base",
            kind="weight_file_scan",
            cause_key=f"weight_file_scan:{FILE}",
            cause={"identifier": FILE, "location": "m.pt"},
            severity="HIGH",
            severity_origin="policy",
            opened_in_version=2,
            evidence_ids=[evidence],
        )


def test_a_weight_finding_reaches_an_adapter_child_and_not_a_quantised_one(
    cli: Cli, tmp_path: Path
) -> None:
    alert_id = _registered_parent(cli, tmp_path)
    adapter = '[[parents]]\nmodel = "example-base"\nversion = 2\nrelationship = "adapter-for"\n'
    quantised = adapter.replace("adapter-for", "quantized-from")
    cli.ok("register", _manifest(tmp_path, "example-adapter", [adapter]))
    cli.ok("register", _manifest(tmp_path, "example-quantised", [quantised]))
    for child in ("example-adapter", "example-quantised"):
        cli.ok("check", child, "--source", "picklescan")
    [event] = _inherited(cli, "example-adapter")
    assert event["detail"]["parent_alert"]["alert_id"] == alert_id
    assert event["detail"]["reach"] == "direct"
    assert _inherited(cli, "example-quantised") == []
    assert _alerts(cli, "example-adapter") == [] and _alerts(cli, "example-quantised") == []
    _, text = cli.run("alerts", "example-adapter", as_json=False)
    assert "      inherited from parent example-base v2 over adapter-for (manifest)" in text

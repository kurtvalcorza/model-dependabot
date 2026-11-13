"""Importing an inventory whose local weight files are present (T017; FR-003, research A5).

A file beside the inventory is classified from its bytes at import: the bytes win over the
document's claim, the entry's format origin is ``bytes`` and a contradiction is recorded as a claim
check made at import (no run). A path that leaves the inventory's directory is not read, and the
document's own ``model-dependabot:format-origin`` is ignored (contracts/inventory-profile.md).
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from model_dependabot.cli import EXIT_OK, main, make_handlers
from model_dependabot.inventory.build import new_entry
from model_dependabot.inventory.cyclonedx import export_bom
from model_dependabot.sources.fetcher import RecordedFetcher
from model_dependabot.store import Store

PICKLE = b"\x80\x04\x95\x10\x00\x00\x00\x00\x00\x00\x00}\x94\x8c\x01a\x94K\x01s."


def _sha(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


def _bom(path: Path, location: str, content: bytes, origin: str | None = None) -> Path:
    entry = new_entry(
        "weight_file",
        identifier=_sha(content),
        pinned=True,
        location=location,
        size=len(content),
        format="safetensors",
        can_run_code=False,
    )
    document = export_bom("third-party", 1, [entry])
    if origin is not None:
        component = document["components"][0]
        component["properties"].append({"name": "model-dependabot:format-origin", "value": origin})
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _import(bom: Path, db: Path, capsys: pytest.CaptureFixture[str]) -> dict[str, Any]:
    handlers = make_handlers(fetcher=RecordedFetcher(bom.parent / "none"))
    argv = ["import", str(bom), "--model-id", "m", "--db", str(db), "--json"]
    assert main(argv, handlers=handlers) == EXIT_OK
    return json.loads(capsys.readouterr().out)


def test_a_local_pickle_named_safetensors_is_stored_as_the_pickle_it_is(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "model.safetensors").write_bytes(PICKLE)
    db = tmp_path / "db" / "md.db"
    _import(_bom(tmp_path / "bom.json", "model.safetensors", PICKLE), db, capsys)
    with Store(db) as store:
        assert store.get_version("m", 1)["origin"] == "import"
        [entry] = store.entries("m", 1)
        [check] = store.claim_checks("m", 1)
    assert (entry["format"], entry["can_run_code"], entry["format_origin"]) == (
        "pickle",
        True,
        "bytes",
    )
    assert (check["claim"], check["outcome"], check["run_id"]) == (
        "code_free",
        "contradicted",
        None,
    )
    assert check["measured_format"] == "pickle"


def test_an_honest_local_file_keeps_its_claim_with_origin_bytes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    header = b'{"w":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}'
    content = len(header).to_bytes(8, "little") + header + b"\x00" * 4
    (tmp_path / "model.safetensors").write_bytes(content)
    db = tmp_path / "db" / "md.db"
    _import(_bom(tmp_path / "bom.json", "model.safetensors", content), db, capsys)
    with Store(db) as store:
        [entry] = store.entries("m", 1)
        assert store.claim_checks("m", 1) == []
    assert (entry["format"], entry["can_run_code"], entry["format_origin"]) == (
        "safetensors",
        False,
        "bytes",
    )


def test_a_weight_path_outside_the_inventory_directory_is_not_read(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "model.safetensors").write_bytes(PICKLE)
    bom_dir = tmp_path / "bom"
    bom_dir.mkdir()
    db = tmp_path / "db" / "md.db"
    _import(_bom(bom_dir / "bom.json", "../model.safetensors", PICKLE), db, capsys)
    with Store(db) as store:
        [entry] = store.entries("m", 1)
        assert store.claim_checks("m", 1) == []
    assert (entry["format"], entry["can_run_code"], entry["format_origin"]) == (
        "safetensors",
        False,
        "import",
    )


@pytest.mark.parametrize("claimed", ["bytes", "name", "record"])
def test_an_imported_format_origin_is_ignored(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], claimed: str
) -> None:
    db = tmp_path / "db" / "md.db"
    _import(_bom(tmp_path / "bom.json", "absent.safetensors", PICKLE, claimed), db, capsys)
    with Store(db) as store:
        [entry] = store.entries("m", 1)
    assert entry["format_origin"] == "import"


def test_a_bom_exported_here_is_a_third_party_claim_when_imported(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Its format-origin property is ignored there too, whatever it says."""
    entry = new_entry(
        "weight_file",
        identifier=_sha(PICKLE),
        pinned=True,
        location="absent.safetensors",
        format="safetensors",
        can_run_code=False,
        format_origin="bytes",
    )
    document = copy.deepcopy(export_bom("owner-model", 1, [entry]))
    props = {p["name"]: p["value"] for p in document["components"][0]["properties"]}
    assert props["model-dependabot:format-origin"] == "bytes"
    bom = tmp_path / "bom.json"
    bom.write_text(json.dumps(document), encoding="utf-8")
    db = tmp_path / "db" / "md.db"
    _import(bom, db, capsys)
    with Store(db) as store:
        assert store.entries("m", 1)[0]["format_origin"] == "import"

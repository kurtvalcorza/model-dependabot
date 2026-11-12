"""Versions recorded before feature 003 are re-marked at their next check (T016; FR-005, FR-007).

The database is written with the schema of main before 003 (``tests/fixtures/db``) and holds two
strict-policy models: an imported one whose code-free hub file silenced the alert, and one
registered from a manifest whose local code-free file is still on disk. One check follows, in
which the hub answers ``503`` to the header read.
"""

from __future__ import annotations

import json
import shutil
import sqlite3
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from conftest import GPT2_COMMIT, GPT2_PICKLE, GPT2_REPO, GPT2_SAFETENSORS, resolve
from model_dependabot.cli import EXIT_OK, EXIT_SOURCE_FAILED, main, make_handlers
from model_dependabot.sources.fetcher import RecordedFetcher
from model_dependabot.store import Store

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
PRE_003 = FIXTURES / "db" / "schema-pre-003.sql"
WEIGHTS = FIXTURES / "manifests" / "weights"
STAMP = "2026-11-01T00:00:00Z"
RULE = "imported code-free claims count only once confirmed"


def _file(path: Path) -> tuple[str, int]:
    import hashlib

    content = path.read_bytes()
    return "sha256:" + hashlib.sha256(content).hexdigest(), len(content)


def legacy_database(path: Path, base_dir: Path) -> None:
    """Two strict-policy models as the tool before 003 would have stored them."""
    conn = sqlite3.connect(path)
    conn.executescript(PRE_003.read_text(encoding="utf-8"))
    with conn:
        for model_id in ("legacy-import", "legacy-manifest"):
            conn.execute(
                "INSERT INTO models (model_id, format_policy, format_policy_set_by,"
                " format_policy_set_at, created_at) VALUES (?, 'strict', 'owner', ?, ?)",
                (model_id, STAMP, STAMP),
            )
            conn.execute(
                "INSERT INTO model_versions (model_id, version, registered_at, manifest_sha256,"
                " inventory, base_dir) VALUES (?, 1, ?, ?, '{}', ?)",
                (model_id, STAMP, "b" * 64, str(base_dir)),
            )
        columns = (
            "model_id, version, kind, identifier, pinned, location, size, format, can_run_code,"
            " hub_repo, hub_revision, hub_file"
        )
        rows = [
            (
                "legacy-import",
                f"sha256:{GPT2_SAFETENSORS}",
                resolve(GPT2_REPO, GPT2_COMMIT, "model.safetensors"),
                548105171,
                "safetensors",
                0,
                GPT2_REPO,
                GPT2_COMMIT,
                "model.safetensors",
            ),
            (
                "legacy-import",
                f"sha256:{GPT2_PICKLE}",
                resolve(GPT2_REPO, GPT2_COMMIT, "pytorch_model.bin"),
                548118077,
                "pickle",
                1,
                GPT2_REPO,
                GPT2_COMMIT,
                "pytorch_model.bin",
            ),
        ]
        for relative, fmt, crc in (
            ("weights/tiny.safetensors", "safetensors", 0),
            ("weights/tiny.pt", "pytorch-zip", 1),
        ):
            identifier, size = _file(base_dir / relative)
            rows.append(("legacy-manifest", identifier, relative, size, fmt, crc, None, None, None))
        for model_id, identifier, location, size, fmt, crc, repo, revision, file in rows:
            conn.execute(
                f"INSERT INTO inventory_entries ({columns}) VALUES (?, 1, 'weight_file', ?, 1,"
                " ?, ?, ?, ?, ?, ?, ?)",
                (model_id, identifier, location, size, fmt, crc, repo, revision, file),
            )
    conn.close()


@pytest.fixture
def legacy(tmp_path: Path) -> Path:
    base = tmp_path / "project"
    shutil.copytree(WEIGHTS, base / "weights")
    db = tmp_path / "md.db"
    legacy_database(db, base)
    return db


def _alerts(db: Path, model_id: str, capsys: pytest.CaptureFixture[str]) -> list[dict[str, Any]]:
    handlers = make_handlers(fetcher=RecordedFetcher(db.parent / "none"))
    assert main(["alerts", model_id, "--db", str(db), "--json"], handlers=handlers) == EXIT_OK
    return json.loads(capsys.readouterr().out)["alerts"]


def test_legacy_import(
    legacy: Path, capsys: pytest.CaptureFixture[str], derive_format_check: Callable
) -> None:
    hop = resolve(GPT2_REPO, GPT2_COMMIT, "model.safetensors")
    failing = derive_format_check({"busy": {"url": hop, "status": 503, "body": "busy"}})
    handlers = make_handlers(fetcher=RecordedFetcher(failing))
    argv = ["check", "--all", "--source", "format-check,picklescan", "--db", str(legacy), "--json"]
    assert main(argv, handlers=handlers) == EXIT_SOURCE_FAILED
    capsys.readouterr()

    [alert] = [a for a in _alerts(legacy, "legacy-import", capsys) if a["kind"] == "format_policy"]
    assert alert["cause"]["identifier"] == f"sha256:{GPT2_PICKLE}"
    assert alert["cause"]["rule"] == RULE
    assert alert["cause"]["unconfirmed_claims"][0]["identifier"] == f"sha256:{GPT2_SAFETENSORS}"
    assert alert["cause"]["unconfirmed_claims"][0]["origin"] == "legacy"

    # The legacy manifest model's local code-free file is confirmed from its bytes: no alert.
    assert [
        a for a in _alerts(legacy, "legacy-manifest", capsys) if a["kind"] == "format_policy"
    ] == []
    with Store(legacy) as store:
        identifier, _ = _file(legacy.parent / "project" / "weights" / "tiny.safetensors")
        latest = store.latest_claim_check("legacy-manifest", 1, identifier)
    assert latest is not None and latest["outcome"] == "confirmed"

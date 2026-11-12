"""``inventory audit`` end to end (T028; US2 acceptance scenarios 1 to 5, quickstart §4, SC-003).

A model with local weight files, a hub weight file, gaps and no environment is registered and
audited before and after a check in which ``hf-scan`` fails (a recorded failure). The audit reads
the database read-only: its bytes and every evidence file are unchanged, on a current database and
on one written before feature 003.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from conftest import EICAR_COMMIT, EICAR_REPO
from model_dependabot.cli import (
    EXIT_INVALID_INPUT,
    EXIT_OK,
    EXIT_SOURCE_FAILED,
    main,
    make_handlers,
)
from model_dependabot.sources.fetcher import RecordedFetcher
from model_dependabot.store import Store

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
WEIGHTS = FIXTURES / "manifests" / "weights"
PRE_003 = FIXTURES / "db" / "schema-pre-003.sql"
NOW = datetime(2026, 11, 13, 9, 0, tzinfo=UTC)
STATEMENT = "No alerts is not evidence that the inventory is complete or the model is safe."

MANIFEST = f"""
[model]
id = "audited"

[[weights]]
path = "weights/tiny.safetensors"

[[weights]]
path = "weights/tiny.onnx"

[[weights]]
hub = "hf:{EICAR_REPO}"
revision = "{EICAR_COMMIT}"
file = "pytorch_model.bin"

[base_model]
hub = "hf:openai-community/gpt2"

[[datasets]]
sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
"""


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _snapshot(db: Path) -> dict[str, str]:
    files = {"db": _digest(db)}
    evidence = db.parent / "evidence"
    for path in sorted(evidence.iterdir()) if evidence.exists() else []:
        files[path.name] = _digest(path)
    return files


@pytest.fixture
def project(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    shutil.copytree(WEIGHTS, root / "weights")
    (root / "model.toml").write_text(MANIFEST, encoding="utf-8")
    return root


Cli = Callable[..., tuple[int, Any]]


@pytest.fixture
def cli(tmp_path: Path, capsys: pytest.CaptureFixture[str], derive_hf: Callable) -> Cli:
    db = tmp_path / "db" / "md.db"
    recordings = derive_hf(errors={"eicar-security": "HTTP 503 after 4 attempts"})

    def invoke(*argv: str, as_json: bool = True) -> tuple[int, Any]:
        handlers = make_handlers(fetcher=RecordedFetcher(recordings), now=lambda: NOW)
        code = main([*argv, "--db", str(db), *(["--json"] if as_json else [])], handlers=handlers)
        out = capsys.readouterr().out
        if not as_json:
            return code, out
        return code, json.loads(out) if out.strip() else None

    invoke.db = db  # type: ignore[attr-defined]
    return invoke


def test_audit_before_and_after_a_check_with_a_failed_source(cli: Cli, project: Path) -> None:
    assert cli("register", str(project / "model.toml"))[0] == EXIT_OK

    before = _snapshot(cli.db)
    code, never = cli("inventory", "audit", "audited")
    assert code == EXIT_OK
    assert _snapshot(cli.db) == before
    assert never["findings"]["state"] == "not_yet_checked"
    assert never["summary"]["checked"] is False
    assert never["statement"] == STATEMENT

    code, _ = cli("check", "audited", "--source", "picklescan,hf-scan")
    assert code == EXIT_SOURCE_FAILED

    before = _snapshot(cli.db)
    code, report = cli("inventory", "audit", "audited")
    assert code == EXIT_OK
    assert _snapshot(cli.db) == before
    summary = report["summary"]
    assert summary["checked"] is True
    assert summary["alerts_open"] == 0
    assert summary["gaps"] == 2  # the base model has no revision, the dataset no DOI
    assert summary["sources_failed"] == 1
    assert report["findings"]["state"] == "checked"
    assert report["findings"]["alerts"] == []
    assert report["statement"] == STATEMENT
    assert "environment" in report["assurance"]["undeclared_kinds"]
    sources = {item["source"]: item for item in report["coverage"]["sources"]}
    assert sources["hf-scan"]["status"] == "failed: HTTP 503 after 4 attempts"
    assert sources["hf-scan"]["relevant_entries"] == [
        "sha256:f9343d7d7ec5c3d8bcced056c438fc9f1d3819e9ca3d42418a40857050e10e20"
    ]
    assert sources["hf-scan"]["last_finished_at"] == "2026-11-13T09:00:00Z"
    # The base model and the dataset are gaps, the local files are code-free: hf-scan is all.
    assert set(sources) == {"hf-scan"}
    reasons = {item["reason"] for item in report["coverage"]["uncheckable"]}
    assert {"no revision", "no DOI"} <= reasons


def test_the_text_report_leads_with_the_summary_and_always_has_the_statement(
    cli: Cli, project: Path
) -> None:
    assert cli("register", str(project / "model.toml"))[0] == EXIT_OK
    code, text = cli("inventory", "audit", "audited", as_json=False)
    assert code == EXIT_OK
    lines = text.splitlines()
    assert lines[0].startswith("audited v1")
    assert lines[1].startswith("Summary:")
    assert "not yet checked" in text
    for heading in ("Findings", "Assurance", "Coverage"):
        assert heading in text
    assert STATEMENT in text
    assert text.index("Findings") < text.index("Assurance") < text.index("Coverage")


def test_unknown_models_and_versions_exit_1(cli: Cli, project: Path) -> None:
    assert cli("register", str(project / "model.toml"))[0] == EXIT_OK
    assert cli("inventory", "audit", "nobody")[0] == EXIT_INVALID_INPUT
    assert cli("inventory", "audit", "audited", "--version", "9")[0] == EXIT_INVALID_INPUT


def test_a_missing_database_is_never_created(cli: Cli) -> None:
    assert cli("inventory", "audit", "audited")[0] == EXIT_INVALID_INPUT
    assert not cli.db.exists()


def _pre_003(path: Path) -> None:
    conn = sqlite3.connect(path)
    conn.executescript(PRE_003.read_text(encoding="utf-8"))
    with conn:
        conn.execute("INSERT INTO models (model_id, created_at) VALUES ('old', 'x')")
        conn.execute(
            "INSERT INTO model_versions (model_id, version, registered_at, manifest_sha256,"
            " inventory) VALUES ('old', 1, '2026-11-01T00:00:00Z', ?, '{}')",
            ("b" * 64,),
        )
        conn.execute(
            "INSERT INTO inventory_entries (model_id, version, kind, identifier, pinned,"
            " location, format, can_run_code) VALUES ('old', 1, 'weight_file', ?, 1,"
            " 'model.safetensors', 'safetensors', 0)",
            ("sha256:" + "a" * 64,),
        )
    conn.close()


def test_a_pre_003_database_is_read_with_defaults_and_never_upgraded(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    db = tmp_path / "old.db"
    _pre_003(db)
    before = _digest(db)
    handlers = make_handlers(fetcher=RecordedFetcher(tmp_path), now=lambda: NOW)
    assert main(["inventory", "audit", "old", "--db", str(db), "--json"], handlers=handlers) == 0
    report = json.loads(capsys.readouterr().out)
    assert _digest(db) == before
    [entry] = report["assurance"]["entries"]
    assert entry["status"] == "declared-but-unverified"
    assert {claim["origin"] for claim in entry["claims"]} == {"legacy"}
    with sqlite3.connect(db) as conn:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(model_versions)")}
    assert "origin" not in columns


def test_a_database_older_than_feature_002_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    db = tmp_path / "ancient.db"
    with sqlite3.connect(db) as conn:
        conn.executescript(
            "CREATE TABLE models (model_id TEXT PRIMARY KEY, created_at TEXT);"
            "CREATE TABLE model_versions (model_id TEXT, version INTEGER, registered_at TEXT,"
            " manifest_sha256 TEXT, inventory TEXT);"
            "CREATE TABLE check_runs (run_id INTEGER PRIMARY KEY, started_at TEXT,"
            " finished_at TEXT, scope TEXT, sources TEXT);"
            "INSERT INTO models VALUES ('old', 'x');"
        )
    before = _digest(db)
    handlers = make_handlers(fetcher=RecordedFetcher(tmp_path), now=lambda: NOW)
    code = main(["inventory", "audit", "old", "--db", str(db)], handlers=handlers)
    assert code == EXIT_INVALID_INPUT
    assert "run any check once to upgrade this database" in capsys.readouterr().err
    assert _digest(db) == before


def test_an_audit_of_a_large_history_is_quick(tmp_path: Path) -> None:
    """300 entries and a year of daily runs (plan, Performance Goals; generous CI bound)."""
    db = tmp_path / "md.db"
    with Store(db, now=lambda: NOW) as store:
        store.add_model("big")
        entries = [
            {
                "kind": "package",
                "identifier": f"pkg:pypi/p{n}@1.0",
                "pinned": True,
                "name": f"p{n}",
                "version": "1.0",
                "hashes": ["sha256:" + "a" * 64],
            }
            for n in range(300)
        ]
        store.add_version("big", {}, "c" * 64, entries, origin="manifest")
        with store.conn:
            store.conn.executemany(
                "INSERT INTO check_runs (started_at, finished_at, scope, sources, trigger)"
                " VALUES (?, ?, 'all', ?, 'scheduled')",
                [
                    (NOW.strftime("%Y-%m-%dT%H:%M:%SZ"),) * 2 + (json.dumps({"osv": "ok"}),)
                    for _ in range(365)
                ],
            )
    from model_dependabot.assurance.audit import audit_report as audit

    with Store.open_read_only(db, now=lambda: NOW) as store:
        started = time.perf_counter()
        report = audit(store, "big")
        elapsed = time.perf_counter() - started
    assert report["summary"]["entries"] == 300
    assert elapsed < 5.0

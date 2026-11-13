"""The check overview end to end (T038; spec US3, quickstart 5, research S6).

Four models in one run: a dangerous pickle (picklescan alerted), a joblib file the scanner cannot
finish (picklescan incomplete), a hub file whose hub answer fails (hf-scan failed) and a model with
only an ONNX file, which no source asked can check.
"""

from __future__ import annotations

import json
import shutil
import sqlite3
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from conftest import EICAR_COMMIT, EICAR_REPO
from model_dependabot.cli import EXIT_OK, EXIT_SOURCE_FAILED, main, make_handlers
from model_dependabot.sources.fetcher import RecordedFetcher

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
HUB = f'hub = "hf:{EICAR_REPO}"\nrevision = "{EICAR_COMMIT}"\nfile = "pytorch_model.bin"'


@pytest.fixture
def cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> Callable[..., tuple[int, Any]]:
    db = tmp_path / "db" / "md.db"

    def invoke(*argv: str, recordings: Path | None = None, as_json: bool = True) -> tuple[int, Any]:
        handlers = make_handlers(fetcher=RecordedFetcher(recordings or tmp_path / "none"))
        code = main([*argv, "--db", str(db), *(["--json"] if as_json else [])], handlers=handlers)
        out = capsys.readouterr().out
        if not as_json:
            return code, out
        return code, json.loads(out) if out.strip() else None

    return invoke


def _model(root: Path, model_id: str, weight: str) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    path = root / "model.toml"
    path.write_text(f'[model]\nid = "{model_id}"\n\n[[weights]]\n{weight}\n', encoding="utf-8")
    return path


def _four_models(cli: Any, tmp_path: Path, craft: ModuleType, derive_hf: Any) -> Path:
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "d.pkl").write_bytes(craft.dangerous())
    assert cli("register", str(_model(tmp_path / "a", "alerted", 'path = "d.pkl"')))[0] == 0
    (tmp_path / "b").mkdir()
    shutil.copy(FIXTURES / "pickles" / "joblib-style.joblib", tmp_path / "b" / "m.joblib")
    assert cli("register", str(_model(tmp_path / "b", "partial", 'path = "m.joblib"')))[0] == 0
    hub = _model(tmp_path / "c", "hubbed", HUB)
    assert cli("register", str(hub), recordings=derive_hf())[0] == 0
    (tmp_path / "d").mkdir()
    shutil.copy(FIXTURES / "manifests" / "weights" / "tiny.onnx", tmp_path / "d" / "t.onnx")
    assert cli("register", str(_model(tmp_path / "d", "onnx", 'path = "t.onnx"')))[0] == 0
    return derive_hf(errors={"eicar-security": "HTTP 503 after 3 tries"})


def _row(rows: list[dict[str, Any]], source: str) -> dict[str, Any]:
    return next(row for row in rows if row["source"] == source)


def test_four_states_in_json(
    cli: Any, tmp_path: Path, craft: ModuleType, derive_hf: Callable[..., Path]
) -> None:
    down = _four_models(cli, tmp_path, craft, derive_hf)
    code, checked = cli("check", "--all", "--source", "picklescan,hf-scan", recordings=down)
    assert code == EXIT_SOURCE_FAILED  # exit 2 unchanged
    covered = checked["overview"]
    wide = covered["sources"]
    assert [row["source"] for row in wide] == ["picklescan", "hf-scan", "policy"]
    assert _row(wide, "picklescan")["state"] == "incomplete"
    assert _row(wide, "picklescan")["incomplete"] == 1
    assert _row(wide, "picklescan")["alerts_open"] == 1
    failed = _row(wide, "hf-scan")
    assert (failed["state"], failed["reason"]) == ("failed", "HTTP 503 after 3 tries")
    assert failed["alerts_open"] is None and failed["incomplete"] is None
    assert _row(wide, "policy")["state"] == "passed"
    models = {model["model_id"]: model for model in covered["models"]}
    assert _row(models["alerted"]["sources"], "picklescan")["state"] == "alerted"
    assert _row(models["partial"]["sources"], "picklescan")["state"] == "incomplete"
    assert _row(models["hubbed"]["sources"], "hf-scan")["state"] == "failed"
    assert models["hubbed"]["checked"] is True  # its policy row was not failed
    assert models["onnx"]["checked"] is False
    assert models["onnx"]["reason"] == "no entry of this model can be checked by the sources asked"
    assert models["onnx"]["sources"] == []

    conn = sqlite3.connect(tmp_path / "db" / "md.db")
    try:
        stored = conn.execute(
            "SELECT model_id, source, state FROM check_run_overview WHERE run_id = ?",
            (checked["run_id"],),
        ).fetchall()
    finally:
        conn.close()
    assert ("", "hf-scan", "failed") in stored
    assert ("partial", "picklescan", "incomplete") in stored

    code, shown = cli("run", "show", str(checked["run_id"]))
    assert code == EXIT_OK
    assert shown["overview"] == covered


def test_the_overview_text(
    cli: Any, tmp_path: Path, craft: ModuleType, derive_hf: Callable[..., Path]
) -> None:
    down = _four_models(cli, tmp_path, craft, derive_hf)
    code, text = cli(
        "check", "--all", "--source", "picklescan,hf-scan", recordings=down, as_json=False
    )
    assert code == EXIT_SOURCE_FAILED
    assert "Overview of run 1 (all)" in text
    assert "source        state       entries  incomplete  alerts  excepted  held" in text
    assert "HTTP 503 after 3 tries" in text
    assert (
        "onnx v1: not checked: no entry of this model can be checked by the sources asked" in text
    )
    assert "alerted v1: checked" in text


def test_an_empty_scope_says_no_models_were_checked(cli: Any) -> None:
    code, text = cli("check", "--all", "--source", "osv", as_json=False)
    assert code == EXIT_OK
    assert "No models were checked" in text
    code, checked = cli("check", "--all", "--source", "osv")
    assert checked["overview"]["models"] == []
    assert _row(checked["overview"]["sources"], "osv")["reason"] == "no entry needed this source"

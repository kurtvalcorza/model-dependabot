"""Held dismissals end to end (T055; FR-020, research S5 and S13, quickstart 7).

A dismissed alert is not opened again by a later check that brings no new evidence; it is listed
under the model's ``dismissals_held`` and counted in the overview's ``held`` column. New evidence
opens a new alert whose cause names the dismissed one under ``reopens``.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from conftest import EICAR_COMMIT, EICAR_REPO
from model_dependabot.cli import EXIT_OK, main, make_handlers
from model_dependabot.sources import hf
from model_dependabot.sources.fetcher import RecordedFetcher

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
NOW = datetime(2026, 11, 14, 9, 0, tzinfo=UTC)
DISMISS = ("--reason", "risk_accepted", "--by", "Owner")
HUB = f'hub = "hf:{EICAR_REPO}"\nrevision = "{EICAR_COMMIT}"\nfile = "pytorch_model.bin"'


@pytest.fixture
def cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> Callable[..., Any]:
    db = tmp_path / "db" / "md.db"

    def invoke(*argv: str, recordings: Path | None = None) -> Any:
        handlers = make_handlers(
            fetcher=RecordedFetcher(recordings or tmp_path / "none"), now=lambda: NOW
        )
        code = main([*argv, "--db", str(db), "--json"], handlers=handlers)
        out = capsys.readouterr().out
        payload = json.loads(out) if out.strip() else None
        assert code == EXIT_OK, payload
        return payload

    return invoke


def _manifest(root: Path, model_id: str, *blocks: str) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    path = root / "model.toml"
    path.write_text(f'[model]\nid = "{model_id}"\n\n' + "\n\n".join(blocks) + "\n", "utf-8")
    return path


def _only(cli: Any, model_id: str, kind: str, state: str = "all") -> list[dict[str, Any]]:
    listed = cli("alerts", model_id, "--state", state)
    return [a for a in listed["alerts"] + listed["excepted"] if a["kind"] == kind]


def _held(checked: dict[str, Any], model_id: str) -> list[int]:
    return next(m for m in checked["models"] if m["model_id"] == model_id)["dismissals_held"]


def test_the_s5_probe_holds_a_weight_alert(cli: Any, tmp_path: Path, craft: ModuleType) -> None:
    root = tmp_path / "w"
    root.mkdir()
    (root / "d.pkl").write_bytes(craft.dangerous())
    cli("register", str(_manifest(root, "w", '[[weights]]\npath = "d.pkl"')))
    cli("check", "w", "--source", "picklescan")
    [alert] = _only(cli, "w", "weight_file_scan")
    cli("alert", "dismiss", str(alert["alert_id"]), *DISMISS)
    checked = cli("check", "w", "--source", "picklescan")
    assert _held(checked, "w") == [alert["alert_id"]]
    assert [a["alert_id"] for a in _only(cli, "w", "weight_file_scan")] == [alert["alert_id"]]
    wide = next(r for r in checked["overview"]["sources"] if r["source"] == "picklescan")
    assert (wide["dismissals_held"], wide["alerts_open"], wide["state"]) == (1, 0, "passed")


def test_an_osv_alert_holds_and_a_changed_record_reopens(
    cli: Any, tmp_path: Path, derive_osv: Callable[..., Path]
) -> None:
    root = tmp_path / "p"
    root.mkdir()
    shutil.copy(FIXTURES / "locks" / "vulnerable.txt", root / "requirements.txt")
    cli("register", str(_manifest(root, "p", '[environment]\nlock = "requirements.txt"')))
    same = derive_osv()
    cli("check", "p", "--source", "osv", recordings=same)
    alerts = _only(cli, "p", "package_advisory", "open")
    first = next(a for a in alerts if "GHSA-cp9v-662q-vvx9" in json.dumps(a["cause"]))
    cli("alert", "dismiss", str(first["alert_id"]), *DISMISS)
    checked = cli("check", "p", "--source", "osv", recordings=same)
    assert first["alert_id"] in _held(checked, "p")
    open_now = _only(cli, "p", "package_advisory", "open")
    assert all("GHSA-cp9v-662q-vvx9" not in json.dumps(a["cause"]) for a in open_now)

    changed = derive_osv(changes={"vuln-GHSA-cp9v-662q-vvx9": lambda b: b | {"details": "revised"}})
    cli("check", "p", "--source", "osv", recordings=changed)
    [reopened] = [
        a
        for a in _only(cli, "p", "package_advisory", "open")
        if "GHSA-cp9v-662q-vvx9" in json.dumps(a["cause"])
    ]
    assert reopened["alert_id"] != first["alert_id"]
    assert reopened["cause"]["reopens"]["alert_id"] == first["alert_id"]
    assert reopened["cause"]["reopens"]["dismissed_by"] == "Owner"


def test_an_upstream_alert_holds_on_an_unchanged_answer(
    cli: Any, tmp_path: Path, derive_upstream: Callable[..., Path]
) -> None:
    gpt2, sha = "openai-community/gpt2", "607a30d783dfa663caf39e06633721c8d4cfcd7e"
    manifest = _manifest(
        tmp_path / "b", "based", f'[base_model]\nhub = "hf:{gpt2}"\nrevision = "{sha}"'
    )
    cli("register", str(manifest), recordings=derive_upstream())
    disabled = derive_upstream(
        changes={"hf_upstream/model-normal": lambda b: b | {"disabled": True}}
    )
    cli("check", "based", "--source", "hf-hub", recordings=disabled)
    [alert] = _only(cli, "based", "base_model_disabled", "open")
    cli("alert", "dismiss", str(alert["alert_id"]), *DISMISS)
    checked = cli("check", "based", "--source", "hf-hub", recordings=disabled)
    assert _held(checked, "based") == [alert["alert_id"]]
    assert _only(cli, "based", "base_model_disabled", "open") == []
    assert hf.model_info_url(gpt2)  # the answer replayed is the hub's model answer


def _flag(extra: dict[str, Any]) -> Callable[[Any], Any]:
    def change(info: Any) -> Any:
        info["securityRepoStatus"]["filesWithIssues"].append(
            {"path": "pytorch_model.bin", "level": "unsafe"}
        )
        return info | extra

    return change


def test_a_hub_scan_alert_holds_when_only_counters_move(
    cli: Any, tmp_path: Path, derive_hf: Callable[..., Path]
) -> None:
    cli(
        "register",
        str(_manifest(tmp_path / "h", "hub", f"[[weights]]\n{HUB}")),
        recordings=derive_hf(),
    )
    cli("check", "hub", "--source", "hf-scan", recordings=derive_hf(security=_flag({})))
    [alert] = _only(cli, "hub", "hub_scan", "open")
    cli("alert", "dismiss", str(alert["alert_id"]), *DISMISS)
    moved = derive_hf(
        security=_flag(
            {"downloads": 123456, "likes": 77, "lastModified": "2026-11-14T00:00:00.000Z"}
        )
    )
    checked = cli("check", "hub", "--source", "hf-scan", recordings=moved)
    assert _held(checked, "hub") == [alert["alert_id"]]
    assert _only(cli, "hub", "hub_scan", "open") == []


def test_a_revoked_exception_that_grows_unlisted_reopens_a_globals_alert(
    cli: Any, tmp_path: Path, craft: ModuleType
) -> None:
    root = tmp_path / "g"
    root.mkdir()
    data = craft.mixed()
    (root / "m.pkl").write_bytes(data)
    cli("register", str(_manifest(root, "g", '[[weights]]\npath = "m.pkl"')))
    cli("policy", "g", "--globals", "strict", "--by", "Owner")
    sha = hashlib.sha256(data).hexdigest()
    made = cli("exception", "record", "--global", "os.system", "--sha256", sha,
               "--reason", "reviewed", "--by", "Owner")  # fmt: skip
    cli("check", "g", "--source", "picklescan")
    [policy] = _only(cli, "g", "globals_policy", "open")
    assert "os.system" not in policy["cause"]["unlisted"]
    cli("alert", "dismiss", str(policy["alert_id"]), *DISMISS)
    checked = cli("check", "g", "--source", "picklescan")
    assert policy["alert_id"] in _held(checked, "g")
    cli("exception", "revoke", str(made["exception_id"]), "--reason", "no", "--by", "Owner")
    cli("check", "g", "--source", "picklescan")
    [reopened] = _only(cli, "g", "globals_policy", "open")
    assert "os.system" in reopened["cause"]["unlisted"]
    assert reopened["cause"]["reopens"]["alert_id"] == policy["alert_id"]

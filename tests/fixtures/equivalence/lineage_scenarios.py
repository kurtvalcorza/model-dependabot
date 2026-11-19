"""The ``[base_model]`` scenarios of feature 011's equivalence baseline (T005, SC-001, L11).

Each scenario mirrors one behaviour of ``tests/integration/test_check_base_model.py``,
``tests/unit/test_lifecycle_base_model.py``, ``tests/unit/test_lifecycle_base_model_moved.py`` or
``tests/integration/test_register.py`` with a single ``[base_model]`` manifest, run through the
command line offline, with hub answers derived from ``tests/fixtures/hf_upstream`` in the
scenario's own directory. Feature 004's ``Scenario``, ``snapshot`` and ``run`` (``scenarios.py``)
are reused; the snapshot is extended with SC-001's other fields: every inventory entry's identifier
and gap, and the exit code of every command.

``tools/record_equivalence_baseline.py --scenarios tests/fixtures/equivalence/lineage_scenarios.py
--out tests/fixtures/equivalence/pre-011-baseline.json --expect-src-tree TREE`` recorded the
baseline once, before any feature 011 code; ``tests/integration/test_lineage_equivalence.py``
replays it on the current build.
"""

from __future__ import annotations

import importlib.util
import io
import json
import shutil
import sqlite3
import sys
from collections.abc import Callable
from contextlib import redirect_stderr, redirect_stdout
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import ModuleType
from typing import Any

from model_dependabot.cli import main, make_handlers
from model_dependabot.sources import hf
from model_dependabot.sources.fetcher import RecordedFetcher

HERE = Path(__file__).resolve().parent
FIXTURES = HERE.parent


def _base() -> ModuleType:
    """Feature 004's scenarios module, loaded once under the name its own test uses."""
    name = "equivalence_scenarios"
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, HERE / "scenarios.py")
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


_BASE = _base()
Scenario = _BASE.Scenario
snapshot = _BASE.snapshot
base_run = _BASE.run

GPT2 = "openai-community/gpt2"
GPT2_SHA = "607a30d783dfa663caf39e06633721c8d4cfcd7e"
OTHER_SHA = "ffffffffffffffffffffffffffffffffffffffff"
RENAMED = "openai-community/gpt2-renamed"
DAY0 = datetime(2026, 10, 24, 6, 0, tzinfo=UTC)
H = timedelta(hours=1)
RETRIEVED = "2026-10-24T05:47:46Z"


class LineageScenario(Scenario):
    """A scenario whose commands run at stated times and whose exit codes are kept."""

    def __init__(self, work: Path, craft: ModuleType) -> None:
        super().__init__(work, craft)
        self.codes: list[list[Any]] = []
        self.derivations = 0

    def call(self, *argv: str, root: Path | None = None, at: timedelta = 0 * H) -> Any:
        handlers = make_handlers(fetcher=RecordedFetcher(root or self.none), now=lambda: DAY0 + at)
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main([*argv, "--db", str(self.db()), "--json"], handlers=handlers)
        self.codes.append([argv[0], code])
        text = out.getvalue()
        return json.loads(text) if text.strip() else None

    def derive(
        self,
        changes: dict[str, Callable[[Any], Any]] | None = None,
        extra: dict[str, dict[str, Any]] | None = None,
    ) -> Path:
        """Hub answers from ``hf_upstream``, as ``tests/conftest.py`` derives them."""
        root = self.work / f"upstream-{self.derivations}"
        self.derivations += 1
        shutil.copytree(
            FIXTURES / "hf_upstream", root / "hf_upstream", ignore=shutil.ignore_patterns("*.md")
        )
        for name, change in (changes or {}).items():
            meta_path = root / "hf_upstream" / f"{name}.meta.json"
            meta = json.loads(meta_path.read_text("utf-8"))
            body = meta_path.parent / meta["body_file"]
            body.write_text(json.dumps(change(json.loads(body.read_text("utf-8")))), "utf-8")
            for key in ("original_sha256", "body_sha256"):
                meta.pop(key, None)
            meta_path.write_text(json.dumps(meta), "utf-8")
        replaced = {spec["url"] for spec in (extra or {}).values()}
        for meta_path in list(root.rglob("*.meta.json")):
            meta = json.loads(meta_path.read_text("utf-8"))
            if meta["url"] in replaced:
                (meta_path.parent / meta["body_file"]).unlink()
                meta_path.unlink()
        for name, spec in (extra or {}).items():
            body = spec["body"] if isinstance(spec["body"], str) else json.dumps(spec["body"])
            folder = root / "extra"
            folder.mkdir(parents=True, exist_ok=True)
            (folder / f"{name}.body").write_text(body, "utf-8")
            meta = {"method": "GET", "url": spec["url"], "status": spec["status"], "headers": {}}
            meta |= {"retrieved_at": RETRIEVED, "body_file": f"{name}.body"}
            if spec.get("redirected_to"):
                meta["redirected_to"] = spec["redirected_to"]
            (folder / f"{name}.meta.json").write_text(json.dumps(meta), "utf-8")
        return root

    def based(self, revision: str | None, name: str = "model") -> Path:
        """A manifest with one ``[base_model]`` table naming gpt2."""
        directory = self.work / name
        directory.mkdir(parents=True, exist_ok=True)
        lines = ["[model]", 'id = "based"', 'name = "Based"', 'owner = "Owner"', ""]
        lines += ["[base_model]", f'hub = "hf:{GPT2}"']
        if revision is not None:
            lines.append(f'revision = "{revision}"')
        path = directory / "model.toml"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path

    def unbased(self, name: str) -> Path:
        directory = self.work / name
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / "model.toml"
        path.write_text('[model]\nid = "based"\n', encoding="utf-8")
        return path


def _disabled(s: LineageScenario) -> Path:
    return s.derive(changes={"model-normal": lambda body: body | {"disabled": True}})


def _refused(s: LineageScenario) -> Path:
    body = (FIXTURES / "hf_upstream" / "model-missing.json").read_text("utf-8")
    return s.derive(extra={"r": {"url": hf.model_info_url(GPT2), "status": 401, "body": body}})


def register_pinned(s: LineageScenario) -> list[str]:
    s.call("register", str(s.based(GPT2_SHA)))
    s.call("inventory", "show", "based")
    return ["md"]


def register_no_revision(s: LineageScenario) -> list[str]:
    s.call("register", str(s.based(None)))
    return ["md"]


def register_not_a_commit(s: LineageScenario) -> list[str]:
    s.call("register", str(s.based("main")))
    return ["md"]


def register_with_licence(s: LineageScenario) -> list[str]:
    s.call("register", str(s.based(GPT2_SHA)), root=s.derive())
    return ["md"]


def check_reachable(s: LineageScenario) -> list[str]:
    s.call("register", str(s.based(GPT2_SHA)), at=-1 * H)
    s.call("check", "based", "--source", "hf-hub", root=s.derive())
    return ["md"]


def check_new_revision(s: LineageScenario) -> list[str]:
    s.call("register", str(s.based(GPT2_SHA)), at=-1 * H)
    s.call("check", "based", "--source", "hf-hub", root=s.derive())
    newer = s.derive(changes={"model-normal": lambda body: body | {"sha": OTHER_SHA}})
    s.call("check", "based", "--source", "hf-hub", root=newer, at=1 * H)
    return ["md"]


def check_disabled(s: LineageScenario) -> list[str]:
    s.call("register", str(s.based(GPT2_SHA)), at=-1 * H)
    s.call("check", "based", "--source", "hf-hub", root=_disabled(s))
    s.call("alerts", "based")
    return ["md"]


def check_disabled_then_enabled(s: LineageScenario) -> list[str]:
    s.call("register", str(s.based(GPT2_SHA)), at=-1 * H)
    s.call("check", "based", "--source", "hf-hub", root=_disabled(s))
    s.call("check", "based", "--source", "hf-hub", root=s.derive(), at=1 * H)
    return ["md"]


def check_refusals(s: LineageScenario) -> list[str]:
    s.call("register", str(s.based(GPT2_SHA)), at=-1 * H)
    refused = _refused(s)
    s.call("check", "--all", "--scheduled", "--source", "hf-hub", root=refused)
    s.call("check", "--all", "--scheduled", "--source", "hf-hub", root=refused, at=24 * H)
    s.call("check", "--all", "--scheduled", "--source", "hf-hub", root=s.derive(), at=48 * H)
    return ["md"]


def check_failed_source(s: LineageScenario) -> list[str]:
    s.call("register", str(s.based(GPT2_SHA)), at=-1 * H)
    s.call("check", "based", "--source", "hf-hub", root=s.none)
    s.call("check", "based", "--source", "hf-hub", "--fail-on", "LOW", root=_disabled(s))
    return ["md"]


def moved_disabled(s: LineageScenario) -> list[str]:
    s.call("register", str(s.based(GPT2_SHA)), at=-1 * H)
    target = hf.model_info_url(RENAMED)
    body = json.loads((FIXTURES / "hf_upstream" / "model-normal.json").read_text("utf-8"))
    moved = {
        "url": hf.model_info_url(GPT2),
        "status": 307,
        "body": "Temporary Redirect. Redirecting to " + target,
        "redirected_to": target,
    }
    renamed = body | {"id": RENAMED, "disabled": True}
    root = s.derive(extra={"moved": moved, "t": {"url": target, "status": 200, "body": renamed}})
    s.call("check", "based", "--source", "hf-hub", root=root)
    return ["md"]


def versions_carry_and_fix(s: LineageScenario) -> list[str]:
    s.call("register", str(s.based(GPT2_SHA)), at=-2 * H)
    s.call("check", "based", "--source", "hf-hub", root=_disabled(s), at=-1 * H)
    s.call("register", str(s.based(OTHER_SHA, "model-2")), "--model-id", "based")
    s.call("register", str(s.based(None, "model-3")), "--model-id", "based", at=1 * H)
    s.call("register", str(s.unbased("model-4")), "--model-id", "based", at=2 * H)
    s.call("history", "based", at=2 * H)
    return ["md"]


SCENARIOS: dict[str, Callable[[LineageScenario], list[str]]] = {
    "register.pinned": register_pinned,
    "register.no_revision": register_no_revision,
    "register.not_a_commit": register_not_a_commit,
    "register.with_licence": register_with_licence,
    "check_base_model.reachable": check_reachable,
    "check_base_model.new_revision": check_new_revision,
    "check_base_model.disabled": check_disabled,
    "check_base_model.disabled_then_enabled": check_disabled_then_enabled,
    "check_base_model.refusals": check_refusals,
    "check_base_model.failed_source": check_failed_source,
    "lifecycle_base_model_moved.disabled": moved_disabled,
    "lifecycle_base_model.versions": versions_carry_and_fix,
}


def entries(db: Path) -> list[dict[str, Any]]:
    """Every inventory entry's identifier and gap, in recorded order (SC-001)."""
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT model_id, version, kind, identifier, pinned, gap_reason"
            " FROM inventory_entries ORDER BY entry_id"
        ).fetchall()
    finally:
        conn.close()
    return [dict(row) for row in rows]


def replay(name: str, work: Path, craft: ModuleType) -> tuple[dict[str, Any], LineageScenario]:
    """Run one scenario in ``work`` (an empty directory); its snapshot and the scenario."""
    scenario = LineageScenario(work, craft)
    databases = SCENARIOS[name](scenario)
    recorded = {}
    for db in databases:
        recorded[db] = snapshot(scenario.db(db), work) | {
            "entries": entries(scenario.db(db)),
            "exit_codes": scenario.codes,
        }
    return recorded, scenario


def run(name: str, work: Path, craft: ModuleType) -> dict[str, Any]:
    return replay(name, work, craft)[0]

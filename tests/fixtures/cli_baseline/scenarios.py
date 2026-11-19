"""The CLI baseline of feature 010 (FR-016, SC-002, research R9).

One store is built from recorded answers only (``RecordedFetcher``) with a fixed clock: a weights
model whose files raise one open, one excepted and one fixed alert, and a package model with one
dismissed and one withdrawn alert. The named invocations of research R9 then run against it, each
in text and ``--json``: ``alerts ID`` under every ``--state``, ``alert show`` for each of the five
alerts, ``history ID``, ``run show RUN_ID``, and ``check ID`` and ``check ID --fail-on HIGH`` in
copies of the store, so the read invocations see a fixed state.

``tools/record_cli_baseline.py`` recorded the outputs once, from the build before feature 010;
``tests/integration/test_cli_baseline.py`` replays them on the current build and compares stdout,
stderr and the exit code byte for byte. The scenario directory is replaced by ``<work>``.

Nothing here loads a weight file: the dangerous pickles are built by ``craft.py`` into the
scenario's own directory.
"""

from __future__ import annotations

import io
import json
import shutil
from contextlib import redirect_stderr, redirect_stdout
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from typing import Any

from model_dependabot.cli import main, make_handlers
from model_dependabot.sources.fetcher import RecordedFetcher

FIXTURES = Path(__file__).resolve().parent.parent
OSV = FIXTURES / "osv"
PICKLES = FIXTURES / "pickles"
VULNERABLE = FIXTURES / "manifests" / "vulnerable.toml"
NOW = datetime(2026, 11, 19, 9, 0, tzinfo=UTC)
WEIGHTS_MODEL = "weights-model"
PACKAGE_MODEL = "pillow-model"
WITHDRAWN = "vuln-GHSA-cp9v-662q-vvx9"
DISMISSED = "GHSA-24rc-8hj2-v98c"


class Baseline:
    """The scenario directory, its store and a command runner that captures every stream."""

    def __init__(self, work: Path, craft: ModuleType) -> None:
        self.work = work
        self.craft = craft
        self.none = work / "no-recordings"
        self.none.mkdir(parents=True, exist_ok=True)

    def db(self, name: str = "md") -> Path:
        return self.work / "db" / name / "md.db"

    def run(
        self, argv: list[str], *, db: str = "md", recordings: Path | None = None
    ) -> tuple[int, str, str]:
        handlers = make_handlers(fetcher=RecordedFetcher(recordings or self.none), now=lambda: NOW)
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main([*argv, "--db", str(self.db(db))], handlers=handlers)
        return code, out.getvalue(), err.getvalue()

    def ok(self, *argv: str, **kwargs: Any) -> Any:
        code, out, err = self.run([*argv, "--json"], **kwargs)
        if code != 0:
            raise AssertionError(f"{argv} exited {code}: {out} {err}")
        return json.loads(out) if out.strip() else None

    def normalise(self, text: str) -> str:
        """The scenario directory replaced by ``<work>``, in every form it is printed in."""
        resolved = self.work.resolve()
        forms = {resolved.as_uri(), str(resolved), str(self.work), self.work.as_posix()}
        for form in sorted(forms, key=len, reverse=True):
            text = text.replace(json.dumps(form)[1:-1], "<work>").replace(form, "<work>")
        return text

    def withdrawn_osv(self) -> Path:
        """The recorded OSV answers with one advisory withdrawn by its source."""
        root = self.work / "osv-withdrawn"
        shutil.copytree(OSV, root)
        body = root / f"{WITHDRAWN}.json"
        record = json.loads(body.read_text("utf-8"))
        record["withdrawn"] = "2026-11-18T00:00:00Z"
        body.write_text(json.dumps(record), "utf-8")
        return root


def _weights_manifest(directory: Path, files: list[str]) -> Path:
    lines = ["[model]", f'id = "{WEIGHTS_MODEL}"', 'name = "Baseline model"', 'owner = "Owner"']
    for name in files:
        lines += ["", "[[weights]]", f'path = "{name}"']
    path = directory / "model.toml"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def build(b: Baseline) -> dict[str, Any]:
    """Build the store; returns the alert ids by state and the last run id."""
    model = b.work / "model"
    model.mkdir()
    (model / "a.pkl").write_bytes(b.craft.dangerous())
    (model / "b.pkl").write_bytes(b.craft.two_dangerous())
    (model / "c.pkl").write_bytes(b.craft.mixed())
    b.ok("register", str(_weights_manifest(model, ["a.pkl", "b.pkl", "c.pkl"])))
    b.ok("check", WEIGHTS_MODEL, "--source", "picklescan")
    listed = b.ok("alerts", WEIGHTS_MODEL)["alerts"]
    by_file = {alert["cause"]["location"]: alert for alert in listed}
    sha = by_file["a.pkl"]["cause"]["identifier"].removeprefix("sha256:")
    b.ok(
        "exception",
        "record",
        "--global",
        "os.system",
        "--sha256",
        sha,
        "--reason",
        "reviewed fixture",
        "--by",
        "Owner",
    )
    b.ok("register", str(_weights_manifest(model, ["a.pkl", "b.pkl"])), "--model-id", WEIGHTS_MODEL)
    b.ok("check", WEIGHTS_MODEL, "--source", "picklescan")

    b.ok("register", str(VULNERABLE))
    b.ok("check", PACKAGE_MODEL, "--source", "osv", recordings=OSV)
    packages = {a["cause"]["advisory_id"]: a for a in b.ok("alerts", PACKAGE_MODEL)["alerts"]}
    b.ok(
        "alert",
        "dismiss",
        str(packages[DISMISSED]["alert_id"]),
        "--reason",
        "not_used_at_runtime",
        "--note",
        "the code path is not loaded",
        "--by",
        "Owner",
    )
    run = b.ok("check", PACKAGE_MODEL, "--source", "osv", recordings=b.withdrawn_osv())
    return {
        "open": by_file["b.pkl"]["alert_id"],
        "excepted": by_file["a.pkl"]["alert_id"],
        "fixed": by_file["c.pkl"]["alert_id"],
        "dismissed": packages[DISMISSED]["alert_id"],
        "withdrawn": packages["GHSA-cp9v-662q-vvx9"]["alert_id"],
        "run": run["run_id"],
    }


def invocations(ids: dict[str, Any]) -> list[tuple[str, list[str], str]]:
    """The named invocation list: (name, argv, database), text first, then ``--json``."""
    plain: list[tuple[str, list[str], str]] = []
    for model in (WEIGHTS_MODEL, PACKAGE_MODEL):
        for state in ("open", "excepted", "closed", "all"):
            plain.append(
                (f"alerts {model} --state {state}", ["alerts", model, "--state", state], "md")
            )
        plain.append((f"alerts {model}", ["alerts", model], "md"))
        plain.append((f"history {model}", ["history", model], "md"))
    for state in ("open", "excepted", "dismissed", "fixed", "withdrawn"):
        plain.append((f"alert show {state}", ["alert", "show", str(ids[state])], "md"))
    plain.append(("alert show unknown", ["alert", "show", "999"], "md"))
    plain.append(("alerts unknown", ["alerts", "no-such-model"], "md"))
    plain.append(("run show", ["run", "show", str(ids["run"])], "md"))
    check = ["check", WEIGHTS_MODEL, "--source", "picklescan"]
    plain.append(("check", check, "check"))
    plain.append(("check --fail-on HIGH", [*check, "--fail-on", "HIGH"], "gate"))
    listed: list[tuple[str, list[str], str]] = []
    for name, argv, db in plain:
        listed.append((name, argv, db))
        listed.append((f"{name} --json", [*argv, "--json"], db))
    return listed


def run_all(work: Path, craft: ModuleType) -> list[dict[str, Any]]:
    """Build the store in ``work`` (an empty directory) and run every invocation.

    ``check`` invocations run in copies of the store taken once the store is built, a fresh copy
    for each, so every invocation sees the same state wherever it is in the list.
    """
    b = Baseline(work, craft)
    ids = build(b)
    results = []
    for name, argv, db in invocations(ids):
        if db != "md":
            target = b.db(db)
            if target.parent.exists():
                shutil.rmtree(target.parent)
            shutil.copytree(b.db("md").parent, target.parent)
        code, out, err = b.run(argv, db=db)
        results.append(
            {
                "name": name,
                "argv": argv,
                "db": db,
                "stdout": b.normalise(out),
                "stderr": b.normalise(err),
                "exit_code": code,
            }
        )
    return results

"""The weight-checking scenarios of the default-policy equivalence baseline (feature 004, SC-002).

Each scenario is the register and check sequence of one weight-checking test in
``tests/integration/test_check_weights.py`` or ``tests/integration/test_register_from_record.py``,
plus one that registers and checks ``posix-path.pkl`` with ``--source picklescan`` (FR-007). The
baseline was recorded once from the build before feature 004 by
``tools/record_equivalence_baseline.py``; ``tests/integration/test_default_equivalence.py`` replays
the same scenarios and compares (research S10).

Nothing here loads a weight file: the dangerous pickle is built by ``craft.py`` into the scenario's
own directory. The clock is fixed, so registration records and their hashes do not depend on when
a scenario runs. A snapshot holds alerts and watch events read from the database by explicit
column, without ids and times, with the scenario's directory replaced by ``<work>``.
"""

from __future__ import annotations

import io
import json
import shutil
import sqlite3
from collections.abc import Callable
from contextlib import redirect_stdout
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from typing import Any

from model_dependabot.cli import main, make_handlers
from model_dependabot.sources.fetcher import RecordedFetcher

FIXTURES = Path(__file__).resolve().parent.parent
PICKLES = FIXTURES / "pickles"
WEIGHTS = FIXTURES / "manifests" / "weights"
HF = FIXTURES / "hf"
NOW = datetime(2026, 11, 13, 9, 0, tzinfo=UTC)
EICAR_REPO = "mcpotato/42-eicar-street"
EICAR_COMMIT = "8fb61c4d511e9aaff0ea55396a124aa292830efc"
HUB_WEIGHT = f'hub = "hf:{EICAR_REPO}"\nrevision = "{EICAR_COMMIT}"\nfile = "pytorch_model.bin"'
LOCAL = [
    'path = "weights/dangerous.pkl"',
    'path = "weights/suspicious.pkl"',
    'path = "weights/innocuous.pkl"',
    'path = "weights/model.joblib"',
    'path = "weights/tiny.onnx"',
]


class Scenario:
    """One scenario's directory, databases and command runner."""

    def __init__(self, work: Path, craft: ModuleType) -> None:
        self.work = work
        self.craft = craft
        self.none = work / "no-recordings"
        self.derived = 0

    def db(self, name: str = "md") -> Path:
        return self.work / "db" / name / "md.db"

    def cli(self, *argv: str, db: str = "md", recordings: Path | None = None) -> tuple[int, Any]:
        handlers = make_handlers(fetcher=RecordedFetcher(recordings or self.none), now=lambda: NOW)
        out = io.StringIO()
        with redirect_stdout(out):
            code = main([*argv, "--db", str(self.db(db)), "--json"], handlers=handlers)
        text = out.getvalue()
        return code, json.loads(text) if text.strip() else None

    def manifest(self, directory: Path, model_id: str, weights: list[str]) -> Path:
        directory.mkdir(parents=True, exist_ok=True)
        lines = ["[model]", f'id = "{model_id}"', 'name = "Equivalence model"', 'owner = "Owner"']
        for item in weights:
            lines += ["", "[[weights]]", item]
        path = directory / "model.toml"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path

    def derive_hf(self, security: Callable[[Any], Any] | None = None) -> Path:
        """The hub recordings, as ``tests/conftest.py`` ``derive_hf`` derives them."""
        root = self.work / f"hf-derived-{self.derived}"
        self.derived += 1
        root.mkdir(parents=True)
        for name in ("eicar-security", "eicar-tree-expand", "gpt2-security"):
            for suffix in (".json", ".meta.json"):
                shutil.copy(HF / f"{name}{suffix}", root / f"{name}{suffix}")
        expanded = json.loads((root / "eicar-tree-expand.json").read_text("utf-8"))
        plain = [{k: v for k, v in item.items() if k != "securityFileStatus"} for item in expanded]
        info = json.loads((root / "eicar-security.json").read_text("utf-8"))
        api = f"https://huggingface.co/api/models/{EICAR_REPO}"
        for name, url, body in (
            ("eicar-tree", f"{api}/tree/{EICAR_COMMIT}", plain),
            ("eicar-revision", f"{api}/revision/{EICAR_COMMIT}", info),
        ):
            (root / f"{name}.json").write_text(json.dumps(body), "utf-8")
            meta = {"method": "GET", "url": url, "status": 200, "headers": {}}
            meta |= {"retrieved_at": "2026-10-24T04:11:44Z", "body_file": f"{name}.json"}
            (root / f"{name}.meta.json").write_text(json.dumps(meta), "utf-8")
        if security is not None:
            body = root / "eicar-security.json"
            body.write_text(json.dumps(security(json.loads(body.read_text("utf-8")))), "utf-8")
        return root

    def owner_clone(self, root: Path, weights: list[str] = LOCAL) -> Path:
        folder = root / "weights"
        folder.mkdir(parents=True)
        (folder / "dangerous.pkl").write_bytes(self.craft.dangerous())
        shutil.copy(PICKLES / "suspicious.pkl", folder / "suspicious.pkl")
        shutil.copy(PICKLES / "innocuous.pkl", folder / "innocuous.pkl")
        shutil.copy(PICKLES / "joblib-style.joblib", folder / "model.joblib")
        shutil.copy(WEIGHTS / "tiny.onnx", folder / "tiny.onnx")
        return self.manifest(root, "record-model", weights)

    def recorded(self) -> tuple[Path, Path]:
        """The record-model manifest and its registration record in a folder without weights."""
        path = self.owner_clone(self.work / "owner")
        out = self.work / "out" / "model.record.json"
        self.ok("record", str(path), "--out", str(out))
        ci = self.work / "ci"
        ci.mkdir(parents=True)
        shutil.copy(path, ci / "model.toml")
        shutil.copy(out, ci / "model.record.json")
        return ci / "model.toml", ci / "model.record.json"

    def ok(self, *argv: str, **kwargs: Any) -> Any:
        code, payload = self.cli(*argv, **kwargs)
        if code != 0:
            raise AssertionError(f"{argv} exited {code}: {payload}")
        return payload


def _flag_bin(info: Any) -> Any:
    issues = info["securityRepoStatus"]["filesWithIssues"]
    issues.append({"path": "pytorch_model.bin", "level": "unsafe"})
    return info


# --- the scenarios ------------------------------------------------------------------------------


def dangerous_benign_and_onnx(s: Scenario) -> list[str]:
    model = s.work / "model"
    model.mkdir()
    (model / "dangerous.pkl").write_bytes(s.craft.dangerous())
    shutil.copy(PICKLES / "innocuous.pkl", model / "innocuous.pkl")
    shutil.copy(WEIGHTS / "tiny.onnx", model / "tiny.onnx")
    weights = ['path = "dangerous.pkl"', 'path = "innocuous.pkl"', 'path = "tiny.onnx"']
    s.ok("register", str(s.manifest(model, "weights-model", weights)))
    s.ok("check", "weights-model")
    return ["md"]


def joblib_incomplete(s: Scenario) -> list[str]:
    model = s.work / "model"
    model.mkdir()
    shutil.copy(PICKLES / "joblib-style.joblib", model / "model.joblib")
    s.ok("register", str(s.manifest(model, "joblib-model", ['path = "model.joblib"'])))
    s.ok("check", "joblib-model")
    return ["md"]


def hub_verdicts(s: Scenario) -> list[str]:
    clean = s.derive_hf()
    path = s.manifest(s.work / "hub", "hub-model", [HUB_WEIGHT])
    s.ok("register", str(path), recordings=clean)
    s.ok("check", "hub-model", "--source", "hf-scan", recordings=clean)
    s.ok("check", "hub-model", "--source", "hf-scan", recordings=s.derive_hf(security=_flag_bin))
    return ["md"]


def hub_fails_at_registration(s: Scenario) -> list[str]:
    path = s.manifest(s.work / "hub", "hub-model", [HUB_WEIGHT])
    s.ok("register", str(path), recordings=s.derive_hf())
    unsafe = s.derive_hf(security=_flag_bin)
    s.ok("check", "hub-model", "--source", "hf-scan", recordings=unsafe)
    down = s.work / "down"
    down.mkdir()
    for number, meta_path in enumerate(sorted(unsafe.glob("*.meta.json"))):
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        failed = {"method": meta["method"], "url": meta["url"], "error": "HTTP 503 after 4 tries"}
        (down / f"{number}.meta.json").write_text(json.dumps(failed), encoding="utf-8")
    s.ok("register", str(path), "--model-id", "hub-model", recordings=down)
    return ["md"]


def record_round_trip(s: Scenario) -> list[str]:
    path = s.owner_clone(s.work / "owner")
    s.ok("register", str(path), db="direct")
    s.ok("check", "record-model", "--source", "osv,picklescan,hf-scan", db="direct")
    out = s.work / "out" / "model.record.json"
    s.ok("record", str(path), "--out", str(out))
    ci = s.work / "ci"
    ci.mkdir(parents=True)
    shutil.copy(path, ci / "model.toml")
    shutil.copy(out, ci / "model.record.json")
    s.ok(
        "register", str(ci / "model.toml"), "--from-record", str(ci / "model.record.json"), db="ci"
    )
    s.ok("check", "record-model", "--source", "osv,hf-scan", db="ci")
    return ["direct", "ci"]


def record_hub_files(s: Scenario) -> list[str]:
    path = s.owner_clone(s.work / "owner", ['path = "weights/innocuous.pkl"', HUB_WEIGHT])
    out = s.work / "out" / "model.record.json"
    s.ok("record", str(path), "--out", str(out))
    ci = s.work / "ci"
    ci.mkdir(parents=True)
    shutil.copy(path, ci / "model.toml")
    shutil.copy(out, ci / "model.record.json")
    s.ok(
        "register",
        str(ci / "model.toml"),
        "--from-record",
        str(ci / "model.record.json"),
        recordings=s.derive_hf(),
    )
    return ["md"]


def record_check_osv_only(s: Scenario) -> list[str]:
    manifest, record = s.recorded()
    s.ok("register", str(manifest), "--from-record", str(record))
    s.ok("check", "record-model", "--source", "osv")
    return ["md"]


def record_picklescan_absent(s: Scenario) -> list[str]:
    manifest, record = s.recorded()
    s.ok("register", str(manifest), "--from-record", str(record))
    s.ok("check", "record-model", "--source", "picklescan")
    return ["md"]


def posix_path_picklescan(s: Scenario) -> list[str]:
    model = s.work / "model"
    model.mkdir()
    shutil.copy(PICKLES / "posix-path.pkl", model / "posix-path.pkl")
    s.ok("register", str(s.manifest(model, "posix-model", ['path = "posix-path.pkl"'])))
    s.ok("check", "posix-model", "--source", "picklescan")
    return ["md"]


SCENARIOS: dict[str, Callable[[Scenario], list[str]]] = {
    "check_weights.dangerous_benign_and_onnx": dangerous_benign_and_onnx,
    "check_weights.joblib_incomplete": joblib_incomplete,
    "check_weights.hub_verdicts": hub_verdicts,
    "check_weights.hub_fails_at_registration": hub_fails_at_registration,
    "register_from_record.round_trip": record_round_trip,
    "register_from_record.hub_files": record_hub_files,
    "register_from_record.check_osv_only": record_check_osv_only,
    "register_from_record.picklescan_absent": record_picklescan_absent,
    "posix_path.picklescan": posix_path_picklescan,
}


# --- snapshots ----------------------------------------------------------------------------------

ALERT_COLUMNS = (
    "model_id",
    "opened_in_version",
    "current_version",
    "kind",
    "cause_key",
    "cause",
    "severity",
    "severity_origin",
    "state",
    "closed_by_version",
    "dismissal_reason",
    "dismissed_by",
    "note",
)
EVENT_COLUMNS = ("model_id", "version", "entry_identifier", "kind", "detail")
EVIDENCE_COLUMNS = (
    "source",
    "url",
    "matched_identifier",
    "body_sha256",
    "detail",
    "original_sha256",
    "redacted_fields",
    "canonical_sha256",
)


def _evidence(conn: sqlite3.Connection, link: str, key: str, value: int) -> list[dict[str, Any]]:
    rows = conn.execute(
        f"SELECT {', '.join('e.' + c for c in EVIDENCE_COLUMNS)} FROM evidence e"
        f" JOIN {link} l ON l.evidence_id = e.evidence_id WHERE l.{key} = ? ORDER BY e.evidence_id",
        (value,),
    )
    return [dict(row) for row in rows]


def snapshot(db: Path, work: Path) -> dict[str, Any]:
    """The alerts and watch events of one database, row for row, without ids and times."""
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    try:
        alerts = []
        for row in conn.execute(
            f"SELECT alert_id, {', '.join(ALERT_COLUMNS)} FROM alerts ORDER BY alert_id"
        ).fetchall():
            record = {column: row[column] for column in ALERT_COLUMNS}
            record["evidence"] = _evidence(conn, "alert_evidence", "alert_id", row["alert_id"])
            alerts.append(record)
        events = []
        for row in conn.execute(
            f"SELECT watch_event_id, {', '.join(EVENT_COLUMNS)} FROM watch_events"
            " ORDER BY watch_event_id"
        ).fetchall():
            record = {column: row[column] for column in EVENT_COLUMNS}
            record["evidence"] = _evidence(
                conn, "watch_event_evidence", "watch_event_id", row["watch_event_id"]
            )
            events.append(record)
    finally:
        conn.close()
    text = json.dumps({"alerts": alerts, "watch_events": events}, sort_keys=True)
    for form in (work.resolve().as_uri(), str(work.resolve()), str(work)):
        text = text.replace(json.dumps(form)[1:-1], "<work>")
    return json.loads(text)


def run(name: str, work: Path, craft: ModuleType) -> dict[str, Any]:
    """Run one scenario in ``work`` (an empty directory) and snapshot its databases."""
    scenario = Scenario(work, craft)
    databases = SCENARIOS[name](scenario)
    return {db: snapshot(scenario.db(db), work) for db in databases}

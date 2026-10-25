"""Registering where the weights are not: ``record`` then ``register --from-record`` (feature 005).

The owner's machine hashes and scans the weight files and writes a registration record; another
machine, without the bytes, registers the model from the manifest and that record. These tests run
both halves offline: the dangerous pickle is built into ``tmp_path`` at test time and never
committed, and the second half runs in a directory that holds only the manifest and the record.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from conftest import EICAR_COMMIT, EICAR_REPO
from model_dependabot.cli import EXIT_INVALID_INPUT, EXIT_OK, main, make_handlers
from model_dependabot.sources.fetcher import RecordedFetcher

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
PICKLES = FIXTURES / "pickles"
WEIGHTS = FIXTURES / "manifests" / "weights"

Cli = Callable[..., tuple[int, Any]]


@pytest.fixture
def cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> Cli:
    def invoke(*argv: str, db: str = "md", recordings: Path = tmp_path / "none") -> tuple[int, Any]:
        handlers = make_handlers(fetcher=RecordedFetcher(recordings))
        database = tmp_path / "db" / db / "md.db"
        code = main([*argv, "--db", str(database), "--json"], handlers=handlers)
        out = capsys.readouterr().out
        return code, json.loads(out) if out.strip() else None

    return invoke


def manifest(directory: Path, model_id: str, weights: list[str]) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    lines = ["[model]", f'id = "{model_id}"', 'name = "Record test model"', 'owner = "Owner"']
    for item in weights:
        lines += ["", "[[weights]]", item]
    path = directory / "model.toml"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


LOCAL = [
    'path = "weights/dangerous.pkl"',
    'path = "weights/suspicious.pkl"',
    'path = "weights/innocuous.pkl"',
    'path = "weights/model.joblib"',
    'path = "weights/tiny.onnx"',
]


def owner_clone(root: Path, craft: ModuleType, weights: list[str] = LOCAL) -> Path:
    """A clone on the owner's machine: the manifest with its weight files beside it."""
    folder = root / "weights"
    folder.mkdir(parents=True)
    (folder / "dangerous.pkl").write_bytes(craft.dangerous())
    shutil.copy(PICKLES / "suspicious.pkl", folder / "suspicious.pkl")
    shutil.copy(PICKLES / "innocuous.pkl", folder / "innocuous.pkl")
    shutil.copy(PICKLES / "joblib-style.joblib", folder / "model.joblib")
    shutil.copy(WEIGHTS / "tiny.onnx", folder / "tiny.onnx")
    return manifest(root, "record-model", weights)


def ci_clone(root: Path, manifest_path: Path, record_path: Path) -> tuple[Path, Path]:
    """The same manifest and record in a directory with no weight files (hosted CI)."""
    root.mkdir(parents=True)
    copied = root / "model.toml"
    shutil.copy(manifest_path, copied)
    record = root / "model.record.json"
    shutil.copy(record_path, record)
    return copied, record


def canonical_sha256(record: dict[str, Any]) -> str:
    body = {key: value for key, value in record.items() if key != "record_sha256"}
    text = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def rewrite(path: Path, change: Callable[[dict[str, Any]], None], *, reseal: bool) -> None:
    record = json.loads(path.read_text(encoding="utf-8"))
    change(record)
    if reseal:
        record["record_sha256"] = canonical_sha256(record)
    path.write_text(json.dumps(record, indent=2), encoding="utf-8")


def make_record(cli: Cli, manifest_path: Path, out: Path) -> dict[str, Any]:
    code, payload = cli("record", str(manifest_path), "--out", str(out))
    assert code == EXIT_OK, payload
    assert payload["output"] == str(out)
    return json.loads(out.read_text(encoding="utf-8"))


def outcomes(cli: Cli, db: str, model_id: str) -> tuple[list[Any], list[Any], list[Any]]:
    _, shown = cli("inventory", "show", model_id, db=db)
    _, listed = cli("alerts", model_id, "--state", "all", db=db)
    alerts = sorted(
        (a["kind"], a["state"], a["severity"], a["severity_origin"], json.dumps(a["cause"]))
        for a in listed["alerts"]
    )
    events = sorted(
        (e["kind"], e["identifier"], json.dumps(e["detail"], sort_keys=True))
        for e in listed["watch_events"]
    )
    return shown["entries"] + shown["gaps"], alerts, events


# --- the record ---------------------------------------------------------------------------------


def test_record_lists_each_local_file_with_hash_format_and_scan(
    cli: Cli, tmp_path: Path, craft: ModuleType
) -> None:
    path = owner_clone(tmp_path / "owner", craft)
    record = make_record(cli, path, tmp_path / "out" / "model.record.json")

    assert record["schema_version"] == "1"
    assert record["model_id"] == "record-model"
    assert record["record_sha256"] == canonical_sha256(record)
    files = {item["location"]: item for item in record["weights"]}
    assert list(files) == [line.split('"')[1] for line in LOCAL]
    dangerous = files["weights/dangerous.pkl"]
    data = (tmp_path / "owner" / "weights" / "dangerous.pkl").read_bytes()
    assert dangerous["sha256"] == hashlib.sha256(data).hexdigest()
    assert dangerous["size"] == len(data)
    assert (dangerous["format"], dangerous["can_run_code"]) == ("pickle", True)
    scan = dangerous["scan"]
    assert (scan["scanner"], scan["scanner_version"], scan["verdict"]) == (
        "picklescan",
        "1.0.5",
        "dangerous",
    )
    assert {"module": "os", "name": "system", "safety": "dangerous"} in scan["globals"]
    assert scan["scanned_at"].endswith("Z")
    assert files["weights/suspicious.pkl"]["scan"]["verdict"] == "suspicious"
    joblib = files["weights/model.joblib"]["scan"]
    assert joblib["complete"] is False and joblib["verdict"] != "clean"  # never clean (FR-022)
    assert files["weights/innocuous.pkl"]["scan"]["verdict"] == "clean"
    onnx = files["weights/tiny.onnx"]
    assert (onnx["format"], onnx["can_run_code"], onnx["scan"]) == ("onnx", False, None)


def test_record_holds_no_bytes_and_no_absolute_paths(
    cli: Cli, tmp_path: Path, craft: ModuleType
) -> None:
    path = owner_clone(tmp_path / "owner", craft)
    out = tmp_path / "out" / "model.record.json"
    make_record(cli, path, out)
    text = out.read_text(encoding="utf-8")
    raw = out.read_bytes()

    for root in (tmp_path, tmp_path / "owner"):
        assert str(root) not in text
        assert root.as_posix() not in text
        assert json.dumps(str(root))[1:-1] not in text  # the JSON-escaped Windows form
    assert str(Path.home()) not in text
    for name in ("dangerous.pkl", "suspicious.pkl", "innocuous.pkl", "model.joblib", "tiny.onnx"):
        content = (tmp_path / "owner" / "weights" / name).read_bytes()
        assert content not in raw
        assert content[:16] not in raw
    record = json.loads(text)

    def strings(value: Any) -> list[str]:
        if isinstance(value, str):
            return [value]
        if isinstance(value, dict):
            return [s for item in value.values() for s in strings(item)]
        if isinstance(value, list):
            return [s for item in value for s in strings(item)]
        return []

    assert not [s for s in strings(record) if Path(s).is_absolute() or ":\\" in s]
    assert all("/" not in item["scan"]["file_name"] for item in record["weights"] if item["scan"])


# --- registering from the record ----------------------------------------------------------------


def test_round_trip_equals_direct_registration(cli: Cli, tmp_path: Path, craft: ModuleType) -> None:
    path = owner_clone(tmp_path / "owner", craft)
    # Direct: registered and scanned where the files are.
    assert cli("register", str(path), db="direct")[0] == EXIT_OK
    code, _ = cli("check", "record-model", "--source", "osv,picklescan,hf-scan", db="direct")
    assert code == EXIT_OK

    # Recorded: the owner records; CI registers without the files and checks without picklescan.
    out = tmp_path / "out" / "model.record.json"
    record = make_record(cli, path, out)
    ci_manifest, ci_record = ci_clone(tmp_path / "ci", path, out)
    assert not (tmp_path / "ci" / "weights").exists()
    code, registered = cli("register", str(ci_manifest), "--from-record", str(ci_record), db="ci")
    assert code == EXIT_OK, registered
    code, _ = cli("check", "record-model", "--source", "osv,hf-scan", db="ci")
    assert code == EXIT_OK

    direct = outcomes(cli, "direct", "record-model")
    recorded = outcomes(cli, "ci", "record-model")
    assert recorded[0] == direct[0]  # the same inventory entries
    assert recorded[1] == direct[1]  # the same alerts
    assert recorded[2] == direct[2]  # the same watch events
    assert [kind for kind, *_ in recorded[1]] == ["weight_file_scan"]
    assert {kind for kind, *_ in recorded[2]} == {
        "pickle_format",
        "scan_suspicious",
        "scan_incomplete",
    }

    # Principle I: the evidence is the recorded local scan, its scanner version and time, and the
    # record's SHA-256.
    _, listed = cli("alerts", "record-model", db="ci")
    [alert] = listed["alerts"]
    [evidence] = alert["evidence"]
    dangerous = next(i for i in record["weights"] if i["location"] == "weights/dangerous.pkl")
    assert evidence["source"] == "picklescan"
    assert evidence["url"] == f"registration-record:sha256:{record['record_sha256']}"
    assert evidence["retrieved_at"] == dangerous["scan"]["scanned_at"]
    assert evidence["matched_identifier"] == f"sha256:{dangerous['sha256']}"
    assert alert["cause"]["scanner_version"] == "1.0.5"


def test_hub_files_register_as_before(
    cli: Cli, tmp_path: Path, craft: ModuleType, derive_hf: Callable[..., Path]
) -> None:
    hub_weight = f'hub = "hf:{EICAR_REPO}"\nrevision = "{EICAR_COMMIT}"\nfile = "pytorch_model.bin"'
    path = owner_clone(tmp_path / "owner", craft, ['path = "weights/innocuous.pkl"', hub_weight])
    out = tmp_path / "out" / "model.record.json"
    record = make_record(cli, path, out)
    assert [item["location"] for item in record["weights"]] == ["weights/innocuous.pkl"]
    ci_manifest, ci_record = ci_clone(tmp_path / "ci", path, out)
    clean = derive_hf()
    code, registered = cli(
        "register", str(ci_manifest), "--from-record", str(ci_record), recordings=clean
    )
    assert code == EXIT_OK, registered
    hub = [entry for entry in registered["entries"] if entry.get("hub_repo")]
    assert len(hub) == 1 and hub[0]["identifier"].startswith("sha256:")


# --- refusals: non-zero exit, a clear message and nothing written ------------------------------


def _refused(cli: Cli, manifest_path: Path, record_path: Path, message: str) -> None:
    code, payload = cli("register", str(manifest_path), "--from-record", str(record_path))
    assert code == EXIT_INVALID_INPUT
    assert message in payload["error"]["message"]
    assert cli("inventory", "show", "record-model")[0] == EXIT_INVALID_INPUT  # nothing written


@pytest.fixture
def recorded(cli: Cli, tmp_path: Path, craft: ModuleType) -> tuple[Path, Path, Path]:
    path = owner_clone(tmp_path / "owner", craft)
    out = tmp_path / "out" / "model.record.json"
    make_record(cli, path, out)
    ci_manifest, ci_record = ci_clone(tmp_path / "ci", path, out)
    return path, ci_manifest, ci_record


def test_tampered_record_sha256_is_refused(cli: Cli, recorded: tuple[Path, Path, Path]) -> None:
    _, ci_manifest, ci_record = recorded

    def smaller(record: dict[str, Any]) -> None:
        record["weights"][0]["size"] -= 1

    rewrite(ci_record, smaller, reseal=False)
    _refused(cli, ci_manifest, ci_record, "record_sha256")


def test_mismatched_model_id_is_refused(
    cli: Cli, recorded: tuple[Path, Path, Path], tmp_path: Path
) -> None:
    _, ci_manifest, ci_record = recorded

    def other_model(record: dict[str, Any]) -> None:
        record["model_id"] = "another-model"

    rewrite(ci_record, other_model, reseal=True)
    _refused(cli, ci_manifest, ci_record, "model id")


def test_mismatched_file_list_is_refused(cli: Cli, recorded: tuple[Path, Path, Path]) -> None:
    _, ci_manifest, ci_record = recorded

    def drop_file(record: dict[str, Any]) -> None:
        record["weights"].pop()

    rewrite(ci_record, drop_file, reseal=True)
    _refused(cli, ci_manifest, ci_record, "weight files")


def test_changed_manifest_is_refused(cli: Cli, recorded: tuple[Path, Path, Path]) -> None:
    _, ci_manifest, ci_record = recorded
    text = ci_manifest.read_text(encoding="utf-8")
    ci_manifest.write_text(text.replace("Record test model", "Renamed model"), encoding="utf-8")
    _refused(cli, ci_manifest, ci_record, "manifest")


def test_line_endings_of_the_manifest_do_not_matter(
    cli: Cli, recorded: tuple[Path, Path, Path]
) -> None:
    _, ci_manifest, ci_record = recorded
    data = ci_manifest.read_bytes()
    crlf = b"\r\n" in data
    flipped = data.replace(b"\r\n", b"\n") if crlf else data.replace(b"\n", b"\r\n")
    assert flipped != data
    ci_manifest.write_bytes(flipped)
    code, payload = cli("register", str(ci_manifest), "--from-record", str(ci_record))
    assert code == EXIT_OK, payload


def test_missing_scan_evidence_for_a_pickle_file_is_refused(
    cli: Cli, recorded: tuple[Path, Path, Path]
) -> None:
    _, ci_manifest, ci_record = recorded

    def unscanned(record: dict[str, Any]) -> None:
        record["weights"][0]["scan"] = None

    rewrite(ci_record, unscanned, reseal=True)
    _refused(cli, ci_manifest, ci_record, "scan evidence")


def test_a_code_free_claim_for_a_pickle_is_refused(
    cli: Cli, recorded: tuple[Path, Path, Path]
) -> None:
    _, ci_manifest, ci_record = recorded

    def disguised(record: dict[str, Any]) -> None:
        record["weights"][0].update(format="safetensors", can_run_code=False, scan=None)

    rewrite(ci_record, disguised, reseal=True)
    _refused(cli, ci_manifest, ci_record, "format")


def test_unknown_schema_version_is_refused(cli: Cli, recorded: tuple[Path, Path, Path]) -> None:
    _, ci_manifest, ci_record = recorded

    def future(record: dict[str, Any]) -> None:
        record["schema_version"] = "2"

    rewrite(ci_record, future, reseal=True)
    _refused(cli, ci_manifest, ci_record, "schema_version")


# --- checking where the bytes are not -----------------------------------------------------------


def test_check_without_picklescan_reads_no_local_file(
    cli: Cli, recorded: tuple[Path, Path, Path]
) -> None:
    _, ci_manifest, ci_record = recorded
    assert cli("register", str(ci_manifest), "--from-record", str(ci_record))[0] == EXIT_OK
    _, before = cli("alerts", "record-model")
    code, checked = cli("check", "record-model", "--source", "osv")
    assert code == EXIT_OK
    [model] = checked["models"]
    assert model["watch_events"] == []
    _, after = cli("alerts", "record-model")
    assert (after["alerts"], after["watch_events"]) == (before["alerts"], before["watch_events"])


def test_picklescan_on_absent_bytes_is_a_watch_event(
    cli: Cli, recorded: tuple[Path, Path, Path]
) -> None:
    _, ci_manifest, ci_record = recorded
    assert cli("register", str(ci_manifest), "--from-record", str(ci_record))[0] == EXIT_OK
    _, before = cli("alerts", "record-model")
    code, checked = cli("check", "record-model", "--source", "picklescan")
    assert code == EXIT_OK
    assert checked["sources"]["picklescan"] == "ok"
    [model] = checked["models"]
    assert model["opened"] == []
    _, after = cli("alerts", "record-model")
    assert [a["alert_id"] for a in after["alerts"]] == [a["alert_id"] for a in before["alerts"]]
    absent = [event for event in after["watch_events"] if event["kind"] == "weight_file_absent"]
    assert {event["detail"]["location"] for event in absent} == {
        "weights/dangerous.pkl",
        "weights/suspicious.pkl",
        "weights/innocuous.pkl",
        "weights/model.joblib",
    }
    assert all("not on this machine" in event["detail"]["reason"] for event in absent)
    assert all(event["detail"]["record_sha256"] for event in absent)
    # A read error is not reported as an incomplete scan for these files.
    incomplete = [event for event in after["watch_events"] if event["kind"] == "scan_incomplete"]
    assert [event["detail"]["location"] for event in incomplete] == ["weights/model.joblib"]
    assert all("cannot read" not in str(event["detail"]) for event in incomplete)

"""Registration records: a manifest's local weight-file facts, made where the weights are (005).

Registration is split in two when the machine that runs ``check`` does not hold the weight files
(contracts/registration-record.md). On the owner's machine, ``record`` hashes each local weight file
in chunks, classifies its format, scans each code-capable file with the local pickle scanner (hash,
scan, hash again through one handle) and writes a canonical JSON record. Elsewhere,
``register --from-record`` takes the hashes, formats and scan results from that record instead of
reading the bytes, and refuses a record that does not match the manifest.

A record holds no weight bytes and no path beyond what the manifest declares: each file is named by
its manifest ``path``, and the scan names the file by its base name only. ``record_sha256`` is the
SHA-256 of the canonical JSON of every other field; it detects a record changed after it was made.
It is a checksum, not a signature: the record's authority is the reviewed change that brought it.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from model_dependabot import __version__
from model_dependabot.inventory.build import (
    CODE_FREE_FORMATS,
    classify,
    hash_stream,
    new_entry,
)
from model_dependabot.manifest import Manifest, WeightSpec
from model_dependabot.sources import pickle_scan
from model_dependabot.store import utc_text

RECORD_SCHEMA_VERSION = "1"
RECORD_URL_PREFIX = "registration-record:sha256:"
GENERATOR = "model-dependabot"
VERDICTS = ("dangerous", "suspicious", "incomplete", "clean")

_TOP_KEYS = {"schema_version", "model_id", "manifest_sha256", "generator", "weights"}
_FILE_KEYS = {"location", "sha256", "size", "format", "can_run_code", "scan"}
_SCAN_KEYS = {
    "scanner",
    "scanner_version",
    "file_name",
    "size",
    "complete",
    "position",
    "error",
    "globals",
    "verdict",
    "scanned_at",
}
_GLOBAL_KEYS = {"module", "name", "safety"}
_SAFETIES = (pickle_scan.DANGEROUS, pickle_scan.SUSPICIOUS, pickle_scan.INNOCUOUS)
_HEX = set("0123456789abcdef")
_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


class RecordError(ValueError):
    """The record cannot be made, or does not fit the manifest (exit code 1)."""


@dataclass(frozen=True)
class RecordedScan:
    """One file's recorded local scan, as ``check`` would have made it."""

    report: pickle_scan.ScanReport
    scanned_at: datetime
    body: bytes


def manifest_sha256(raw: bytes) -> str:
    """The manifest's SHA-256 with CRLF line endings read as LF.

    A manifest checked out on another machine can differ only in line endings (git's
    ``core.autocrlf``); that is the same manifest.
    """
    return hashlib.sha256(raw.replace(b"\r\n", b"\n")).hexdigest()


def canonical(body: Mapping[str, Any]) -> bytes:
    """The canonical JSON ``record_sha256`` is taken over: sorted keys, no spaces, UTF-8."""
    text = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return text.encode("utf-8")


def record_sha256(record: Mapping[str, Any]) -> str:
    body = {key: value for key, value in record.items() if key != "record_sha256"}
    return hashlib.sha256(canonical(body)).hexdigest()


def verdict(report: pickle_scan.ScanReport) -> str:
    """One word for the scan: a dangerous global, else a suspicious one, else a scan that stopped
    early, else ``clean``. An incomplete scan is never clean (FR-022)."""
    if report.dangerous:
        return "dangerous"
    if report.suspicious:
        return "suspicious"
    if not report.complete:
        return "incomplete"
    return "clean"


# --- making a record (on the machine with the weights) ------------------------------------------


def _record_file(spec: WeightSpec, now: Callable[[], datetime]) -> dict[str, Any]:
    assert spec.path is not None and spec.relative is not None
    file_format, can_run_code = classify(spec.path.name, spec.path)
    scan = None
    # Hashed, scanned and hashed again through one handle, as a check's local scan is: the scan
    # counts only if both hashes agree.
    with spec.path.open("rb") as handle:
        sha256, size = hash_stream(handle)
        if can_run_code:
            report = pickle_scan.scan_handle(handle, spec.path.name)
            scanned_at = now()
            handle.seek(0)
            again, _ = hash_stream(handle)
            if again != sha256:
                raise RecordError(f"{spec.relative} changed while it was scanned; record it again")
            scan = {
                **report.as_record(),
                "verdict": verdict(report),
                "scanned_at": utc_text(scanned_at),
            }
    return {
        "location": spec.relative,
        "sha256": sha256,
        "size": size,
        "format": file_format,
        "can_run_code": can_run_code,
        "scan": scan,
    }


def make_record(manifest: Manifest, now: Callable[[], datetime] | None = None) -> dict[str, Any]:
    """The registration record of a manifest's local weight files; hub files are not in it.

    Raises ``OSError`` if a weight file cannot be read.
    """
    clock = now or (lambda: datetime.now(UTC))
    body: dict[str, Any] = {
        "schema_version": RECORD_SCHEMA_VERSION,
        "model_id": manifest.model_id,
        "manifest_sha256": manifest_sha256(manifest.path.read_bytes()),
        "generator": {"name": GENERATOR, "version": __version__},
        "weights": [_record_file(spec, clock) for spec in manifest.weights if spec.path],
    }
    return {**body, "record_sha256": record_sha256(body)}


def write_record(record: Mapping[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(record, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    path.write_text(text, encoding="utf-8")


# --- reading a record (where the weights are not) -----------------------------------------------


def _keys(value: Any, where: str, allowed: set[str]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RecordError(f"{where} must be an object")
    missing, unknown = sorted(allowed - set(value)), sorted(set(value) - allowed)
    if missing or unknown:
        raise RecordError(
            f"{where}: missing {missing or 'nothing'}, unknown {unknown or 'nothing'}"
        )
    return value


def _sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and set(value) <= _HEX


def _count(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def load_record(path: Path | str) -> dict[str, Any]:
    """Read a record and check its schema version and ``record_sha256``."""
    try:
        record = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise RecordError(f"cannot read {path} as a registration record: {error}") from None
    if not isinstance(record, dict):
        raise RecordError("a registration record must be a JSON object")
    if record.get("schema_version") != RECORD_SCHEMA_VERSION:
        raise RecordError(
            f"unknown registration record schema_version {record.get('schema_version')!r};"
            f" this version reads {RECORD_SCHEMA_VERSION!r}"
        )
    _keys(record, "the record", _TOP_KEYS | {"record_sha256"})
    if record["record_sha256"] != record_sha256(record):
        raise RecordError(
            "the record's record_sha256 does not match its content: it was changed after it was"
            " made; record it again"
        )
    return record


def _check_class(location: str, file_format: Any, can_run_code: Any) -> None:
    by_name = classify(location, None)
    allowed = {by_name}
    if by_name[0] not in CODE_FREE_FORMATS.values():
        allowed.add(("pytorch-zip", True))  # only the bytes show a zip; the name cannot rule it out
    if (file_format, can_run_code) not in allowed:
        raise RecordError(
            f"{location}: format {file_format!r} with can_run_code {can_run_code!r} does not fit"
            " the file name"
        )


def _check_scan(location: str, size: int, scan: Any) -> RecordedScan:
    where = f"{location}: scan"
    _keys(scan, where, _SCAN_KEYS)
    if scan["scanner"] != pickle_scan.SCANNER:
        raise RecordError(f"{where}: unknown scanner {scan['scanner']!r}")
    if not isinstance(scan["scanner_version"], str) or not scan["scanner_version"]:
        raise RecordError(f"{where}: scanner_version must be a non-empty string")
    if scan["file_name"] != PurePosixPath(location).name:
        raise RecordError(f"{where}: file_name {scan['file_name']!r} is not the file's name")
    if scan["size"] != size:
        raise RecordError(f"{where}: size {scan['size']!r} is not the file's size {size}")
    if not isinstance(scan["complete"], bool):
        raise RecordError(f"{where}: complete must be true or false")
    if scan["position"] is not None and not _count(scan["position"]):
        raise RecordError(f"{where}: position must be a byte count or null")
    if scan["error"] is not None and not isinstance(scan["error"], str):
        raise RecordError(f"{where}: error must be text or null")
    if not isinstance(scan["globals"], list):
        raise RecordError(f"{where}: globals must be a list")
    findings = []
    for index, found in enumerate(scan["globals"]):
        _keys(found, f"{where}.globals[{index}]", _GLOBAL_KEYS)
        if found["safety"] not in _SAFETIES or not all(
            isinstance(found[key], str) for key in ("module", "name")
        ):
            raise RecordError(f"{where}.globals[{index}] is not a scanner finding")
        findings.append(pickle_scan.Finding(found["module"], found["name"], found["safety"]))
    try:
        scanned_at = datetime.strptime(str(scan["scanned_at"]), _TIME_FORMAT).replace(tzinfo=UTC)
    except ValueError:
        raise RecordError(
            f"{where}: scanned_at must be a UTC time like 2026-10-25T08:00:00Z"
        ) from None
    report = pickle_scan.ScanReport(
        file_name=scan["file_name"],
        size=size,
        findings=tuple(findings),
        complete=scan["complete"],
        position=scan["position"],
        error=scan["error"],
        scanner=scan["scanner"],
        scanner_version=scan["scanner_version"],
    )
    if scan["verdict"] != verdict(report):
        raise RecordError(f"{where}: verdict {scan['verdict']!r} does not follow from its findings")
    return RecordedScan(report, scanned_at, canonical(scan))


@dataclass(frozen=True)
class CheckedRecord:
    """A record that fits its manifest: the entries for its files and their recorded scans."""

    record_sha256: str
    entries: dict[str, dict[str, Any]]
    scans: dict[str, RecordedScan]

    def local_entry(self, spec: WeightSpec) -> dict[str, Any]:
        assert spec.relative is not None
        return dict(self.entries[spec.relative])


def check_record(manifest: Manifest, record: Mapping[str, Any]) -> CheckedRecord:
    """Refuse a record that does not fit the manifest; otherwise its entries and scans.

    The model id, the manifest's SHA-256 and the list of local weight files must all match, every
    file's format must fit its name, and every code-capable file must carry its scan evidence.
    """
    if record["model_id"] != manifest.model_id:
        raise RecordError(
            f"the record's model id {record['model_id']!r} does not match the manifest's"
            f" {manifest.model_id!r}"
        )
    if record["manifest_sha256"] != manifest_sha256(manifest.path.read_bytes()):
        raise RecordError(
            "the record was made from a different manifest (manifest_sha256 does not match);"
            " record it again from this manifest"
        )
    if not isinstance(record["weights"], list):
        raise RecordError("the record's weights must be a list")
    files = [_keys(item, f"weights[{n}]", _FILE_KEYS) for n, item in enumerate(record["weights"])]
    declared = [spec.relative for spec in manifest.weights if spec.path is not None]
    listed = [item["location"] for item in files]
    if listed != declared:
        missing = [item for item in declared if item not in listed]
        extra = [item for item in listed if item not in declared]
        raise RecordError(
            "the record's weight files do not match the manifest's local weight files"
            f" (missing {missing or 'none'}, extra {extra or 'none'}, order as in the manifest)"
        )
    entries: dict[str, dict[str, Any]] = {}
    scans: dict[str, RecordedScan] = {}
    for item in files:
        location = str(item["location"])
        if not _sha256(item["sha256"]) or not _count(item["size"]):
            raise RecordError(f"{location}: sha256 must be 64 lower-case hex digits, size a count")
        _check_class(location, item["format"], item["can_run_code"])
        if item["can_run_code"] is True:
            if item["scan"] is None:
                raise RecordError(
                    f"{location} can run code when loaded but the record has no scan evidence"
                    " for it; record it again where the file is"
                )
            scans[location] = _check_scan(location, item["size"], item["scan"])
        elif item["scan"] is not None:
            raise RecordError(f"{location}: scan evidence is only for a file that can run code")
        entries[location] = new_entry(
            "weight_file",
            identifier=f"sha256:{item['sha256']}",
            pinned=True,
            location=location,
            size=item["size"],
            format=item["format"],
            can_run_code=item["can_run_code"],
        )
    return CheckedRecord(str(record["record_sha256"]), entries, scans)

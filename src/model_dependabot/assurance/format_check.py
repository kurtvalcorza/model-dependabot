"""The ``format-check`` source: confirming imported and legacy weight-file claims (research A3-A5).

For each pinned weight file whose format claim needs confirmation (``trust.needs_confirmation``),
the source confirms the file's identity (claim ``identity``: the local file's SHA-256, or the hub
tree's SHA-256 at the pinned commit) and, when the claim is that the file cannot run code, its
format (claim ``code_free``: the local bytes, or a bounded header read of the hub file). Each
attempt is one claim check, ``confirmed``, ``contradicted`` or ``unreadable``, with one evidence
row holding a JSON summary of what was read and never the file's bytes.

``confirmed`` and ``contradicted`` are final for the version, entry and claim, so they are never
read again; ``unreadable`` (a missing file, a refusal, a header over the limit) is read again at
the next run. A local file is read only inside the version's ``base_dir``: an absolute path, a
path that leaves it and a symbolic link out of it are never opened. A hub file without a pinned
commit is never read, since its bytes could change. A network error, a server error after
retries or an answer cut off mid-read raises ``SourceFailedError`` from ``read_claims``, before
anything is recorded, so a failed source leaves every claim unverified, which already counts as
absent (fail closed). A version with nothing to confirm makes no request.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, BinaryIO

from model_dependabot.assurance.trust import (
    CODE_FREE,
    IDENTITY,
    latest_check,
    needs_confirmation,
)
from model_dependabot.inventory.build import (
    NO_ONNX_STRUCTURE,
    ZIP_TAIL,
    classify,
    hash_file,
    shows_onnx,
)
from model_dependabot.sources.fetcher import Fetcher, SourceFailedError
from model_dependabot.sources.hf import HEADER_LEAD, HuggingFace, is_commit
from model_dependabot.store import Store

SOURCE = "format-check"
FINAL = ("confirmed", "contradicted")
FILE_ABSENT = "file absent"
OUTSIDE = "outside the version's directory"
NO_BASE_DIR = "the version records no directory for its local files"


@dataclass(frozen=True)
class VersionTarget:
    """One model version as the source reads it."""

    model_id: str
    version: int
    origin: str | None
    base_dir: str | None
    entries: list[dict[str, Any]]


@dataclass(frozen=True)
class ClaimRead:
    """One claim check read but not yet recorded."""

    model_id: str
    version: int
    entry: Mapping[str, Any]
    claim: str
    outcome: str
    measured_format: str | None
    measured_can_run_code: bool | None
    reason: str | None
    url: str
    retrieved_at: datetime
    summary: dict[str, Any] = field(default_factory=dict)

    @property
    def identifier(self) -> str:
        return str(self.entry["identifier"])


@dataclass(frozen=True)
class AppliedClaim:
    """A recorded claim check: its row and its evidence."""

    read: ClaimRead
    claim_check_id: int
    evidence_id: int


@dataclass(frozen=True)
class _Wanted:
    identity: bool
    code_free: bool


def _wanted(entry: Mapping[str, Any], checks: Sequence[Mapping[str, Any]]) -> _Wanted | None:
    """Which claims of an entry are still to be checked, or ``None`` when none is."""
    identifier = entry["identifier"]
    identity = latest_check(checks, identifier, IDENTITY)
    if identity is not None and identity["outcome"] == "contradicted":
        return None  # the file is not the one pinned: nothing more about it can be confirmed
    code_free = latest_check(checks, identifier, CODE_FREE)
    want = _Wanted(
        identity=identity is None or identity["outcome"] not in FINAL,
        code_free=entry.get("can_run_code") is False
        and (code_free is None or code_free["outcome"] not in FINAL),
    )
    return want if want.identity or want.code_free else None


def pending(
    target: VersionTarget, checks: Sequence[Mapping[str, Any]]
) -> list[tuple[dict[str, Any], _Wanted]]:
    """The version's weight files with claims still to check (empty: no request is made)."""
    found = []
    for entry in target.entries:
        if not entry.get("pinned") or not needs_confirmation(entry, target.origin):
            continue
        if entry.get("hub_repo") and not is_commit(entry.get("hub_revision")):
            continue  # no pinned commit: the bytes could change, so they are never read
        if not entry.get("hub_repo") and not entry.get("location"):
            continue
        want = _wanted(entry, checks)
        if want is not None:
            found.append((entry, want))
    return found


def _ends(handle: BinaryIO, size: int) -> tuple[bytes, bytes]:
    """A local file's first ``HEADER_LEAD`` bytes and its last ``ZIP_TAIL`` bytes."""
    lead = handle.read(HEADER_LEAD)
    handle.seek(max(0, size - ZIP_TAIL))
    return lead, handle.read(ZIP_TAIL)


def _unproven_onnx(
    file_format: str | None, can_run_code: bool | None, lead: bytes, size: int, tail: bytes
) -> bool:
    """An ``.onnx`` file classified code-free by its name whose bytes show no ONNX model.

    Its imported code-free claim stays unverified (review F2, PR #15 R5): the claim check is
    ``unreadable`` with ``NO_ONNX_STRUCTURE``, so the claim never counts under the strict policy.
    A zip signature in the file's lead or tail refuses it too (PR #15 round 2, G2).
    """
    return file_format == "onnx" and can_run_code is False and not shows_onnx(lead, size, tail)


def _code_free_outcome(
    file_format: str | None, can_run_code: bool | None
) -> tuple[str, str | None]:
    if can_run_code is False:
        return "confirmed", None
    if can_run_code is True:
        return "contradicted", f"the bytes show {file_format}, which can run code when loaded"
    return "contradicted", f"the bytes show {file_format}, not a format that cannot run code"


def _rows(
    target: VersionTarget,
    entry: Mapping[str, Any],
    want: _Wanted,
    *,
    identity: str,
    identity_reason: str | None,
    measured: tuple[str | None, bool | None] | None,
    reason: str | None,
    url: str,
    retrieved_at: datetime,
    summary: dict[str, Any],
) -> list[ClaimRead]:
    """The claim checks one read gives: identity, then code-free when wanted and possible."""
    rows: list[ClaimRead] = []

    def row(claim: str, outcome: str, fmt: str | None, crc: bool | None, why: str | None) -> None:
        rows.append(
            ClaimRead(
                target.model_id,
                target.version,
                entry,
                claim,
                outcome,
                fmt,
                crc,
                why,
                url,
                retrieved_at,
                summary | {"claim": claim, "outcome": outcome, "reason": why},
            )
        )

    if want.identity:
        row(IDENTITY, identity, None, None, identity_reason)
    if not want.code_free or identity == "contradicted":
        return rows
    if identity == "unreadable":
        row(CODE_FREE, "unreadable", None, None, identity_reason)
    elif measured is None or measured[0] is None:
        row(CODE_FREE, "unreadable", None, None, reason)
    else:
        outcome, why = _code_free_outcome(*measured)
        row(CODE_FREE, outcome, measured[0], measured[1], why)
    return rows


def _outside(location: str) -> bool:
    return (
        Path(location).is_absolute()
        or location.startswith(("/", "\\"))
        or bool(PureWindowsPath(location).drive)
    )


def contained(base_dir: str | Path, location: str) -> Path | None:
    """The file ``location`` names inside ``base_dir``, or ``None`` if it would be outside.

    An absolute path, a ``..`` that leaves the directory and a symbolic link that points out of
    it are all outside; the path is resolved, so the check is on the file that would be opened.
    """
    if _outside(location):
        return None
    base = Path(base_dir).resolve()
    path = (base / location).resolve()  # a symbolic link is resolved to where it points
    return path if path.is_relative_to(base) else None


@dataclass(frozen=True)
class ImportMeasure:
    """An imported local weight file classified from its bytes at import (research A5)."""

    entry: dict[str, Any]
    contradicted: bool
    url: str
    retrieved_at: datetime
    summary: dict[str, Any]


def measure_imported(
    entries: Sequence[dict[str, Any]], base_dir: str | Path, now: datetime
) -> list[ImportMeasure]:
    """Classify each pinned local weight file present inside ``base_dir`` from its bytes.

    The bytes win (FR-003): a present file whose hash matches its entry gets the class its bytes
    show and the format origin ``bytes``. A file outside the directory, absent or with another
    hash keeps the document's claim, which ``format-check`` handles at the next check. ``entries``
    are changed in place; the measures returned say which claims the bytes contradicted.
    """
    measures = []
    for entry in entries:
        if entry["kind"] != "weight_file" or not entry["pinned"] or entry.get("hub_repo"):
            continue
        location = entry.get("location")
        path = None if not location else contained(base_dir, str(location))
        if path is None or not path.is_file():
            continue
        try:
            sha256, size = hash_file(path)
            if f"sha256:{sha256}" != entry["identifier"]:
                continue
            with path.open("rb") as handle:
                lead, tail = _ends(handle, size)
            file_format, can_run_code = classify(path.name, path)
        except OSError:
            continue
        if _unproven_onnx(file_format, can_run_code, lead, size, tail):
            continue  # the name alone confirms nothing: format-check reads it as unverified
        claimed = (entry["format"], entry["can_run_code"])
        contradicted = claimed[1] is False and can_run_code is not False
        entry.update(format=file_format, can_run_code=can_run_code, format_origin="bytes")
        summary = {
            "path": location,
            "base_dir": str(Path(base_dir).resolve()),
            "file": path.name,
            "sha256": f"sha256:{sha256}",
            "total_size": size,
            "lead_sha256": hashlib.sha256(lead).hexdigest(),
            "lead_length": len(lead),
            "claimed_format": claimed[0],
            "claimed_can_run_code": claimed[1],
            "measured_format": file_format,
            "measured_can_run_code": can_run_code,
            "claim": CODE_FREE,
            "outcome": "contradicted" if contradicted else "confirmed",
        }
        measures.append(ImportMeasure(entry, contradicted, path.as_uri(), now, summary))
    return measures


def record_import_contradictions(
    store: Store, model_id: str, version: int, measures: Sequence[ImportMeasure]
) -> list[int]:
    """Record each claim the bytes contradicted at import as a claim check with no run."""
    reads = [
        ClaimRead(
            model_id,
            version,
            measure.entry,
            CODE_FREE,
            "contradicted",
            measure.entry["format"],
            measure.entry["can_run_code"],
            _code_free_outcome(measure.entry["format"], measure.entry["can_run_code"])[1],
            measure.url,
            measure.retrieved_at,
            measure.summary,
        )
        for measure in measures
        if measure.contradicted
    ]
    return [applied.claim_check_id for applied in apply_claims(store, None, reads)]


def read_local(
    target: VersionTarget, entry: Mapping[str, Any], want: _Wanted, now: datetime
) -> list[ClaimRead]:
    """Confirm a local file's claims from its bytes, inside the version's directory only (A5)."""
    location = str(entry["location"])
    summary: dict[str, Any] = {
        "path": location,
        "base_dir": target.base_dir,
        "file": PurePosixPath(location.replace("\\", "/")).name,
        "commit": None,
        "status": None,
        "content_range": None,
    }

    def unreadable(reason: str, url: str = location) -> list[ClaimRead]:
        return _rows(
            target,
            entry,
            want,
            identity="unreadable",
            identity_reason=reason,
            measured=None,
            reason=reason,
            url=url,
            retrieved_at=now,
            summary=summary,
        )

    if target.base_dir is None:
        return unreadable(NO_BASE_DIR)
    path = contained(target.base_dir, location)
    if path is None:
        return unreadable(OUTSIDE)
    if not path.is_file():
        return unreadable(FILE_ABSENT, path.as_uri())
    try:
        sha256, size = hash_file(path)
        with path.open("rb") as handle:
            lead, tail = _ends(handle, size)
        file_format, can_run_code = classify(path.name, path)
    except OSError as error:
        return unreadable(f"cannot read the file: {error.strerror or error}", path.as_uri())
    summary |= {
        "sha256": f"sha256:{sha256}",
        "total_size": size,
        "lead_sha256": hashlib.sha256(lead).hexdigest(),
        "lead_length": len(lead),
        "measured_format": file_format,
        "measured_can_run_code": can_run_code,
    }
    if f"sha256:{sha256}" != entry["identifier"]:
        reason = f"the file's SHA-256 is sha256:{sha256}, the inventory pins {entry['identifier']}"
        identity, identity_reason = "contradicted", reason
    else:
        identity, identity_reason = "confirmed", None
    unproven = _unproven_onnx(file_format, can_run_code, lead, size, tail)
    return _rows(
        target,
        entry,
        want,
        identity=identity,
        identity_reason=identity_reason,
        measured=None if unproven else (file_format, can_run_code),
        reason=NO_ONNX_STRUCTURE if unproven else None,
        url=path.as_uri(),
        retrieved_at=now,
        summary=summary,
    )


def read_hub(
    hub: HuggingFace, target: VersionTarget, entry: Mapping[str, Any], want: _Wanted, now: datetime
) -> list[ClaimRead]:
    """Confirm a hub file's claims from its tree and a bounded header read (research A4)."""
    expected = str(entry["identifier"]).removeprefix("sha256:")
    read = hub.read_header(
        entry["hub_repo"], entry["hub_revision"], entry["hub_file"], expected, header=want.code_free
    )
    measured = None if read.format is None else (read.format, read.can_run_code)
    return _rows(
        target,
        entry,
        want,
        identity=read.identity,
        identity_reason=read.reason,
        measured=measured,
        reason=read.reason,
        url=read.url,
        retrieved_at=read.retrieved_at or now,
        summary=read.summary(),
    )


class ClaimReadFailedError(SourceFailedError):
    """The hub could not be read. ``reads`` holds the local reads, which need no source."""

    def __init__(self, error: SourceFailedError, reads: list[ClaimRead]) -> None:
        super().__init__(error.source, error.reason)
        self.reads = reads


def read_claims(
    store: Store, fetcher: Fetcher, targets: Sequence[VersionTarget]
) -> list[ClaimRead]:
    """Read every claim still to check, before anything is recorded (FR-016).

    The store is only read (its clock and earlier claim checks). Local files are read first; when
    the hub then cannot be read, ``ClaimReadFailedError`` carries the local reads and none from
    the hub, so a hub failure changes nothing a hub read would have and local files are still
    confirmed (quickstart §3, FR-007).
    """
    hub = HuggingFace(fetcher)
    local: list[ClaimRead] = []
    remote: list[tuple[VersionTarget, dict[str, Any], _Wanted]] = []
    for target in targets:
        checks = store.claim_checks(target.model_id, target.version)
        for entry, want in pending(target, checks):
            if entry.get("hub_repo"):
                remote.append((target, entry, want))
            else:
                local += read_local(target, entry, want, store.now())
    reads = list(local)
    try:
        for target, entry, want in remote:
            reads += read_hub(hub, target, entry, want, store.now())
    except SourceFailedError as error:
        raise ClaimReadFailedError(error, local) from None
    return reads


def _body(summary: Mapping[str, Any]) -> bytes:
    return json.dumps(summary, sort_keys=True, separators=(",", ":")).encode("utf-8")


def apply_claims(
    store: Store, run_id: int | None, reads: Sequence[ClaimRead]
) -> list[AppliedClaim]:
    """Record each read as a claim check with its evidence (``run_id`` null at import)."""
    applied = []
    for read in reads:
        evidence_id = store.add_evidence(
            source=SOURCE,
            url=read.url,
            retrieved_at=read.retrieved_at,
            matched_identifier=read.identifier,
            body=_body(read.summary),
            detail={
                "claim": read.claim,
                "outcome": read.outcome,
                "measured_format": read.measured_format,
                "measured_can_run_code": read.measured_can_run_code,
                "reason": read.reason,
            },
            run_id=run_id,
        )
        claim_check_id = store.add_claim_check(
            model_id=read.model_id,
            version=read.version,
            entry_identifier=read.identifier,
            claim=read.claim,
            run_id=run_id,
            outcome=read.outcome,
            measured_format=read.measured_format,
            measured_can_run_code=read.measured_can_run_code,
            reason=read.reason,
            evidence_id=evidence_id,
        )
        applied.append(AppliedClaim(read, claim_check_id, evidence_id))
    return applied

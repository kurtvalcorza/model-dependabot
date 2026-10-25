"""Static scan of pickle-based weight files with ``picklescan`` (research R4; FR-011, FR-022).

The scan goes through ``picklescan.scanner.scan_bytes`` (on a file handle for a file on disk, so
the file is never read whole into memory), which disassembles the pickle stream with
``pickletools`` and never executes it: nothing here unpickles a file. Each imported global comes
back as ``innocuous``, ``suspicious`` or ``dangerous``; the global names are the evidence.

A scan is complete only if the scanner read the stream to its end. ``picklescan`` 1.0.5 stops at
the first bytes that are not pickle instructions (for example the raw array data inside a joblib
file) and still returns the globals it saw before that point. Such a scan is reported as
incomplete with the byte position reached, never as clean (FR-022). For a plain stream the
position is the offset of the first byte the scanner could not read as an instruction; inside a
zip archive the scanner does not expose a position, so it is ``None``.
"""

from __future__ import annotations

import io
import os
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from posixpath import splitext
from typing import Any, BinaryIO

from picklescan import scanner

SCANNER = "picklescan"
SCANNER_VERSION = "1.0.5"
DANGEROUS = "dangerous"
SUSPICIOUS = "suspicious"
INNOCUOUS = "innocuous"


@dataclass(frozen=True)
class Finding:
    """One imported global and the scanner's label for it."""

    module: str
    name: str
    safety: str

    @property
    def global_name(self) -> str:
        return f"{self.module}.{self.name}"


@dataclass(frozen=True)
class ScanReport:
    """What the scanner found in one file and whether it read the file to the end."""

    file_name: str
    size: int
    findings: tuple[Finding, ...] = field(default_factory=tuple)
    complete: bool = True
    position: int | None = None
    error: str | None = None
    scanner: str = SCANNER
    scanner_version: str = SCANNER_VERSION

    def _names(self, safety: str) -> list[str]:
        return sorted({f.global_name for f in self.findings if f.safety == safety})

    @property
    def dangerous(self) -> list[str]:
        return self._names(DANGEROUS)

    @property
    def suspicious(self) -> list[str]:
        return self._names(SUSPICIOUS)

    @property
    def innocuous(self) -> list[str]:
        return self._names(INNOCUOUS)

    def as_record(self) -> dict[str, Any]:
        """The report as stored in evidence (its JSON is the evidence body)."""
        return {
            "scanner": self.scanner,
            "scanner_version": self.scanner_version,
            "file_name": self.file_name,
            "size": self.size,
            "complete": self.complete,
            "position": self.position,
            "error": self.error,
            "globals": [
                {"module": f.module, "name": f.name, "safety": f.safety}
                for f in sorted(self.findings, key=lambda f: (f.module, f.name))
            ],
        }


def scan(data: bytes, file_name: str) -> ScanReport:
    """Scan one file's bytes; ``file_name`` gives the extension the scanner dispatches on."""
    return _scan_stream(io.BytesIO(data), file_name, len(data))


def scan_path(path: Path, file_name: str | None = None) -> ScanReport:
    """Scan a file on disk through a file handle, so a large file is never read whole.

    Raises ``OSError`` if the file cannot be opened.
    """
    with path.open("rb") as handle:
        return scan_handle(handle, file_name or path.name)


def scan_handle(handle: BinaryIO, file_name: str) -> ScanReport:
    """Scan an open file from its start. The scanner seeks (a zip archive is read from its end),
    so it is given the handle, not a stream it must read in order."""
    handle.seek(0)
    size = os.fstat(handle.fileno()).st_size
    return _scan_stream(handle, file_name, size)


def _scan_stream(stream: BinaryIO, file_name: str, size: int) -> ScanReport:
    extension = splitext(file_name)[1].lower() or None
    try:
        result = scanner.scan_bytes(stream, file_name, extension)
    except Exception as error:  # the scanner gave up: incomplete, never clean (FR-022)
        return ScanReport(
            file_name, size, complete=False, position=None, error=f"scanner error: {error}"
        )
    findings = tuple(
        Finding(str(found.module), str(found.name), found.safety.value) for found in result.globals
    )
    # After reading a stream to its end the scanner sits one byte before it; after a stop it
    # sits one byte past the first byte it could not read. Record it before checking for a zip.
    reached = stream.tell()
    stream.seek(0)
    if zipfile.is_zipfile(stream):
        complete = not result.scan_err
        position = size if complete else None
    else:
        complete = not result.scan_err and reached >= size - 1
        position = size if complete else max(reached - 1, 0)
    error = None if complete else "scanner stopped before the end of the file"
    return ScanReport(file_name, size, findings, complete, position, error)

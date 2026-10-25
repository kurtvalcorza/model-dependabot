"""Crafted pickle fixtures, built as raw pickle opcode bytes and never loaded (T035).

Every fixture is a byte string written opcode by opcode, so no object is ever pickled or unpickled
to make it. The harmless fixtures are committed beside this script (run it to rebuild them):

    uv run python tests/fixtures/pickles/craft.py

The dangerous fixture (a pickle importing ``os.system``) and its PyTorch-zip-wrapped copy are never
committed: the tests build them into a temporary directory with ``dangerous()`` and
``pytorch_zip()``, because antivirus or repository scanning may quarantine or flag such a file. See
``NOTES.md``.
"""

from __future__ import annotations

import io
import sys
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent

PROTO_2 = b"\x80\x02"
STOP = b"."
POP = b"0"
EMPTY_TUPLE = b")"
REDUCE = b"R"
MARK = b"("
TUPLE = b"t"


def _global(module: str, name: str) -> bytes:
    """The ``GLOBAL`` opcode: ``c`` then the module and name, each ended by a newline."""
    return b"c" + module.encode("ascii") + b"\n" + name.encode("ascii") + b"\n"


def _string(text: str) -> bytes:
    """The protocol 0 ``STRING`` opcode."""
    return b"S'" + text.encode("ascii") + b"'\n"


def innocuous() -> bytes:
    """Imports only ``collections.OrderedDict`` and ``torch._utils._rebuild_tensor_v2``."""
    return (
        PROTO_2
        + _global("collections", "OrderedDict")
        + EMPTY_TUPLE
        + REDUCE
        + _global("torch._utils", "_rebuild_tensor_v2")
        + POP
        + STOP
    )


SUSPICIOUS_GLOBAL = ("model_dependabot_fixture.layers", "CustomLayer")


def suspicious() -> bytes:
    """Imports a global that is on neither of the scanner's lists."""
    return PROTO_2 + _global(*SUSPICIOUS_GLOBAL) + EMPTY_TUPLE + REDUCE + STOP


DANGEROUS_GLOBAL = ("os", "system")


def dangerous() -> bytes:
    """Imports ``os.system`` and calls it with a harmless command: built at test time only."""
    return (
        _global(*DANGEROUS_GLOBAL)
        + MARK
        + _string("echo model-dependabot fixture")
        + TUPLE
        + REDUCE
        + STOP
    )


def pytorch_zip(data_pkl: bytes, folder: str = "archive") -> bytes:
    """A PyTorch zip archive (``folder/data.pkl`` and ``folder/version``), stored, fixed dates."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, body in ((f"{folder}/data.pkl", data_pkl), (f"{folder}/version", b"3\n")):
            archive.writestr(zipfile.ZipInfo(name, date_time=(2026, 10, 24, 0, 0, 0)), body)
    return buffer.getvalue()


JOBLIB_HEADER = PROTO_2 + _global("joblib.numpy_pickle", "NumpyArrayWrapper") + EMPTY_TUPLE + REDUCE
# Four float32 values (0.0, 1.0, 2.0, 3.0) as joblib writes them: raw bytes inside the stream,
# which are not pickle instructions, so a disassembler stops here.
JOBLIB_ARRAY = b"\x00\x00\x00\x00\x00\x00\x80\x3f\x00\x00\x00\x40\x00\x00\x40\x40"


def joblib_style() -> bytes:
    """Pickle opcodes followed by raw array bytes, then the rest of the stream (T039b)."""
    return JOBLIB_HEADER + JOBLIB_ARRAY + POP + STOP


COMMITTED = {
    "innocuous.pkl": innocuous,
    "suspicious.pkl": suspicious,
    "joblib-style.joblib": joblib_style,
}


def main() -> int:
    for name, build in COMMITTED.items():
        (HERE / name).write_bytes(build())
        print(f"{name}: {len(build())} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())

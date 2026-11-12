"""The proposed manifest written by ``discover -o`` (research A10; FR-022, FR-023).

The existing manifest format, unchanged, written with a small TOML writer (the standard library
reads TOML but does not write it). Only what registration measures or pins itself is active:
``[model] id``, each measured local weight file and, when exactly one hash-locked requirements file
was found, ``[environment] lock``. Every other candidate is a comment showing its status, origin
and gaps, so registering the file as written registers none of them. Paths are written relative to
the output file, since the manifest reader resolves them from there. The text is written to a
temporary file beside the target, loaded back with ``load_manifest`` and only then renamed; an
existing target is refused unless ``force`` is given.
"""

from __future__ import annotations

import os
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from model_dependabot.discover.candidate import (
    DECLARED,
    VERIFIED,
    origin_text,
)
from model_dependabot.manifest import ManifestError, load_manifest

SEVERAL_LOCKS = "several lock files; choose one"
RULE = "# --- not registered as written: uncomment what you accept " + "-" * 38


class OutputExistsError(FileExistsError):
    """The output file exists and ``--force`` was not given."""


def toml_string(text: str) -> str:
    """``text`` as a TOML basic string, with every character TOML needs escaped."""
    escaped = []
    for char in text:
        if char == "\\":
            escaped.append("\\\\")
        elif char == '"':
            escaped.append('\\"')
        elif char == "\n":
            escaped.append("\\n")
        elif char == "\t":
            escaped.append("\\t")
        elif ord(char) < 0x20 or ord(char) == 0x7F:
            escaped.append(f"\\u{ord(char):04x}")
        else:
            escaped.append(char)
    return '"' + "".join(escaped) + '"'


def _comment(text: str) -> str:
    """A single comment line; line breaks in data never start an uncommented line."""
    flat = " ".join(str(text).split())
    return f"# {flat}" if flat else "#"


def _relative_to(output: Path, target: Path) -> str:
    try:
        return Path(os.path.relpath(target, output.parent)).as_posix()
    except ValueError:  # another drive on Windows
        return target.as_posix()


def _shown(item: Mapping[str, Any]) -> str | None:
    """What a commented package or licence is, as the file declared it."""
    identity = item["identity"]
    if item["kind"] == "package":
        return identity.get("requirement") or f"{identity.get('name')}=={identity.get('version')}"
    if item["kind"] == "licence":
        return identity.get("licence")
    return None


def _describe(item: Mapping[str, Any]) -> str:
    gaps = item.get("gaps") or []
    text = f"{item['kind']}: {item['status']}, from {origin_text(item['origin'])}"
    shown = _shown(item)
    if shown:
        text += f": {shown}"
    if gaps:
        text += f"; gaps: {', '.join(gaps)}"
    if item.get("manifest"):
        text += f"; manifest: {item['manifest']}"
    if item.get("note"):
        text += f"; {item['note']}"
    return text


def _weight_note(identity: Mapping[str, Any]) -> str:
    runs = "can run code" if identity.get("can_run_code") else "code-free"
    if identity.get("can_run_code") is None:
        runs = "unknown whether it can run code"
    return f"verified: sha256 {identity['sha256']}, bytes show {identity['format']} ({runs})"


def _block(item: Mapping[str, Any]) -> list[str]:
    """The commented-out lines of a candidate that is not registered as written."""
    identity = item["identity"]
    lines = [_comment(_describe(item))]
    kind = item["kind"]
    if kind == "base_model":
        lines += [
            "# [base_model]",
            _comment(f"hub = {toml_string('hf:' + str(identity['hub_repo']))}"),
            '# revision = "<commit>"',
        ]
    elif kind == "dataset" and identity.get("hub_repo"):
        lines += [
            "# [[datasets]]",
            _comment(f"hub = {toml_string('hf:datasets/' + str(identity['hub_repo']))}"),
            '# revision = "<commit>"',
        ]
    elif kind == "weight_file" and identity.get("path"):
        lines.append(_comment(f"[[weights]] path = {toml_string(str(identity['path']))}"))
    elif kind == "environment":
        lines.append(_comment(f"[environment] lock = {toml_string(str(identity['lock']))}"))
    return [*lines, "#"]


def render(result: Mapping[str, Any], model_id: str, root: Path, output: Path) -> str:
    """The proposed manifest's text for a discovery result."""
    candidates: Sequence[Mapping[str, Any]] = result["candidates"]
    weights = [
        item for item in candidates if item["kind"] == "weight_file" and item["status"] == VERIFIED
    ]
    locks = [
        item for item in candidates if item["kind"] == "environment" and item["status"] == DECLARED
    ]
    lock = locks[0] if len(locks) == 1 else None
    active = {id(item) for item in [*weights, *([lock] if lock else [])]}
    if lock is not None:
        # The lock's own packages are registered through it, so they are not commented again.
        locked = lock["identity"]["lock"]
        active |= {
            id(item)
            for item in candidates
            if item["kind"] == "package" and item["origin"].get("file") == locked
        }
    lines = [
        _comment(f"Proposed by model-dependabot discover on {result['observed_at']} from {root}."),
        "# These are dependencies proposed from the evidence available in the project.",
        "# Discovery cannot establish complete training provenance. Review every comment below.",
        "",
        "[model]",
        f"id = {toml_string(model_id)}",
    ]
    for item in weights:
        path = _relative_to(output, root / item["identity"]["path"])
        note = _comment(_weight_note(item["identity"]))
        lines += ["", "[[weights]]", f"path = {toml_string(path)}   {note}"]
        if item.get("note"):
            lines.append(_comment(item["note"]))
    if lock is not None:
        path = _relative_to(output, root / lock["identity"]["lock"])
        count = lock["identity"].get("packages")
        lines += [
            "",
            "[environment]",
            f"lock = {toml_string(path)}   {_comment(f'{count} packages, hash-locked')}",
        ]
    rest = [item for item in candidates if id(item) not in active]
    skipped = result.get("skipped") or []
    if rest or skipped or len(locks) > 1:
        lines += ["", RULE]
    if len(locks) > 1:
        lines.append(_comment(SEVERAL_LOCKS))
    for item in rest:
        lines += _block(item)
    for item in skipped:
        lines.append(_comment(f"skipped: {item['path']} ({item['reason']})"))
    return "\n".join(lines) + "\n"


def write(text: str, output: Path, *, force: bool) -> None:
    """Write ``text`` to ``output`` through a temporary file beside it, checked to load as a
    manifest first; ``OutputExistsError`` if ``output`` exists and ``force`` is false."""
    output = output.absolute()
    if output.exists() and not force:
        raise OutputExistsError(f"{output} exists; give --force to replace it")
    output.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(
        prefix=f".{output.name}.", suffix=".tmp", dir=output.parent
    )
    temp = Path(temporary)
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
        # The paths are relative to the output's folder, so the check loads it from there.
        load_manifest(temp)
        if output.exists() and not force:
            raise OutputExistsError(f"{output} exists; give --force to replace it")
        os.replace(temp, output)
    except (ManifestError, OSError):
        temp.unlink(missing_ok=True)
        raise

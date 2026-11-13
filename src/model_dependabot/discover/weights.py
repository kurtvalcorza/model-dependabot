"""Local weight files: hashed and classified from their bytes, never loaded (FR-017).

The SHA-256 and the class come from ``hash_file`` and ``classify``, the functions registration
uses, so a pickle named ``.safetensors`` is ``pickle`` here exactly as it is when registered. A
measured file is ``verified``. The same bytes under two names are both ``conflicting``. At most
2,000 weight files are hashed; the rest are listed under ``skipped``.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import PurePosixPath
from typing import Any

from model_dependabot.discover.candidate import CONFLICTING, UNAVAILABLE, VERIFIED, candidate
from model_dependabot.discover.walk import OUTSIDE, UNREADABLE, Limits, Walk, skip
from model_dependabot.inventory.build import (
    CODE_FREE_FORMATS,
    PICKLE_FORMATS,
    classify,
    hash_file,
)

WEIGHT_SUFFIXES = frozenset(CODE_FREE_FORMATS) | frozenset(PICKLE_FORMATS)
WEIGHT_LIMIT = "weight file limit reached"


def is_weight(path: str) -> bool:
    return PurePosixPath(path).suffix.lower() in WEIGHT_SUFFIXES


def _note(path: str, file_format: str) -> str | None:
    expected = CODE_FREE_FORMATS.get(PurePosixPath(path).suffix.lower())
    if expected is not None and file_format != expected:
        return f"named as {expected}; the bytes show {file_format}"
    return None


def _measure(found: Walk, path: str, observed_at: str) -> dict[str, Any]:
    origin = {"file": path}
    try:
        real = found.path(path)
        sha256, size = hash_file(real)
        file_format, can_run_code = classify(real.name, real)
    except PermissionError:
        identity = {"path": path}
        return candidate("weight_file", identity, origin, UNAVAILABLE, observed_at, [OUTSIDE])
    except OSError as error:
        reason = f"{UNREADABLE}: {error.strerror or error}"
        return candidate("weight_file", {"path": path}, origin, UNAVAILABLE, observed_at, [reason])
    identity = {
        "path": path,
        "sha256": sha256,
        "size": size,
        "format": file_format,
        "can_run_code": can_run_code,
    }
    found_candidate = candidate("weight_file", identity, origin, VERIFIED, observed_at)
    note = _note(path, file_format)
    if note is not None:
        found_candidate["note"] = note
    return found_candidate


def discover_weights(
    found: Walk, observed_at: str, limits: Limits
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    paths = [path for path in found.files if is_weight(path)]
    measured = [_measure(found, path, observed_at) for path in paths[: limits.weight_files]]
    skipped = [skip(path, WEIGHT_LIMIT) for path in paths[limits.weight_files :]]
    by_hash: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in measured:
        if item["identity"].get("sha256"):
            by_hash[item["identity"]["sha256"]].append(item)
    for same in by_hash.values():
        if len(same) < 2:
            continue
        for item in same:
            others = [other["identity"]["path"] for other in same if other is not item]
            item["status"] = CONFLICTING
            text = f"the same bytes as {', '.join(others)}"
            item["note"] = f"{item['note']}; {text}" if item.get("note") else text
    return measured, skipped

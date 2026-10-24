"""The registration manifest, read with ``tomllib`` (contracts/manifest.md, research R9).

Only the structure is checked here: ``model.id`` is required, unknown keys are an error so a typo
cannot silently drop a dependency, and paths are resolved relative to the manifest. Anything that
is present but inexact (a missing revision, an unpinned package) is not an error; the inventory
builder records it as a gap (FR-003).
"""

from __future__ import annotations

import hashlib
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from model_dependabot.sources.hf import parse_hub

_TOP_KEYS = {"model", "weights", "environment", "base_model", "datasets"}
_MODEL_KEYS = {"id", "name", "owner"}
_WEIGHT_KEYS = {"path", "hub", "revision", "file"}
_ENVIRONMENT_KEYS = {"lock"}
_BASE_MODEL_KEYS = {"hub", "revision"}
_DATASET_KEYS = {"doi", "sha256"}


class ManifestError(ValueError):
    """The manifest is not valid (exit code 1)."""


@dataclass(frozen=True)
class WeightSpec:
    """A local weight file (``path``, ``relative``) or a hub file (``hub_repo``, ``file``)."""

    path: Path | None = None
    relative: str | None = None
    hub_repo: str | None = None
    revision: str | None = None
    file: str | None = None


@dataclass(frozen=True)
class BaseModelSpec:
    repo: str
    revision: str | None


@dataclass(frozen=True)
class DatasetSpec:
    doi: str | None
    sha256: str | None


@dataclass(frozen=True)
class Manifest:
    path: Path
    sha256: str
    model_id: str
    name: str | None
    owner: str | None
    weights: tuple[WeightSpec, ...]
    lock: Path | None
    base_model: BaseModelSpec | None
    datasets: tuple[DatasetSpec, ...]


def _table(value: Any, where: str, allowed: set[str]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ManifestError(f"{where} must be a table")
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ManifestError(f"unknown key in {where}: {', '.join(unknown)}")
    return value


def _tables(value: Any, where: str, allowed: set[str]) -> list[Mapping[str, Any]]:
    if not isinstance(value, list):
        raise ManifestError(f"{where} must be an array of tables ([[{where}]])")
    return [_table(item, f"{where}[{index}]", allowed) for index, item in enumerate(value)]


def _text(table: Mapping[str, Any], key: str, where: str) -> str | None:
    value = table.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ManifestError(f"{where}.{key} must be a non-empty string")
    return value.strip()


def _hub(text: str, where: str) -> str:
    try:
        return parse_hub(text)
    except ValueError as error:
        raise ManifestError(f"{where}.hub: {error}") from None


def _local(base: Path, text: str, where: str) -> Path:
    path = (base / text).resolve()
    if not path.is_file():
        raise ManifestError(f"{where}: file not found: {text}")
    return path


def _weight(base: Path, table: Mapping[str, Any], where: str) -> WeightSpec:
    path = _text(table, "path", where)
    hub = _text(table, "hub", where)
    revision = _text(table, "revision", where)
    file = _text(table, "file", where)
    if (path is None) == (hub is None):
        raise ManifestError(f"{where} needs exactly one of 'path' and 'hub'")
    if path is not None:
        if revision is not None or file is not None:
            raise ManifestError(f"{where}: 'revision' and 'file' are for hub files only")
        return WeightSpec(path=_local(base, path, where), relative=Path(path).as_posix())
    if file is None:
        raise ManifestError(f"{where}: a hub weight file needs 'file'")
    return WeightSpec(hub_repo=_hub(hub or "", where), revision=revision, file=file)


def load_manifest(path: Path | str) -> Manifest:
    """Read and check a manifest; raise ``ManifestError`` if it is not valid."""
    path = Path(path).resolve()
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise ManifestError(f"cannot read {path}: {error}") from None
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise ManifestError(f"{path.name} is not valid TOML: {error}") from None
    _table(data, "the manifest", _TOP_KEYS)
    base = path.parent

    model = _table(data.get("model", {}), "model", _MODEL_KEYS)
    model_id = _text(model, "id", "model")
    if model_id is None:
        raise ManifestError("model.id is required")

    weights = tuple(
        _weight(base, table, f"weights[{index}]")
        for index, table in enumerate(_tables(data.get("weights", []), "weights", _WEIGHT_KEYS))
    )

    lock = None
    if "environment" in data:
        environment = _table(data["environment"], "environment", _ENVIRONMENT_KEYS)
        lock_text = _text(environment, "lock", "environment")
        lock = None if lock_text is None else _local(base, lock_text, "environment.lock")

    base_model = None
    if "base_model" in data:
        table = _table(data["base_model"], "base_model", _BASE_MODEL_KEYS)
        hub = _text(table, "hub", "base_model")
        if hub is None:
            raise ManifestError("base_model.hub is required when [base_model] is given")
        base_model = BaseModelSpec(
            repo=_hub(hub, "base_model"), revision=_text(table, "revision", "base_model")
        )

    datasets = tuple(
        DatasetSpec(
            doi=_text(table, "doi", f"datasets[{index}]"),
            sha256=_text(table, "sha256", f"datasets[{index}]"),
        )
        for index, table in enumerate(_tables(data.get("datasets", []), "datasets", _DATASET_KEYS))
    )

    return Manifest(
        path=path,
        sha256=hashlib.sha256(raw).hexdigest(),
        model_id=model_id,
        name=_text(model, "name", "model"),
        owner=_text(model, "owner", "model"),
        weights=weights,
        lock=lock,
        base_model=base_model,
        datasets=datasets,
    )

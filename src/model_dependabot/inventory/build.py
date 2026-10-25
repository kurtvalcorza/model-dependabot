"""Manifest to inventory entries: hashing, format classes and gaps (FR-001 to FR-003).

Every entry is a plain dict with exactly the store's ``ENTRY_FIELDS``. An entry is pinned only
when its identifier is exact; otherwise it is a gap with a reason and is never matched against
advisories or scanned. Weight files are hashed here with SHA-256 (local files) or pinned from the
hub's tree (hub files); the format class follows research R4.
"""

from __future__ import annotations

import hashlib
import io
import zipfile
from collections.abc import Callable, Mapping
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO
from urllib.parse import quote

from model_dependabot.doi import normalise_doi
from model_dependabot.lockfile import read_lock
from model_dependabot.manifest import BaseModelSpec, DatasetSpec, Manifest, WeightSpec
from model_dependabot.sources import datacite, figshare, zenodo
from model_dependabot.sources.fetcher import Fetcher, NoRecordingError, SourceFailedError
from model_dependabot.sources.hf import (
    HuggingFace,
    is_commit,
    read_dataset,
    read_model,
    resolve_url,
)
from model_dependabot.store import ENTRY_FIELDS, ENTRY_KINDS
from model_dependabot.upstream.licences import normalise

ENTRY_KIND_ORDER = ("weight_file", "package", "base_model", "dataset")

NO_REVISION = "no revision"
NOT_A_COMMIT = "revision is not a commit"
REVISION_MISMATCH = "hub revision does not match the manifest"
NO_DOI = "no DOI"
NOT_A_DOI = "not a DOI"

PICKLE_FORMATS = {".pt": "pickle", ".pth": "pickle", ".bin": "pickle", ".ckpt": "pickle"}
PICKLE_FORMATS |= {".pkl": "pickle", ".joblib": "joblib"}
CODE_FREE_FORMATS = {".safetensors": "safetensors", ".onnx": "onnx", ".gguf": "gguf"}
UNKNOWN_FORMAT = "unknown"

_ZIP_MAGIC = b"PK\x03\x04"
_HEAD_BYTES = 4
_CHUNK = 1 << 20
HUB_DATASET_PREFIX = "hf-dataset:"

__all__ = ["normalise_doi"]


def new_entry(kind: str, **fields: Any) -> dict[str, Any]:
    """An entry with every field present; unset fields are ``None`` and ``pinned`` is False."""
    unknown = set(fields) - set(ENTRY_FIELDS)
    if unknown:
        raise ValueError(f"unknown entry fields: {sorted(unknown)}")
    entry: dict[str, Any] = dict.fromkeys(ENTRY_FIELDS)
    entry.update(fields, kind=kind)
    entry["pinned"] = bool(entry["pinned"])
    return entry


def gap(kind: str, reason: str, **fields: Any) -> dict[str, Any]:
    return new_entry(kind, pinned=False, gap_reason=reason, **fields)


def check_entry(entry: dict[str, Any]) -> None:
    """Raise ``ValueError`` if an entry breaks the data-model rules."""
    if entry.get("kind") not in ENTRY_KINDS:
        raise ValueError(f"entry kind must be one of {ENTRY_KINDS}, got {entry.get('kind')!r}")
    if entry.get("pinned"):
        if not entry.get("identifier"):
            raise ValueError("a pinned entry needs an identifier")
    elif not entry.get("gap_reason"):
        raise ValueError("an entry that is not pinned needs a gap_reason")


def _starts_like_zip(content: bytes | Path) -> bool:
    if isinstance(content, Path):
        with content.open("rb") as handle:
            return handle.read(_HEAD_BYTES) == _ZIP_MAGIC
    return content.startswith(_ZIP_MAGIC)


def _is_pytorch_zip(content: bytes | Path) -> bool:
    # A path is opened by zipfile itself, which reads only the central directory, never the
    # whole file.
    source = content if isinstance(content, Path) else io.BytesIO(content)
    try:
        with zipfile.ZipFile(source) as archive:
            names = archive.namelist()
    except zipfile.BadZipFile:
        return False
    return any(PurePosixPath(name).name == "data.pkl" for name in names)


def classify(name: str, head: bytes | Path | None) -> tuple[str, bool | None]:
    """A file's format and whether loading it can run code (research R4, FR-002).

    ``head`` is the local file's path, or its content when it is at hand (for a zip the content
    must be the whole file), and ``None`` for a hub file, which is then classified by its
    extension alone.
    """
    suffix = PurePosixPath(name).suffix.lower()
    if suffix in CODE_FREE_FORMATS:
        return CODE_FREE_FORMATS[suffix], False
    if head is not None and _starts_like_zip(head) and _is_pytorch_zip(head):
        return "pytorch-zip", True
    if suffix in PICKLE_FORMATS:
        return PICKLE_FORMATS[suffix], True
    return UNKNOWN_FORMAT, None


def hash_file(path: Path) -> tuple[str, int]:
    """A file's SHA-256 and size, read in chunks so a large file is never held in memory."""
    with path.open("rb") as handle:
        return hash_stream(handle)


def hash_stream(handle: BinaryIO) -> tuple[str, int]:
    """The SHA-256 and size of what ``handle`` reads from where it is to its end, in chunks."""
    digest = hashlib.sha256()
    size = 0
    while chunk := handle.read(_CHUNK):
        digest.update(chunk)
        size += len(chunk)
    return digest.hexdigest(), size


def _local_weight(spec: WeightSpec) -> dict[str, Any]:
    assert spec.path is not None
    sha256, size = hash_file(spec.path)
    file_format, can_run_code = classify(spec.path.name, spec.path)
    return new_entry(
        "weight_file",
        identifier=f"sha256:{sha256}",
        pinned=True,
        location=spec.relative,
        size=size,
        format=file_format,
        can_run_code=can_run_code,
    )


def _hub_weight(spec: WeightSpec, hub: HuggingFace | None) -> dict[str, Any]:
    assert spec.hub_repo is not None and spec.file is not None
    file_format, can_run_code = classify(spec.file, None)
    fields: dict[str, Any] = {
        "format": file_format,
        "can_run_code": can_run_code,
        "hub_repo": spec.hub_repo,
        "hub_file": spec.file,
    }
    if spec.revision is None:
        return gap("weight_file", NO_REVISION, **fields)
    fields["location"] = resolve_url(spec.hub_repo, spec.revision, spec.file)
    if not is_commit(spec.revision):
        return gap("weight_file", NOT_A_COMMIT, **fields)
    if hub is None:
        return gap("weight_file", "hub not consulted", **fields)
    found = hub.hub_file(spec.hub_repo, spec.revision, spec.file)
    if found.file is not None:
        fields["size"] = found.file.size
    if found.gap_reason is not None:
        return gap("weight_file", found.gap_reason, **fields)
    if found.commit != spec.revision:
        return gap("weight_file", REVISION_MISMATCH, **fields)
    assert found.file is not None and found.file.sha256 is not None
    return new_entry(
        "weight_file",
        identifier=f"sha256:{found.file.sha256}",
        pinned=True,
        hub_revision=found.commit,
        **fields,
    )


def _packages(lock: Path) -> list[dict[str, Any]]:
    entries = []
    for item in read_lock(lock):
        entries.append(
            new_entry(
                "package",
                identifier=item.purl,
                pinned=item.pinned,
                gap_reason=item.gap_reason,
                name=item.name,
                version=item.version,
                hashes=list(item.hashes) or None,
            )
        )
    return entries


def huggingface_purl(repo: str, commit: str | None) -> str:
    """The base model's purl at ``commit``; without one, the repository's versionless purl."""
    owner, name = repo.split("/", 1)
    purl = f"pkg:huggingface/{quote(owner, safe='')}/{quote(name, safe='')}"
    return purl if commit is None else f"{purl}@{commit}"


def _base_model(spec: BaseModelSpec) -> dict[str, Any]:
    if spec.revision is None:
        return gap("base_model", NO_REVISION, name=spec.repo)
    if not is_commit(spec.revision):
        return gap("base_model", NOT_A_COMMIT, name=spec.repo)
    return new_entry(
        "base_model",
        identifier=huggingface_purl(spec.repo, spec.revision),
        pinned=True,
        name=spec.repo,
        version=spec.revision,
    )


def hub_dataset_identifier(repo: str, commit: str) -> str:
    """``hf-dataset:owner/name@commit`` (data-model.md, Inventory entry)."""
    return f"{HUB_DATASET_PREFIX}{repo}@{commit}"


def _dataset(spec: DatasetSpec) -> dict[str, Any]:
    hashes = None if spec.sha256 is None else [f"sha256:{spec.sha256.lower()}"]
    papers = list(spec.paper_dois) or None
    if spec.hub is not None:
        fields: dict[str, Any] = {"hashes": hashes, "paper_dois": papers, "hub_repo": spec.hub}
        if spec.revision is None:
            return gap("dataset", NO_REVISION, **fields)
        if not is_commit(spec.revision):
            return gap("dataset", NOT_A_COMMIT, **fields)
        return new_entry(
            "dataset",
            identifier=hub_dataset_identifier(spec.hub, spec.revision),
            pinned=True,
            hub_revision=spec.revision,
            **fields,
        )
    if spec.doi is None:
        return gap("dataset", NO_DOI, hashes=hashes, paper_dois=papers)
    doi = normalise_doi(spec.doi)
    if doi is None:
        return gap("dataset", NOT_A_DOI, hashes=hashes, paper_dois=papers)
    return new_entry("dataset", identifier=doi, pinned=True, hashes=hashes, paper_dois=papers)


def build_entries(manifest: Manifest, fetcher: Fetcher | None = None) -> list[dict[str, Any]]:
    """The inventory entries of a manifest, in kind order; gaps included, never raised."""
    hub = None if fetcher is None else HuggingFace(fetcher)
    entries: list[dict[str, Any]] = []
    for spec in manifest.weights:
        entries.append(_local_weight(spec) if spec.path is not None else _hub_weight(spec, hub))
    if manifest.lock is not None:
        entries += _packages(manifest.lock)
    if manifest.base_model is not None:
        entries.append(_base_model(manifest.base_model))
    entries += [_dataset(spec) for spec in manifest.datasets]
    for entry in entries:
        check_entry(entry)
    return entries


Routing = Callable[[str], Mapping[str, Any] | None]


def _declared(entry: Mapping[str, Any], fetcher: Fetcher, routing: Routing) -> str | None:
    """The licence a source declares for a base model or dataset (FR-008, US1 adapters)."""
    if entry["kind"] == "base_model":
        model = read_model(fetcher, entry["name"])
        return model.licence if model.outcome == "reachable" else None
    if entry.get("hub_repo"):
        dataset = read_dataset(fetcher, entry["hub_repo"])
        return dataset.licence if dataset.outcome == "reachable" else None
    doi = entry["identifier"]
    route = routing(doi) or {}
    if not datacite.queried(route.get("agency")):
        return None
    record = datacite.DataCite(fetcher).record(doi)
    if record.licence:
        return record.licence
    repository, record_id = route.get("repository"), route.get("repository_id")
    if record.outcome == "reachable" and record.repository is not None:
        repository, record_id = record.repository, record.repository_id
    if repository == "zenodo" and record_id:
        found = zenodo.Zenodo(fetcher).record(str(record_id))
        return found.licence if found.outcome == "reachable" else None
    if repository == "figshare" and record_id:
        article = figshare.Figshare(fetcher).article(str(record_id))
        return article.licence if article.outcome == "reachable" else None
    return None


def record_licences(entries: list[dict[str, Any]], fetcher: Fetcher, routing: Routing) -> None:
    """Write the declared licence, normalised, into each base-model and dataset entry (FR-008).

    The order for a DOI is DataCite's ``rightsList``, then the Zenodo or Figshare record it routes
    to. A source that fails, or declares none, leaves the licence empty: the first successful
    observation at a check then becomes the baseline (research U8).
    """
    for entry in entries:
        if entry["kind"] not in ("base_model", "dataset") or not entry["pinned"]:
            continue
        try:
            declared = _declared(entry, fetcher, routing)
        except (SourceFailedError, NoRecordingError):
            declared = None
        licence = normalise(declared)
        if licence.form == "none":
            continue
        entry["recorded_licence"] = licence.normalised
        entry["licence_form"] = licence.form

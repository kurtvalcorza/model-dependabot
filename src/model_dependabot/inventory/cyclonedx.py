"""Inventory entries to and from CycloneDX 1.7 JSON (contracts/inventory-profile.md, research R1).

Exports are written as plain data and validated against the vendored official schema. The
``referencing`` registry holds only the vendored files; any other ``$ref`` fails loudly instead of
being fetched (``cryptography-defs.schema.json`` is not vendored and exports never reach it).
Imports accept CycloneDX 1.5, 1.6 and 1.7 and read them with the same mapping; anything the mapping
cannot read becomes a gap rather than an error.

A dataset is written as a ``data`` component (``bom-ref: "doi:<doi>"``, the DOI as a distribution
reference, the optional SHA-256 in ``hashes``) that the model card's ``modelParameters.datasets[]``
references by ``bom-ref``: the schema's inline dataset form allows neither ``hashes`` nor
``externalReferences``.

Feature 002 (contracts/inventory-profile.md, research U11) uses standard fields only: recorded
licences in ``licenses`` (``license.id``, ``license.name`` or ``expression``), tied papers as
``citation`` references and hub datasets as ``data`` components with
``bom-ref: "hf-dataset:<owner>/<name>@<commit>"`` and a ``distribution`` reference to the hub page.

Issue #34: a package's lock marker is the property ``model-dependabot:marker``, written only when
the marker is recorded: the marker as stored, or ``none`` for a lock line without one. On import the
value is untrusted: ``none`` reads as no marker (``""``), a value ``packaging`` reads as a marker is
kept normalised, and anything else, the property absent included, is not recorded (``None``).
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from functools import cache
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote

from jsonschema import Draft7Validator
from packaging.markers import InvalidMarker, Marker
from packaging.utils import canonicalize_name
from referencing import Registry, Resource
from referencing.exceptions import NoSuchResource
from referencing.jsonschema import DRAFT7

from model_dependabot import __version__
from model_dependabot.inventory.build import (
    ENTRY_KIND_ORDER,
    HUB_DATASET_PREFIX,
    NO_DOI,
    NO_REVISION,
    NOT_A_COMMIT,
    class_fits_name,
    classify,
    gap,
    hub_dataset_identifier,
    huggingface_purl,
    merge_datasets,
    new_entry,
    normalise_doi,
)
from model_dependabot.lineage import RELATIONSHIPS, UNSPECIFIED
from model_dependabot.lineage.edges import NO_VERSION, fold, new_edge
from model_dependabot.lockfile import NO_EXACT_VERSION, NO_HASH
from model_dependabot.sources.hf import is_commit
from model_dependabot.upstream.licences import join_licences, recorded

SPEC_VERSION = "1.7"
IMPORTABLE_VERSIONS = ("1.5", "1.6", "1.7")
PREFIX = "model-dependabot:"
P_FORMAT = PREFIX + "format"
P_CAN_RUN_CODE = PREFIX + "can-run-code"
P_SIZE = PREFIX + "size"
P_HUB_REPO = PREFIX + "hub-repo"
P_HUB_REVISION = PREFIX + "hub-revision"
P_HUB_FILE = PREFIX + "hub-file"
P_GAP = PREFIX + "gap"
# Feature 003 (contracts/inventory-profile.md): where the format claim came from. Written on
# export; ignored on import, where every claim is a third party's.
P_FORMAT_ORIGIN = PREFIX + "format-origin"
# Feature 011 (contracts/cyclonedx-lineage.md): an ancestor's lineage edge. CycloneDX 1.7 has no
# field for a relationship type, an edge's origin or a reference to a model in the same store.
P_RELATIONSHIP = PREFIX + "relationship"
P_RELATIONSHIP_RECORDED = PREFIX + "relationship-recorded"
P_EDGE_ORIGIN = PREFIX + "edge-origin"
P_CLAIMED_ORIGIN = PREFIX + "claimed-origin"
P_PARENT_MODEL = PREFIX + "parent-model"
P_PARENT_VERSION = PREFIX + "parent-version"
# Issue #34 (contracts/inventory-profile.md): a package's lock marker. CycloneDX has no field for
# it. ``none`` spells "recorded, the lock line has none": no marker parses as ``none``.
P_MARKER = PREFIX + "marker"
NO_MARKER = "none"
# Research P2: at most this many ancestors are read; the rest is one recorded gap.
MAX_ANCESTORS = 256
_LIMIT_GAP = re.compile(r"^more than \d+ ancestors; \d+ not read$")
UNIDENTIFIED_ANCESTOR = "unidentified base model"
PROPERTIES = frozenset(
    {
        P_FORMAT,
        P_CAN_RUN_CODE,
        P_SIZE,
        P_HUB_REPO,
        P_HUB_REVISION,
        P_HUB_FILE,
        P_GAP,
        P_FORMAT_ORIGIN,
        P_RELATIONSHIP,
        P_RELATIONSHIP_RECORDED,
        P_EDGE_ORIGIN,
        P_CLAIMED_ORIGIN,
        P_PARENT_MODEL,
        P_PARENT_VERSION,
        P_MARKER,
    }
)

SCHEMA_DIR = Path(__file__).resolve().parent / "schema"
VENDORED_SCHEMAS = ("bom-1.7.schema.json", "spdx.schema.json", "jsf-0.82.schema.json")
BOM_SCHEMA_ID = "http://cyclonedx.org/schema/bom-1.7.schema.json"

_ALGORITHMS = {"sha256": "SHA-256", "sha384": "SHA-384", "sha512": "SHA-512"}
_ALGORITHM_NAMES = {value: key for key, value in _ALGORITHMS.items()}
DOI_URL = "https://doi.org/"
HUB_DATASET_URL = "https://huggingface.co/datasets/"
UNIDENTIFIED_DATASET = "unidentified dataset"


class InventoryError(ValueError):
    """The document is not a CycloneDX inventory this tool can read (exit code 1)."""


# --- validation ---------------------------------------------------------------------------------


def _vendored_sums() -> dict[str, str]:
    sums = {}
    for line in (SCHEMA_DIR / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        if line.strip():
            digest, name = line.split()
            sums[name] = digest
    return sums


def _refuse(uri: str) -> Resource[Any]:
    raise NoSuchResource(ref=uri)


@cache
def _validator() -> Draft7Validator:
    sums = _vendored_sums()
    resources = []
    schemas: dict[str, Any] = {}
    for name in VENDORED_SCHEMAS:
        raw = (SCHEMA_DIR / name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != sums.get(name):
            raise RuntimeError(f"vendored schema {name} does not match SHA256SUMS")
        contents = json.loads(raw)
        schemas[contents["$id"]] = contents
        resources.append(
            (contents["$id"], Resource.from_contents(contents, default_specification=DRAFT7))
        )
    registry: Registry[Any] = Registry(retrieve=_refuse).with_resources(resources)  # type: ignore[call-arg]
    return Draft7Validator(schemas[BOM_SCHEMA_ID], registry=registry)


def validate(document: Any) -> None:
    """Raise ``jsonschema.ValidationError`` unless the document is valid CycloneDX 1.7.

    A ``$ref`` outside the vendored schemas raises ``referencing.exceptions.Unresolvable``.
    """
    _validator().validate(document)


# --- export -------------------------------------------------------------------------------------


def _properties(pairs: list[tuple[str, Any]]) -> list[dict[str, str]]:
    return [{"name": name, "value": str(value)} for name, value in pairs if value is not None]


def _hashes(values: list[str] | None) -> list[dict[str, str]]:
    result = []
    for value in values or []:
        alg, _, content = value.partition(":")
        if alg in _ALGORITHMS:
            result.append({"alg": _ALGORITHMS[alg], "content": content})
    return result


def _with(item: dict[str, Any], **optional: Any) -> dict[str, Any]:
    item.update({key: value for key, value in optional.items() if value})
    return item


def _licenses(entry: dict[str, Any]) -> list[dict[str, Any]] | None:
    """The recorded licence set in CycloneDX form, one choice per entry (inventory-profile.md)."""
    licences = recorded(entry.get("recorded_licence"), entry.get("licence_form"))
    if licences is None or not licences.entries:
        return None
    choices: list[dict[str, Any]] = []
    for licence in sorted(licences.entries, key=lambda item: str(item.normalised)):
        if licence.form == "spdx":
            choices.append({"license": {"id": licence.normalised}})
        elif licence.form == "expression":
            choices.append({"expression": licence.normalised})
        else:
            choices.append({"license": {"name": licence.declared}})
    return choices


def _citations(entry: dict[str, Any]) -> list[dict[str, str]]:
    return [
        {"type": "citation", "url": DOI_URL + quote(doi, safe="/")}
        for doi in entry.get("paper_dois") or []
    ]


def _weight_component(index: int, entry: dict[str, Any]) -> dict[str, Any]:
    can_run_code = entry["can_run_code"]
    hub = entry["hub_repo"] is not None
    identifier = entry["identifier"]
    component = {
        "type": "file",
        "bom-ref": f"file:{index}",
        "name": entry["hub_file"] if hub else entry["location"],
    }
    references = None
    if hub and entry["location"]:
        references = [{"type": "distribution", "url": entry["location"]}]
    return _with(
        component,
        hashes=_hashes([identifier] if identifier else None),
        externalReferences=references,
        properties=_properties(
            [
                (P_FORMAT, entry["format"]),
                (P_CAN_RUN_CODE, None if can_run_code is None else str(can_run_code).lower()),
                (P_SIZE, entry["size"]),
                (P_HUB_REPO, entry["hub_repo"]),
                (P_HUB_REVISION, entry["hub_revision"]),
                (P_HUB_FILE, entry["hub_file"]),
                (P_GAP, entry["gap_reason"]),
                (P_FORMAT_ORIGIN, entry.get("format_origin")),
            ]
        ),
    )


def _package_component(index: int, entry: dict[str, Any]) -> dict[str, Any]:
    component = {"type": "library", "bom-ref": f"package:{index}", "name": entry["name"]}
    return _with(
        component,
        version=entry["version"],
        purl=entry["identifier"],
        hashes=_hashes(entry["hashes"]),
        properties=_properties([(P_GAP, entry["gap_reason"]), (P_MARKER, _marker_value(entry))]),
    )


def _marker_value(entry: dict[str, Any]) -> str | None:
    """The ``marker`` property's value: ``none`` for ``""``, or the stored marker normalised when
    ``packaging`` reads it. A marker that is not recorded, or one stored as written because it does
    not parse (the literal ``none`` included), writes no property, so a re-import reads it as not
    recorded rather than as something else (review R34-2)."""
    stored = entry.get("marker")
    if stored is None:
        return None
    if stored == "":
        return NO_MARKER
    try:
        return str(Marker(stored))
    except (InvalidMarker, RecursionError):
        return None


def _base_model_component(index: int, entry: dict[str, Any]) -> dict[str, Any]:
    component = {
        "type": "machine-learning-model",
        "bom-ref": f"base-model:{index}",
        "name": entry["name"],
    }
    return _with(
        component,
        version=entry["version"],
        purl=entry["identifier"],
        licenses=_licenses(entry),
        properties=_properties([(P_GAP, entry["gap_reason"])]),
    )


def _dataset_component(index: int, entry: dict[str, Any]) -> dict[str, Any]:
    identifier = entry["identifier"]
    hub = entry.get("hub_repo")
    if hub is not None:
        name = hub
        ref = identifier or f"dataset:{index}"
        references = [{"type": "distribution", "url": HUB_DATASET_URL + quote(hub, safe="/")}]
        pairs = [(P_HUB_REPO, None if identifier else hub), (P_GAP, entry["gap_reason"])]
    else:
        name = identifier or UNIDENTIFIED_DATASET
        ref = f"doi:{identifier}" if identifier else f"dataset:{index}"
        references = (
            [{"type": "distribution", "url": DOI_URL + quote(identifier, safe="/")}]
            if identifier
            else []
        )
        pairs = [(P_GAP, entry["gap_reason"])]
    component = {
        "type": "data",
        "bom-ref": ref,
        "name": name,
        "data": [{"type": "dataset", "name": name}],
    }
    return _with(
        component,
        version=entry.get("hub_revision"),
        externalReferences=references + _citations(entry),
        hashes=_hashes(entry["hashes"]),
        licenses=_licenses(entry),
        properties=_properties(pairs),
    )


def _edge_properties(edge: Mapping[str, Any]) -> list[tuple[str, Any]]:
    return [
        (P_RELATIONSHIP, edge["relationship"]),
        (P_RELATIONSHIP_RECORDED, edge.get("relationship_recorded")),
        (P_EDGE_ORIGIN, edge.get("origin")),
        (P_CLAIMED_ORIGIN, edge.get("claimed_origin")),
    ]


def _edge_component(
    index: int, edge: Mapping[str, Any], entry: dict[str, Any] | None
) -> dict[str, Any]:
    """One ancestor for one lineage edge (contracts/cyclonedx-lineage.md, Ancestor forms).

    A pinned hub edge is its base model entry's component plus the edge's properties. A
    registered-model edge has no purl (FR-010a). A gap edge carries ``model-dependabot:gap`` and,
    when it names a repository, ``hub-repo`` and ``hub-revision``, so a re-import reads it back.
    """
    ref = f"base-model:{index}"
    if edge.get("parent_kind") == "model":
        component = {"type": "machine-learning-model", "bom-ref": ref}
        component["name"] = str(edge["parent_model_id"])
        pairs = [
            (P_PARENT_MODEL, edge["parent_model_id"]),
            (P_PARENT_VERSION, edge.get("parent_version")),
            (P_GAP, edge.get("gap_reason")),
        ]
        return _with(component, properties=_properties(pairs + _edge_properties(edge)))
    if entry is not None:
        component = _base_model_component(index, entry)
        properties = component.get("properties", []) + _properties(_edge_properties(edge))
        component["properties"] = properties
        return component
    repo = edge.get("parent_repo")
    component = {"type": "machine-learning-model", "bom-ref": ref}
    component["name"] = str(repo or UNIDENTIFIED_ANCESTOR)
    pairs = [
        (P_HUB_REPO, repo),
        (P_HUB_REVISION, edge.get("parent_revision") if repo else None),
        (P_GAP, edge.get("gap_reason")),
    ]
    return _with(component, properties=_properties(pairs + _edge_properties(edge)))


def export_bom(
    model_id: str,
    version: int,
    entries: list[dict[str, Any]],
    edges: Sequence[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """The CycloneDX 1.7 document for one model version.

    With ``edges`` (feature 011), ancestors are written one per edge, not one per base model entry:
    the k-th edge's ``bom-ref`` is ``base-model:<n + k>``, n the number of weight-file and package
    entries, so a legacy version's one ancestor keeps the ref it had (research L4).
    """
    components: list[dict[str, Any]] = []
    ancestors: list[dict[str, Any]] = []
    datasets: list[dict[str, str]] = []
    for index, entry in enumerate(entries):
        kind = entry["kind"]
        if kind == "weight_file":
            components.append(_weight_component(index, entry))
        elif kind == "package":
            components.append(_package_component(index, entry))
        elif kind == "base_model":
            if edges is None:
                ancestors.append(_base_model_component(index, entry))
        elif kind == "dataset":
            data = _dataset_component(index, entry)
            components.append(data)
            datasets.append({"ref": data["bom-ref"]})
        else:
            raise ValueError(f"unknown entry kind {kind!r}")
    if edges is not None:
        first = sum(entry["kind"] in ("weight_file", "package") for entry in entries)
        pinned = {
            entry["identifier"]: entry
            for entry in reversed(entries)
            if entry["kind"] == "base_model" and entry["identifier"]
        }
        for k, edge in enumerate(edges):
            entry = pinned.get(edge.get("entry_identifier")) if not edge.get("gap_reason") else None
            ancestors.append(_edge_component(first + k, edge, entry))
    model: dict[str, Any] = {
        "type": "machine-learning-model",
        "bom-ref": f"model:{model_id}@{version}",
        "name": model_id,
        "version": str(version),
    }
    if ancestors:
        model["pedigree"] = {"ancestors": ancestors}
    if datasets:
        model["modelCard"] = {"modelParameters": {"datasets": datasets}}
    tool = {"type": "application", "name": "model-dependabot", "version": __version__}
    return {
        "$schema": BOM_SCHEMA_ID,
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "version": 1,
        "metadata": {"tools": {"components": [tool]}, "component": model},
        "components": components,
    }


# --- import -------------------------------------------------------------------------------------


def _props(item: dict[str, Any]) -> dict[str, str]:
    result = {}
    for prop in item.get("properties") or []:
        if isinstance(prop, dict) and isinstance(prop.get("name"), str):
            result[prop["name"]] = str(prop.get("value", ""))
    return result


def _read_hashes(item: dict[str, Any]) -> list[str]:
    result = []
    for value in item.get("hashes") or []:
        if not isinstance(value, dict):
            continue
        alg = _ALGORITHM_NAMES.get(str(value.get("alg")))
        content = str(value.get("content", "")).lower()
        if alg and content:
            result.append(f"{alg}:{content}")
    return result


def _references(item: dict[str, Any], kind: str) -> list[str]:
    return [
        str(ref["url"])
        for ref in item.get("externalReferences") or []
        if isinstance(ref, dict) and ref.get("type") == kind and ref.get("url")
    ]


def _read_licence(item: dict[str, Any]) -> tuple[str | None, str | None]:
    """``(recorded_licence, licence_form)`` from every ``licenses`` choice of a component.

    Several choices are the recorded set, one entry per line; the form is ``unrecognised`` if any
    choice is a ``license.name``, ``expression`` if any is an expression, else ``spdx``.
    """
    entries: list[tuple[str, str]] = []
    for choice in item.get("licenses") or []:
        if not isinstance(choice, dict):
            continue
        if isinstance(choice.get("expression"), str):
            entries.append((choice["expression"], "expression"))
            continue
        licence = choice.get("license")
        if isinstance(licence, dict):
            if isinstance(licence.get("id"), str):
                entries.append((licence["id"], "spdx"))
            elif isinstance(licence.get("name"), str):
                entries.append((licence["name"], "unrecognised"))
    if not entries:
        return None, None
    forms = {form for _, form in entries}
    form = next(f for f in ("unrecognised", "expression", "spdx") if f in forms)
    return join_licences([text for text, _ in entries]), form


def _read_papers(item: dict[str, Any]) -> list[str] | None:
    dois = [normalise_doi(unquote(url)) for url in _references(item, "citation")]
    return [doi for doi in dois if doi is not None] or None


def _int(text: str | None) -> int | None:
    try:
        return None if text is None else int(text)
    except ValueError:
        return None


def _bool(text: str | None) -> bool | None:
    return {"true": True, "false": False}.get((text or "").lower())


def _import_weight(item: dict[str, Any]) -> dict[str, Any]:
    props = _props(item)
    name = str(item.get("name") or "")
    hub = P_HUB_REPO in props
    sha256 = [value for value in _read_hashes(item) if value.startswith("sha256:")]
    distribution = _references(item, "distribution")
    if P_FORMAT in props:
        file_format, can_run_code = props[P_FORMAT], _bool(props.get(P_CAN_RUN_CODE))
        if not class_fits_name(name, file_format, can_run_code):
            # The document's own class is not trusted blindly (review F8): a code-capable file
            # described as code-free would never be scanned.
            raise InventoryError(
                f"{name}: format {file_format!r} with can-run-code"
                f" {props.get(P_CAN_RUN_CODE)!r} does not fit the file name"
            )
    else:
        file_format, can_run_code = classify(name, None)
    identifier = sha256[0] if sha256 else None
    reason = props.get(P_GAP) or (None if identifier else "no SHA-256")
    return new_entry(
        "weight_file",
        identifier=identifier,
        pinned=reason is None,
        gap_reason=reason,
        location=distribution[0] if distribution else (None if hub else name or None),
        size=_int(props.get(P_SIZE)),
        format=file_format,
        can_run_code=can_run_code,
        hub_repo=props.get(P_HUB_REPO),
        hub_revision=props.get(P_HUB_REVISION),
        hub_file=props.get(P_HUB_FILE),
        # Whatever the document says (P_FORMAT_ORIGIN included), its claims are a third
        # party's: they count only once confirmed (feature 003, FR-002).
        format_origin="import",
    )


def _split_purl(purl: str) -> tuple[str, str, str | None]:
    """``(type, path, version)`` of a ``pkg:`` URL, ignoring qualifiers and subpath."""
    body = purl[4:].split("#", 1)[0].split("?", 1)[0]
    kind, _, rest = body.partition("/")
    path, _, version = rest.rpartition("@") if "@" in rest else (rest, "", "")
    return kind.lower(), unquote(path), unquote(version) or None


def _read_marker(item: dict[str, Any]) -> str | None:
    """The marker an imported package records (issue #34): ``""`` for ``none``, the marker
    normalised with ``packaging``, or ``None`` (not recorded) for an absent property, a value
    that is neither, or several ``marker`` properties that disagree (review R34-4; identical ones
    count once). The value is a third party's: an unreadable one is never no marker."""
    values = {
        str(prop.get("value", ""))
        for prop in item.get("properties") or []
        if isinstance(prop, dict) and prop.get("name") == P_MARKER
    }
    if len(values) != 1:
        return None
    (value,) = values
    if value == NO_MARKER:
        return ""
    try:
        return str(Marker(value))
    except (InvalidMarker, RecursionError):
        return None


def _import_package(item: dict[str, Any]) -> dict[str, Any]:
    props = _props(item)
    marker = _read_marker(item)
    hashes = _read_hashes(item) or None
    purl = item.get("purl")
    kind = item.get("type")
    name = str(item.get("name") or "") or None
    if kind not in ("library", "framework"):
        reason = props.get(P_GAP) or f"unrecognised component type {kind!r}"
        return gap("package", reason, name=name, hashes=hashes, marker=marker)
    if not isinstance(purl, str) or not purl.startswith("pkg:"):
        reason = props.get(P_GAP) or "no purl"
        return gap(
            "package", reason, name=name, version=item.get("version"), hashes=hashes, marker=marker
        )
    purl_type, path, version = _split_purl(purl)
    if purl_type != "pypi":
        reason = props.get(P_GAP) or "not a PyPI package"
        return gap("package", reason, name=name, hashes=hashes, marker=marker)
    name = canonicalize_name(path)
    identifier = None
    if version is not None:
        identifier = f"pkg:pypi/{name}@{quote(version, safe='.!-_~')}"
    reason = props.get(P_GAP)
    if reason is None:
        reason = NO_EXACT_VERSION if version is None else (None if hashes else NO_HASH)
    return new_entry(
        "package",
        identifier=identifier,
        pinned=reason is None,
        gap_reason=reason,
        name=name,
        version=version,
        hashes=hashes,
        marker=marker,
    )


def _import_base_model(item: dict[str, Any]) -> dict[str, Any]:
    props = _props(item)
    name = str(item.get("name") or "") or None
    purl = item.get("purl")
    if not isinstance(purl, str) or not purl.startswith("pkg:huggingface/"):
        return gap("base_model", props.get(P_GAP) or "no Hugging Face purl", name=name)
    _, repo, commit = _split_purl(purl)
    if commit is None:
        return gap("base_model", props.get(P_GAP) or NO_REVISION, name=repo)
    commit = commit.lower()
    if not is_commit(commit):
        return gap("base_model", props.get(P_GAP) or NOT_A_COMMIT, name=repo)
    reason = props.get(P_GAP)
    licence, form = _read_licence(item)
    return new_entry(
        "base_model",
        identifier=huggingface_purl(repo, commit),
        pinned=reason is None,
        gap_reason=reason,
        name=repo,
        version=commit,
        recorded_licence=licence,
        licence_form=form,
    )


def _dataset_doi(item: dict[str, Any]) -> str | None:
    candidates = []
    ref = item.get("bom-ref")
    if isinstance(ref, str) and ref.startswith("doi:"):
        candidates.append(ref)
    candidates += [url for url in _references(item, "distribution") if "doi.org/" in url]
    contents = item.get("contents")
    if isinstance(contents, dict) and isinstance(contents.get("url"), str):
        candidates.append(contents["url"])
    for candidate in candidates:
        doi = normalise_doi(unquote(candidate))
        if doi is not None:
            return doi
    return None


def _hub_dataset(item: dict[str, Any]) -> tuple[str, str | None] | None:
    """``(repo, commit)`` of a hub dataset component, or ``None`` for any other dataset."""
    ref = item.get("bom-ref")
    if isinstance(ref, str) and ref.startswith(HUB_DATASET_PREFIX):
        repo, _, commit = ref[len(HUB_DATASET_PREFIX) :].rpartition("@")
        return repo, commit.lower() or None
    repo = _props(item).get(P_HUB_REPO)
    if repo is None:
        for url in _references(item, "distribution"):
            if url.startswith(HUB_DATASET_URL):
                repo = unquote(url[len(HUB_DATASET_URL) :])
                break
    return None if repo is None else (repo, None)


def _import_dataset(item: dict[str, Any]) -> dict[str, Any]:
    props = _props(item)
    hashes = _read_hashes(item) or None
    licence, form = _read_licence(item)
    common: dict[str, Any] = {
        "hashes": hashes,
        "paper_dois": _read_papers(item),
        "recorded_licence": licence,
        "licence_form": form,
    }
    hub = _hub_dataset(item)
    if hub is not None:
        repo, commit = hub
        reason = props.get(P_GAP)
        if reason is None and commit is None:
            reason = NO_REVISION
        elif reason is None and not is_commit(commit):
            reason = NOT_A_COMMIT
        identifier = hub_dataset_identifier(repo, commit) if reason is None and commit else None
        return new_entry(
            "dataset",
            identifier=identifier,
            pinned=reason is None,
            gap_reason=reason,
            hub_repo=repo,
            hub_revision=commit if identifier else None,
            **common,
        )
    doi = _dataset_doi(item)
    reason = props.get(P_GAP) or (None if doi else NO_DOI)
    return new_entry("dataset", identifier=doi, pinned=reason is None, gap_reason=reason, **common)


def _list(value: Any) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _limit_reason(unread: int) -> str:
    return f"more than {MAX_ANCESTORS} ancestors; {unread} not read"


def _read_ancestors(
    model: Mapping[str, Any],
) -> tuple[list[tuple[int, dict[str, Any]]], int, list[tuple[int, dict[str, Any]]]]:
    """The ancestors read (with their index), how many were not, and carried limit gaps.

    A limit gap a previous export wrote (an ancestor whose gap is the limit's) is not counted
    towards the limit: it is read back as the gap it records (review R3).
    """
    pedigree = model.get("pedigree") if isinstance(model.get("pedigree"), dict) else {}
    listed = list(enumerate(_list(pedigree.get("ancestors"))))
    carried = [(i, item) for i, item in listed if _LIMIT_GAP.match(_props(item).get(P_GAP, ""))]
    others = [(i, item) for i, item in listed if (i, item) not in carried]
    read = others[:MAX_ANCESTORS]
    return read + carried, len(others) - len(read), carried


def _ancestor_edge(index: int, item: dict[str, Any], **source: Any) -> dict[str, Any]:
    """The edge one imported ancestor gives (contracts/cyclonedx-lineage.md, rules 2 to 6)."""
    props = _props(item)
    stated = props.get(P_RELATIONSHIP)
    relationship, recorded = UNSPECIFIED, props.get(P_RELATIONSHIP_RECORDED)
    if stated in RELATIONSHIPS:
        relationship = stated
    elif stated is not None and stated != UNSPECIFIED:
        recorded = stated
    common = {
        "relationship": relationship,
        "relationship_recorded": recorded,
        "origin": "import",
        "claimed_origin": props.get(P_EDGE_ORIGIN),
        "source_key": f"ancestors[{index}]",
        "state": "unverified",
        **source,
    }
    if P_PARENT_MODEL in props:
        text = props.get(P_PARENT_VERSION, "")
        version = int(text) if text.isdecimal() and int(text) >= 1 else None
        return new_edge(
            parent_kind="model",
            parent_model_id=props[P_PARENT_MODEL],
            parent_version=version,
            gap_reason=props.get(P_GAP) or (NO_VERSION if version is None else None),
            **common,
        )
    purl = item.get("purl")
    if isinstance(purl, str) and purl.startswith("pkg:huggingface/"):
        _, repo, commit = _split_purl(purl)
        commit = None if commit is None else commit.lower()
        reason = props.get(P_GAP)
        if commit is None:
            reason = reason or NO_REVISION
        elif not is_commit(commit):
            reason = reason or NOT_A_COMMIT
        entry = huggingface_purl(repo, commit) if commit and is_commit(commit) else None
        return new_edge(
            parent_kind="hub",
            parent_repo=repo,
            parent_revision=commit,
            gap_reason=reason,
            entry_identifier=entry,
            **common,
        )
    repo = props.get(P_HUB_REPO)
    return new_edge(
        parent_kind="hub",
        parent_repo=repo,
        parent_revision=props.get(P_HUB_REVISION) if repo else None,
        gap_reason=props.get(P_GAP) or (NO_REVISION if repo else "no Hugging Face purl"),
        **common,
    )


def import_ancestors(
    document: Any, *, source_file: str | None = None, source_sha256: str | None = None
) -> list[dict[str, Any]]:
    """The lineage edges of a document's ``pedigree.ancestors[]``, folded by identity (T030).

    Every edge is origin ``import`` and state ``unverified``, whatever the document says; its stated
    ``edge-origin`` is kept as ``claimed_origin`` (FR-007, FR-011). Beyond ``MAX_ANCESTORS``, one
    gap edge without a parent identity records how many were not read.
    """
    if not isinstance(document, dict):
        return []
    metadata = document.get("metadata") if isinstance(document.get("metadata"), dict) else {}
    model = metadata.get("component") if isinstance(metadata.get("component"), dict) else {}
    ancestors, unread, _ = _read_ancestors(model)
    source = {"source_file": source_file, "source_sha256": source_sha256}
    edges = [_ancestor_edge(index, item, **source) for index, item in ancestors]
    if unread:
        edges.append(
            new_edge(
                parent_kind="hub",
                relationship=UNSPECIFIED,
                origin="import",
                state="unverified",
                source_key=f"ancestors[{MAX_ANCESTORS}+]",
                gap_reason=_limit_reason(unread),
                **source,
            )
        )
    return fold(edges)


def import_bom(document: Any) -> list[dict[str, Any]]:
    """The inventory entries of a CycloneDX 1.5, 1.6 or 1.7 JSON document, in kind order."""
    if not isinstance(document, dict) or document.get("bomFormat") != "CycloneDX":
        raise InventoryError("not a CycloneDX JSON document")
    if document.get("specVersion") not in IMPORTABLE_VERSIONS:
        raise InventoryError(
            f"CycloneDX {document.get('specVersion')!r} is not supported; "
            f"expected one of {', '.join(IMPORTABLE_VERSIONS)}"
        )
    metadata = document.get("metadata") if isinstance(document.get("metadata"), dict) else {}
    model = metadata.get("component") if isinstance(metadata.get("component"), dict) else {}
    components = _list(document.get("components"))
    by_ref = {c["bom-ref"]: c for c in components if isinstance(c.get("bom-ref"), str)}

    entries: list[dict[str, Any]] = []
    used: set[int] = set()
    card = model.get("modelCard") if isinstance(model.get("modelCard"), dict) else {}
    parameters = card.get("modelParameters")
    parameters = parameters if isinstance(parameters, dict) else {}
    for item in _list(parameters.get("datasets")):
        target = by_ref.get(item["ref"]) if isinstance(item.get("ref"), str) else item
        if target is None:
            entries.append(gap("dataset", f"dataset reference {item['ref']!r} not found"))
            continue
        used.add(id(target))
        entries.append(_import_dataset(target))

    for component in components:
        if id(component) in used:
            continue
        kind = component.get("type")
        if kind == "file":
            entries.append(_import_weight(component))
        elif kind == "data":
            entries.append(_import_dataset(component))
        else:
            entries.append(_import_package(component))

    # Feature 011 (research L4, review R1): an ancestor naming a registered model gives an edge and
    # no entry; at most MAX_ANCESTORS are read and the rest is one gap entry.
    ancestors, unread, _ = _read_ancestors(model)
    entries += [
        _import_base_model(item) for _, item in ancestors if P_PARENT_MODEL not in _props(item)
    ]
    if unread:
        entries.append(gap("base_model", _limit_reason(unread)))

    # A dataset listed twice (or two components sharing one bom-ref) is one entry (review F-03).
    order = {kind: rank for rank, kind in enumerate(ENTRY_KIND_ORDER)}
    return sorted(merge_datasets(entries), key=lambda entry: order[entry["kind"]])

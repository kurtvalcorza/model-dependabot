"""Lineage edges from a manifest, their identity and folding, and their views (data-model.md).

An edge is a mapping with the fields of ``EDGE_FIELDS``; the store adds ``edge_id``, ``model_id``
and ``version``. Edge identity (FR-023, research L3) is the parent's identity, a hub repository
(lower-cased) and revision or a registered model id and version, plus the relationship. Repeats of
one identity fold into one edge whose ``declared_count`` says how often it was declared (the
"duplicate parent" problem). An edge without a parent identity (an imported ancestor with neither a
``pkg:huggingface`` purl nor ``model-dependabot:parent-model``, or the import-limit gap) is keyed
by its ``source_key`` instead, so it never folds into another (review R2).
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from typing import TYPE_CHECKING, Any

from model_dependabot.assurance.trust import edge_state
from model_dependabot.inventory.build import NO_REVISION, NOT_A_COMMIT, huggingface_purl
from model_dependabot.lineage import UNSPECIFIED
from model_dependabot.sources.hf import is_commit

if TYPE_CHECKING:
    from model_dependabot.manifest import Manifest, ParentSpec

NO_VERSION = "no version"
PARENT_NOT_REGISTERED = "parent not registered"
RESOLVED_BY_ID = "resolved by id and version only"
# A version registered before feature 003 has no recorded origin; its synthesised edges show this.
NO_ORIGIN = "origin not recorded"

EDGE_FIELDS = (
    "position",
    "parent_kind",
    "parent_repo",
    "parent_revision",
    "parent_model_id",
    "parent_version",
    "relationship",
    "relationship_recorded",
    "origin",
    "claimed_origin",
    "source_file",
    "source_sha256",
    "source_key",
    "recorded_at",
    "state",
    "gap_reason",
    "entry_identifier",
    "declared_count",
)

Edge = Mapping[str, Any]
Exists = Callable[[str, int], bool]


def new_edge(**fields: Any) -> dict[str, Any]:
    """An edge with every field present; unset fields are ``None``, ``declared_count`` 1."""
    unknown = set(fields) - set(EDGE_FIELDS)
    if unknown:
        raise ValueError(f"unknown edge fields: {sorted(unknown)}")
    edge: dict[str, Any] = dict.fromkeys(EDGE_FIELDS)
    edge["declared_count"] = 1
    edge.update(fields)
    return edge


def parent_identity(edge: Edge) -> tuple[Any, ...] | None:
    """The parent's identity, or ``None`` for an edge without one (review R2)."""
    if edge.get("parent_model_id") is not None:
        return ("model", edge["parent_model_id"], edge.get("parent_version"))
    if edge.get("parent_repo") is not None:
        return ("hub", str(edge["parent_repo"]).lower(), edge.get("parent_revision"))
    return None


def identity(edge: Edge) -> tuple[Any, ...]:
    """Edge identity (FR-023): the parent's identity and the relationship."""
    parent = parent_identity(edge)
    if parent is None:
        return ("source", edge.get("source_key"))
    return (*parent, edge["relationship"])


def fold(edges: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """One edge per identity, in order of first declaration, with ``declared_count`` summed."""
    folded: dict[tuple[Any, ...], dict[str, Any]] = {}
    for edge in edges:
        key = identity(edge)
        if key in folded:
            folded[key]["declared_count"] += int(edge.get("declared_count") or 1)
            continue
        folded[key] = dict(edge)
    result = list(folded.values())
    for position, edge in enumerate(result):
        edge["position"] = position
    return result


def _hub_gap(revision: str | None) -> str | None:
    if revision is None:
        return NO_REVISION
    if not is_commit(revision):
        return NOT_A_COMMIT
    return None


def edge_from_parent(
    parent: ParentSpec,
    *,
    origin: str,
    source_file: str | None,
    source_sha256: str | None,
    recorded_at: str | None = None,
) -> dict[str, Any]:
    key = "base_model" if parent.form == "base_model" else f"parents[{parent.index}]"
    common = {
        "relationship": parent.relationship,
        "origin": origin,
        "source_file": source_file,
        "source_sha256": source_sha256,
        "source_key": key,
        "recorded_at": recorded_at,
        "state": edge_state(origin),
    }
    if parent.repo is not None:
        gap = _hub_gap(parent.revision)
        entry = None if gap is not None else huggingface_purl(parent.repo, parent.revision)
        return new_edge(
            parent_kind="hub",
            parent_repo=parent.repo,
            parent_revision=parent.revision,
            gap_reason=gap,
            entry_identifier=entry,
            **common,
        )
    return new_edge(
        parent_kind="model",
        parent_model_id=parent.model_id,
        parent_version=parent.model_version,
        gap_reason=NO_VERSION if parent.model_version is None else None,
        **common,
    )


def edges_from_manifest(
    manifest: Manifest,
    *,
    origin: str,
    source_file: str | None,
    source_sha256: str | None,
    recorded_at: str | None = None,
) -> list[dict[str, Any]]:
    """The folded edges of a manifest's parents, in declaration order (T021).

    ``origin`` is ``manifest``, or ``record`` for a registration from a registration record, whose
    SHA-256 is then ``source_sha256``; the state follows the origin (FR-007).
    """
    from model_dependabot.manifest import parents_of

    return fold(
        edge_from_parent(
            parent,
            origin=origin,
            source_file=source_file,
            source_sha256=source_sha256,
            recorded_at=recorded_at,
        )
        for parent in parents_of(manifest)
    )


def resolved(edge: Edge, exists: Exists) -> bool | None:
    """Whether a registered-model edge names a version in the store; ``None`` for a hub edge."""
    if edge.get("parent_kind") != "model":
        return None
    version = edge.get("parent_version")
    return version is not None and exists(str(edge["parent_model_id"]), int(version))


def edge_gap(edge: Edge, exists: Exists) -> str | None:
    """The edge's stored gap, or ``parent not registered`` when the reference does not resolve."""
    if edge.get("gap_reason"):
        return str(edge["gap_reason"])
    if resolved(edge, exists) is False:
        return PARENT_NOT_REGISTERED
    return None


def parent_label(edge: Edge) -> str:
    """``hf:owner/name@revision``, ``model:id@version`` or the source key of an unidentified one."""
    if edge.get("parent_kind") == "model":
        version = edge.get("parent_version")
        return f"model:{edge['parent_model_id']}" + ("" if version is None else f"@{version}")
    if edge.get("parent_repo") is not None:
        revision = edge.get("parent_revision")
        return f"hf:{edge['parent_repo']}" + ("" if revision is None else f"@{revision}")
    return f"unidentified parent ({edge.get('source_key')})"


def _parent(edge: Edge) -> dict[str, Any] | None:
    if edge.get("parent_kind") == "model":
        return {
            "kind": "model",
            "model_id": edge["parent_model_id"],
            "version": edge.get("parent_version"),
        }
    if edge.get("parent_repo") is None:
        return None
    return {"kind": "hub", "repo": edge["parent_repo"], "revision": edge.get("parent_revision")}


def edge_view(edge: Edge, exists: Exists) -> dict[str, Any]:
    """The edge as every output shows it (contracts/edge-evidence.md, Edge view)."""
    found = resolved(edge, exists)
    note = RESOLVED_BY_ID if found and edge.get("origin") == "import" else None
    return {
        "edge_id": edge.get("edge_id"),
        "relationship": edge["relationship"],
        "relationship_recorded": edge.get("relationship_recorded"),
        "parent": _parent(edge),
        "origin": edge.get("origin"),
        "claimed_origin": edge.get("claimed_origin"),
        "state": edge["state"],
        "source": {
            "file": edge.get("source_file"),
            "sha256": edge.get("source_sha256"),
            "key": edge.get("source_key"),
        },
        "recorded_at": edge.get("recorded_at"),
        "declared_count": edge.get("declared_count") or 1,
        "gap": edge_gap(edge, exists),
        "resolved": found,
        "note": note,
    }


def edge_line(view: Mapping[str, Any]) -> str:
    """One edge for text output: type, parent, origin and state, and any gap or note."""
    parent = view["parent"]
    if parent is None:
        label = f"unidentified parent ({view['source']['key']})"
    elif parent["kind"] == "model":
        version = "" if parent["version"] is None else f"@{parent['version']}"
        label = f"model:{parent['model_id']}{version}"
    else:
        revision = "" if parent["revision"] is None else f"@{parent['revision']}"
        label = f"hf:{parent['repo']}{revision}"
    origin = view["origin"] or NO_ORIGIN
    line = f"  {view['relationship']:<16} {label}  origin {origin}, {view['state']}"
    if view.get("claimed_origin"):
        line += f" (claimed {view['claimed_origin']})"
    if view.get("relationship_recorded"):
        line += f" (recorded as {view['relationship_recorded']})"
    if view["gap"]:
        line += f"  [{view['gap']}]"
    elif view["resolved"]:
        line += "  resolved" + (f" ({view['note']})" if view["note"] else "")
    return line


def cause_edges(edges: Sequence[Edge], repo: str) -> list[dict[str, Any]]:
    """Every hub edge of a version that names ``repo``, as a finding cites it (FR-009, FR-024)."""
    wanted = repo.lower()
    return [
        {
            "relationship": edge["relationship"],
            "origin": edge.get("origin"),
            "state": edge["state"],
            "revision": edge.get("parent_revision"),
            "source_key": edge.get("source_key"),
        }
        for edge in edges
        if edge.get("parent_kind") == "hub" and str(edge.get("parent_repo") or "").lower() == wanted
    ]


def is_unspecified(edge: Edge) -> bool:
    return edge["relationship"] == UNSPECIFIED

"""The candidate dependency discovery proposes (data-model.md, Candidate dependency; FR-015)."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

VERIFIED = "verified"
DECLARED = "declared-but-unverified"
CONFLICTING = "conflicting"
UNAVAILABLE = "unavailable"
STATUSES = (VERIFIED, DECLARED, CONFLICTING, UNAVAILABLE)
KINDS = ("package", "weight_file", "base_model", "dataset", "licence", "environment")

NO_REVISION = "no revision"
NOT_LOCKED = "not locked"
NO_EXACT_VERSION = "no exact version"
NOT_A_REGISTRY_PACKAGE = "not a registry package"
SEVERAL_BASE_MODELS = "several base models; multi-parent lineage is #9"
NOT_A_HUB_NAME = "not a hub repository name (owner/name)"

STATEMENT = (
    "These are dependencies proposed from the evidence available in the project. Discovery cannot"
    " establish complete training provenance."
)


def utc_text(moment: datetime) -> str:
    """A UTC timestamp as the tool prints it: ``YYYY-MM-DDTHH:MM:SSZ``."""
    if moment.tzinfo is None:
        raise ValueError("timestamps must carry a time zone")
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def candidate(
    kind: str,
    identity: Mapping[str, Any],
    origin: Mapping[str, Any],
    status: str,
    observed_at: str,
    gaps: list[str] | None = None,
    **fields: Any,
) -> dict[str, Any]:
    if kind not in KINDS or status not in STATUSES:
        raise ValueError(f"not a candidate kind and status: {kind}, {status}")
    return {
        "kind": kind,
        "identity": dict(identity),
        "origin": dict(origin),
        "status": status,
        "observed_at": observed_at,
        "gaps": list(gaps or []),
        **fields,
    }


def origin_text(origin: Mapping[str, Any]) -> str:
    """Where a candidate was seen, for people: ``README.md (base_model)``, ``a.txt line 3``."""
    if "source" in origin:
        return f"{origin['source']} ({origin.get('url', '')})"
    where = str(origin.get("file", "?"))
    if origin.get("line") is not None:
        return f"{where} line {origin['line']}"
    if origin.get("key"):
        return f"{where} ({origin['key']})"
    return where

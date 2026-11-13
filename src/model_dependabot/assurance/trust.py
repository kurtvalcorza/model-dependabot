"""Which claims about an inventory entry need confirmation, and how each claim is verified.

A weight file's format claim (``format`` and ``can_run_code``) is *owner-trusted* when it was
classified from the local bytes, named in the owner's manifest or taken from a registration record.
It *needs confirmation* when it was imported from a third-party inventory, or when it has no
recorded origin and its version was imported or registered before feature 003 (legacy, research
A2). Under the strict format policy, only a pinned code-free file whose claim is owner-trusted or
confirmed counts as a code-free file beside the others (FR-004; data-model.md, Rule FR-004).

Every security-relevant claim of an entry is shown with its origin and verification (FR-001):
``owner``, ``measured``, ``confirmed``, ``unverified`` or ``contradicted``. ``format-check``
confirms imported weight files (claim ``code_free`` and claim ``identity``); no source in this
feature confirms imported package hashes or base-model and dataset revisions, so they stay
``unverified`` with the reason ``NO_CHECK_CONFIRMS``.

Pure functions of the stored rows: nothing here reads a file or a source.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

OWNER_TRUSTED = ("bytes", "name", "record")
OWNER_VERSIONS = ("manifest", "record")
CODE_FREE = "code_free"
IDENTITY = "identity"
NO_CHECK_CONFIRMS = "no check confirms this claim"
LEGACY = "legacy"

Entry = Mapping[str, Any]
Check = Mapping[str, Any]


def needs_confirmation(entry: Entry, version_origin: str | None) -> bool:
    """Whether a weight file's format claim counts only once a check confirms it."""
    if entry.get("kind") != "weight_file":
        return False
    format_origin = entry.get("format_origin")
    if format_origin == "import":
        return True
    return format_origin is None and version_origin not in OWNER_VERSIONS


def _confirmed(latest: Check | None) -> bool:
    return latest is not None and latest.get("outcome") == "confirmed"


def counts_as_code_free(
    entry: Entry, version_origin: str | None, latest_check: Check | None
) -> bool:
    """Whether the entry counts as a code-free file under the strict policy (FR-004).

    ``latest_check`` is the entry's latest ``code_free`` claim check in its version, if any.
    """
    if entry.get("kind") != "weight_file" or not entry.get("pinned"):
        return False
    if entry.get("can_run_code") is not False:
        return False
    return not needs_confirmation(entry, version_origin) or _confirmed(latest_check)


def latest_check(checks: Sequence[Check], identifier: str | None, claim: str) -> Check | None:
    """The latest of ``checks`` (oldest first) for one entry and claim; the latest decides."""
    found = None
    for check in checks:
        if check.get("entry_identifier") == identifier and check.get("claim") == claim:
            found = check
    return found


def _verdict(latest: Check | None) -> tuple[str, str | None]:
    if latest is None:
        return "unverified", "not yet checked"
    outcome = latest.get("outcome")
    if outcome == "confirmed":
        return "confirmed", None
    if outcome == "contradicted":
        return "contradicted", latest.get("reason")
    return "unverified", latest.get("reason") or "the check could not read the file"


def _origin(version_origin: str | None) -> str:
    return LEGACY if version_origin is None else version_origin


def _claim(
    claim: str, value: Any, origin: str, verification: str, reason: str | None = None
) -> dict[str, Any]:
    return {
        "claim": claim,
        "value": value,
        "origin": origin,
        "verification": verification,
        "reason": reason,
    }


def _weight_claims(
    entry: Entry, version_origin: str | None, checks: Sequence[Check]
) -> list[dict[str, Any]]:
    identifier = entry.get("identifier")
    hub = entry.get("hub_repo") is not None
    claims: list[dict[str, Any]] = []
    if needs_confirmation(entry, version_origin):
        origin = entry.get("format_origin") or _origin(version_origin)
        verification, reason = _verdict(latest_check(checks, identifier, CODE_FREE))
        identity, identity_reason = _verdict(latest_check(checks, identifier, IDENTITY))
        for name in ("format", "can_run_code"):
            claims.append(_claim(name, entry.get(name), origin, verification, reason))
        claims.append(_claim("sha256", identifier, origin, identity, identity_reason))
        if hub:
            revision = entry.get("hub_revision")
            claims.append(_claim("revision", revision, origin, identity, identity_reason))
        return claims
    format_origin = entry.get("format_origin") or _origin(version_origin)
    kind = "measured" if format_origin == "bytes" else "owner"
    for name in ("format", "can_run_code"):
        claims.append(_claim(name, entry.get(name), format_origin, kind))
    claims.append(_claim("sha256", identifier, format_origin, kind))
    if hub:
        claims.append(_claim("revision", entry.get("hub_revision"), format_origin, "owner"))
    return claims


def claim_verification(
    entry: Entry, version_origin: str | None, checks: Sequence[Check]
) -> list[dict[str, Any]]:
    """Each security-relevant claim of a pinned entry with its origin and verification (FR-001).

    ``checks`` are the version's claim checks, oldest first. A gap pins nothing, so it makes no
    claim; its gap reason is shown instead.
    """
    if not entry.get("pinned"):
        return []
    kind = entry.get("kind")
    if kind == "weight_file":
        return _weight_claims(entry, version_origin, checks)
    trusted = version_origin in OWNER_VERSIONS
    origin = _origin(version_origin)
    verification = "owner" if trusted else "unverified"
    reason = None if trusted else NO_CHECK_CONFIRMS
    if kind == "package":
        return [_claim("sha256", entry.get("hashes"), origin, verification, reason)]
    if kind == "base_model":
        return [_claim("revision", entry.get("version"), origin, verification, reason)]
    if kind == "dataset" and entry.get("hub_repo"):
        return [_claim("revision", entry.get("hub_revision"), origin, verification, reason)]
    if kind == "dataset" and entry.get("hashes"):
        return [_claim("sha256", entry.get("hashes"), origin, verification, reason)]
    return []


def measured_entries(entries: Sequence[Entry], checks: Sequence[Check]) -> list[Entry]:
    """The entries with each contradicted code-free claim replaced by what the bytes showed.

    The stored entry is immutable (FR-005), so a claim that ``format-check`` contradicted is
    applied where the entries are used: the file is the format its bytes show (FR-003), so it is
    scanned, ruled on and audited as that format, never as the claim (review F3).
    """
    result: list[Entry] = []
    for entry in entries:
        latest = latest_check(checks, entry.get("identifier"), CODE_FREE)
        if entry.get("kind") == "weight_file" and latest and latest["outcome"] == "contradicted":
            result.append(
                dict(
                    entry,
                    format=latest["measured_format"],
                    can_run_code=latest["measured_can_run_code"],
                )
            )
        else:
            result.append(entry)
    return result

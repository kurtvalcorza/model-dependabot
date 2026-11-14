"""Global exceptions: an owner's acceptance of one global in one exact file (feature 004, US1).

An exception names a global exactly as the scanner reports it (module and name, compared
case-sensitively, research S9, D7) and the SHA-256 of one file's bytes; it applies wherever those
bytes are registered (FR-002). It is recorded with a reason and who accepted it, may expire at the
end of a UTC day and may be revoked, once (data-model.md, Global exception). A global whose module
or name contains the lower-case string ``unknown`` is never excepted (research S14). Recording,
listing and revoking change no alert: exceptions take effect at the next check that asks a weight
source (FR-010).
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from datetime import date, datetime
from typing import Any

from model_dependabot.store import Store, exception_state

_HEX = re.compile(r"^[0-9a-f]{64}$")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
UNRESOLVED = "unknown"


def parse_global(text: str) -> tuple[str, str]:
    """``MODULE.NAME`` split at the last dot, or ``MODULE:NAME`` split at the colon (S9)."""
    if ":" in text:
        module, _, name = text.partition(":")
    else:
        module, _, name = text.rpartition(".")
    if not module or not name:
        raise ValueError(f"a global is MODULE.NAME or MODULE:NAME, got {text!r}")
    if "*" in module or "*" in name:
        raise ValueError(f"a global is one exact module and name; no wildcards, got {text!r}")
    return module, name


def normalise_sha256(text: str) -> str:
    """64 hexadecimal digits, with or without ``sha256:``, as stored: lower case, no prefix."""
    digest = text.strip().removeprefix("sha256:").lower()
    if not _HEX.match(digest):
        raise ValueError(f"a SHA-256 is 64 hexadecimal digits, got {text!r}")
    return digest


def _expiry(text: str | None, today: date) -> str | None:
    if text is None:
        return None
    if not _DATE.match(text):
        raise ValueError(f"an expiry date is YYYY-MM-DD, got {text!r}")
    try:
        day = date.fromisoformat(text)
    except ValueError:
        raise ValueError(f"an expiry date is YYYY-MM-DD, got {text!r}") from None
    if day < today:
        raise ValueError(f"the expiry date {text} is in the past (today is {today} UTC)")
    return text


def active_at(record: Mapping[str, Any], at: datetime) -> bool:
    """Whether the exception covers its global at ``at`` (data-model.md, State)."""
    return exception_state(record, at) == "active"


def covering(
    exceptions: Iterable[Mapping[str, Any]], module: str, name: str
) -> Mapping[str, Any] | None:
    """The exception among ``exceptions`` for exactly this module and name, if any (D7)."""
    return next((e for e in exceptions if e["module"] == module and e["name"] == name), None)


def exception_view(store: Store, record: Mapping[str, Any]) -> dict[str, Any]:
    """One exception as ``exception list`` prints it (contracts/cli.md)."""
    latest = store.latest_file_scan(record["sha256"])
    seen = latest["globals"] if latest is not None else []
    revoked = None
    if record["revoked_at"]:
        revoked = {
            "at": record["revoked_at"],
            "by": record["revoked_by"],
            "reason": record["revoke_reason"],
        }
    return {
        "exception_id": record["exception_id"],
        "global": f"{record['module']}.{record['name']}",
        "module": record["module"],
        "name": record["name"],
        "sha256": record["sha256"],
        "reason": record["reason"],
        "accepted_by": record["accepted_by"],
        "recorded_at": record["recorded_at"],
        "expires_on": record["expires_on"],
        "state": record["state"],
        "revoked": revoked,
        "applies_to": store.pinned_to(record["sha256"]),
        "in_use": covering(seen, record["module"], record["name"]) is not None,
    }


def record_exception(
    store: Store,
    *,
    global_name: str,
    sha256: str,
    reason: str,
    by: str,
    expires_on: str | None = None,
) -> dict[str, Any]:
    """Record an exception; every refusal of contracts/cli.md is a ``ValueError``."""
    if not reason.strip():
        raise ValueError("an exception needs a reason")
    if not by.strip():
        raise ValueError("an exception needs the name of who accepted it")
    module, name = parse_global(global_name)
    if UNRESOLVED in module or UNRESOLVED in name:
        raise ValueError(
            f"{global_name} names an import the scanner could not resolve ('{UNRESOLVED}');"
            " it cannot be excepted"
        )
    digest = normalise_sha256(sha256)
    expiry = _expiry(expires_on, store.now().date())
    made = store.add_exception(
        module=module,
        name=name,
        sha256=digest,
        reason=reason.strip(),
        accepted_by=by.strip(),
        expires_on=expiry,
    )
    return exception_view(store, made)


def list_exceptions(
    store: Store, *, include_inactive: bool = False, sha256: str | None = None
) -> list[dict[str, Any]]:
    """Active exceptions (``include_inactive``: also revoked and expired), oldest first."""
    digest = None if sha256 is None else normalise_sha256(sha256)
    return [
        exception_view(store, record)
        for record in store.exceptions(digest, include_inactive=include_inactive)
    ]


def revoke_exception(store: Store, exception_id: int, *, reason: str, by: str) -> dict[str, Any]:
    """Revoke an active exception; the finding returns at the next check (FR-004)."""
    return exception_view(store, store.revoke_exception(exception_id, by=by, reason=reason))

"""Recording, matching and expiry of global exceptions (T017, data-model.md, research S8-S14)."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from model_dependabot.assurance import exceptions
from model_dependabot.store import Store

NOW = datetime(2026, 11, 13, 9, 0, tzinfo=UTC)
SHA = "c" * 64


class Clock:
    def __init__(self) -> None:
        self.at = NOW

    def __call__(self) -> datetime:
        return self.at


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def store(tmp_path: Path, clock: Clock) -> Iterator[Store]:
    with Store(tmp_path / "md.db", now=clock) as opened:
        yield opened


def _record(store: Store, **changes: str | None) -> dict:
    fields: dict = {
        "global_name": "__builtin__.getattr",
        "sha256": SHA,
        "reason": "reviewed: attribute lookup on layer classes only",
        "by": "Owner",
        "expires_on": None,
    }
    fields.update(changes)
    return exceptions.record_exception(store, **fields)


# --- spelling a global (S9) ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "parsed"),
    [
        ("__builtin__.getattr", ("__builtin__", "getattr")),
        ("torch._utils._rebuild_parameter", ("torch._utils", "_rebuild_parameter")),
        (
            "model_dependabot_fixture.layers:CustomLayer",
            ("model_dependabot_fixture.layers", "CustomLayer"),
        ),
        ("pkg.mod:Outer.Inner", ("pkg.mod", "Outer.Inner")),
    ],
)
def test_a_global_splits_at_the_last_dot_or_at_the_colon(
    text: str, parsed: tuple[str, str]
) -> None:
    assert exceptions.parse_global(text) == parsed


@pytest.mark.parametrize(
    "text", ["getattr", ".getattr", "builtins.", ":name", "module:", "", "os.*"]
)
def test_a_malformed_global_is_refused(text: str) -> None:
    with pytest.raises(ValueError):
        exceptions.parse_global(text)


@pytest.mark.parametrize("text", [SHA, f"sha256:{SHA}", SHA.upper()])
def test_a_hash_is_64_hexadecimal_digits_with_or_without_the_prefix(text: str) -> None:
    assert exceptions.normalise_sha256(text) == SHA


@pytest.mark.parametrize("text", ["c" * 63, "g" * 64, f"sha1:{SHA}", "", f"sha256:{SHA}0"])
def test_a_malformed_hash_is_refused(text: str) -> None:
    with pytest.raises(ValueError):
        exceptions.normalise_sha256(text)


# --- refusals when recording (US1 scenario 5, S8, S14) -------------------------------------------


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"reason": ""}, "reason"),
        ({"reason": "   "}, "reason"),
        ({"by": ""}, "name"),
        ({"sha256": "1234"}, "SHA-256"),
        ({"global_name": "getattr"}, "global"),
        ({"global_name": "unknown.eval"}, "unknown"),
        ({"global_name": "os.unknown_call"}, "unknown"),
        ({"global_name": "my_unknown_pkg:thing"}, "unknown"),
        ({"expires_on": "2026-11-12"}, "past"),
        ({"expires_on": "13/11/2026"}, "YYYY-MM-DD"),
    ],
)
def test_recording_refuses_bad_input(store: Store, changes: dict, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        _record(store, **changes)
    assert store.exceptions(include_inactive=True) == []


def test_a_capitalised_unknown_is_not_refused(store: Store) -> None:
    """The scanner flags only the lower-case string, so only it is refused (S14)."""
    assert _record(store, global_name="Unknown.thing")["global"] == "Unknown.thing"


def test_an_expiry_of_today_is_accepted(store: Store) -> None:
    assert _record(store, expires_on="2026-11-13")["expires_on"] == "2026-11-13"


def test_a_second_active_exception_for_the_same_global_and_hash_is_refused(store: Store) -> None:
    _record(store)
    with pytest.raises(ValueError, match="active exception"):
        _record(store, reason="again")
    # Another global or another hash is not the same exception.
    _record(store, global_name="builtins.getattr")
    _record(store, sha256="d" * 64)


def test_a_new_exception_can_follow_a_revoked_one(store: Store) -> None:
    first = _record(store)
    exceptions.revoke_exception(store, first["exception_id"], reason="replaced", by="Owner")
    second = _record(store, reason="reviewed again")
    assert second["exception_id"] != first["exception_id"]


def test_a_recorded_exception_has_its_evidence(store: Store) -> None:
    made = _record(store)
    [row] = store.exceptions()
    evidence = store.get_evidence(row["evidence_id"])
    assert evidence["source"] == "exception"
    assert evidence["url"] == f"exception:{made['exception_id']}"
    assert evidence["matched_identifier"] == f"sha256:{SHA}"
    assert made["state"] == "active"
    assert made["recorded_at"] == "2026-11-13T09:00:00Z"
    assert (made["accepted_by"], made["module"], made["name"]) == (
        "Owner",
        "__builtin__",
        "getattr",
    )


# --- activity with a fixed clock -----------------------------------------------------------------


def test_an_exception_expires_at_midnight_utc_after_its_expiry_date(
    store: Store, clock: Clock
) -> None:
    made = _record(store, expires_on="2027-01-31")
    record = store.exceptions(include_inactive=True)[0]
    assert exceptions.active_at(record, datetime(2027, 1, 31, 23, 59, 59, tzinfo=UTC))
    assert not exceptions.active_at(record, datetime(2027, 2, 1, 0, 0, tzinfo=UTC))
    clock.at = datetime(2027, 2, 1, 0, 0, tzinfo=UTC)
    assert store.exceptions() == []
    [listed] = exceptions.list_exceptions(store, include_inactive=True)
    assert (listed["exception_id"], listed["state"]) == (made["exception_id"], "expired")
    with pytest.raises(ValueError, match="expired"):
        exceptions.revoke_exception(store, made["exception_id"], reason="late", by="Owner")


def test_revoking_records_who_when_and_why_once(store: Store, clock: Clock) -> None:
    made = _record(store)
    clock.at = datetime(2026, 11, 14, 10, 0, tzinfo=UTC)
    revoked = exceptions.revoke_exception(
        store, made["exception_id"], reason="new review", by="Lead"
    )
    assert revoked["state"] == "revoked"
    assert revoked["revoked"] == {
        "at": "2026-11-14T10:00:00Z",
        "by": "Lead",
        "reason": "new review",
    }
    with pytest.raises(ValueError, match="revoked"):
        exceptions.revoke_exception(store, made["exception_id"], reason="again", by="Lead")
    for reason, by in (("", "Lead"), ("why", " ")):
        with pytest.raises(ValueError):
            exceptions.revoke_exception(store, made["exception_id"], reason=reason, by=by)
    with pytest.raises(ValueError, match="no exception"):
        exceptions.revoke_exception(store, 999, reason="x", by="Lead")


# --- exact matching (D7) -------------------------------------------------------------------------


def test_builtin_and_builtins_getattr_never_match_each_other(store: Store) -> None:
    _record(store, global_name="__builtin__.getattr")
    active = store.exceptions(sha256=SHA)
    assert exceptions.covering(active, "__builtin__", "getattr") is not None
    assert exceptions.covering(active, "builtins", "getattr") is None
    assert exceptions.covering(active, "__builtin__", "GetAttr") is None
    assert exceptions.covering(active, "__builtin__.getattr", "") is None

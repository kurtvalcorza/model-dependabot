"""The new-evidence rule of held dismissals (T054, FR-020, research S13).

A dismissed alert holds while a check brings no new evidence: an observation is new unless one
linked to the dismissed alert has the same source, URL, matching key and matched identifier, or
the check computes a higher severity. The matching key drops the volatile fields of the source
(``store.VOLATILE_FIELDS``, dotted paths, nested ones included); stored evidence stays whole.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from model_dependabot import lifecycle
from model_dependabot.store import VOLATILE_FIELDS, Store, canonical_sha256, matching_key

NOW = datetime(2026, 11, 14, 9, 0, tzinfo=UTC)
ID = "sha256:" + "e" * 64


def _body(value: Any) -> bytes:
    return json.dumps(value).encode("utf-8")


# --- the matching key, per source (owner's ruling 2026-11-14) -------------------------------------

HUB = {"id": "o/r", "downloads": 1, "likes": 2, "lastModified": "2026-01-01", "sha": "abc"}
CASES = [
    ("huggingface.co", HUB, {"downloads": 9, "likes": 8, "lastModified": "2026-02-02"}),
    ("hf-hub", HUB, {"downloads": 9, "likes": 8, "lastModified": "2026-02-02"}),
    ("zenodo", {"id": 1, "stats": {"views": 1, "downloads": 2}}, {"stats": {"views": 5}}),
    (
        "crossref",
        {
            "status": "ok",
            "message": {"DOI": "10.1/x", "indexed": {"t": 1}, "is-referenced-by-count": 3},
        },
        {"message": {"DOI": "10.1/x", "indexed": {"t": 2}, "is-referenced-by-count": 4}},
    ),
    (
        "datacite",
        {"data": {"id": "10.1/x", "attributes": {"state": "findable", "viewCount": 1,
                                                 "citationsOverTime": [], "versionCount": 0}}},
        {"data": {"id": "10.1/x", "attributes": {"state": "findable", "viewCount": 7,
                                                 "citationsOverTime": [{"year": 2026}],
                                                 "versionCount": 0}}},
    ),
]  # fmt: skip


def _merge(base: dict[str, Any], change: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for key, value in change.items():
        out[key] = _merge(out[key], value) if isinstance(value, dict) and key in out else value
    return out


@pytest.mark.parametrize(("source", "body", "change"), CASES)
def test_only_volatile_fields_changed_is_the_same_key(
    source: str, body: dict[str, Any], change: dict[str, Any]
) -> None:
    changed = _merge(body, change)
    assert canonical_sha256(_body(body)) != canonical_sha256(_body(changed))
    assert matching_key(source, _body(body)) == matching_key(source, _body(changed))


@pytest.mark.parametrize(
    ("source", "body", "change"),
    [
        ("huggingface.co", HUB, {"sha": "def"}),
        ("zenodo", {"id": 1, "stats": {}}, {"id": 2}),
        ("crossref", {"message": {"indexed": 1, "type": "a"}}, {"message": {"type": "b"}}),
        ("datacite", {"data": {"attributes": {"state": "findable"}}},
         {"data": {"attributes": {"state": "registered"}}}),
    ],
)  # fmt: skip
def test_any_other_change_is_a_new_key(
    source: str, body: dict[str, Any], change: dict[str, Any]
) -> None:
    assert matching_key(source, _body(body)) != matching_key(source, _body(_merge(body, change)))


def test_fields_are_dropped_only_for_their_own_source() -> None:
    a, b = _body(HUB), _body(HUB | {"downloads": 99})
    assert matching_key("osv.dev", a) != matching_key("osv.dev", b)


def test_the_table_names_real_datacite_keys_not_wildcards() -> None:
    assert all("*" not in path for paths in VOLATILE_FIELDS.values() for path in paths)
    datacite = set(VOLATILE_FIELDS["datacite"])
    assert "data.attributes.viewCount" in datacite
    assert "data.attributes.downloadsOverTime" in datacite


def test_a_body_that_is_not_json_keys_by_its_raw_hash() -> None:
    import hashlib

    assert matching_key("huggingface.co", b"not json") == hashlib.sha256(b"not json").hexdigest()


# --- the helper on each insert path ---------------------------------------------------------------


@pytest.fixture
def store(tmp_path: Path) -> Iterator[Store]:
    with Store(tmp_path / "md.db", now=lambda: NOW) as opened:
        opened.add_model("m")
        yield opened


def _target() -> Any:
    return lifecycle._Target("m", 1, [], {"dismissals_held": []}, source="picklescan")


def _dismissed(store: Store, body: bytes, *, severity: str = "HIGH", identifier: str = ID) -> int:
    evidence_id = store.add_evidence(
        source="picklescan", url="file:///w.pkl", retrieved_at=NOW,
        matched_identifier=identifier, body=body,
    )  # fmt: skip
    alert_id = store.insert_alert(
        model_id="m", kind="weight_file_scan", cause_key=f"weight_file_scan:{ID}",
        cause={"identifier": ID}, severity=severity, severity_origin="policy",
        opened_in_version=1, evidence_ids=[evidence_id],
    )  # fmt: skip
    store.close_alert(
        alert_id, state="dismissed", dismissal_reason="risk_accepted", dismissed_by="Owner"
    )
    return alert_id


def _observation(body: bytes) -> Any:
    return lifecycle._Observation("picklescan", "file:///w.pkl", NOW, body, {})


def test_the_same_observation_holds_the_dismissal(store: Store) -> None:
    alert_id = _dismissed(store, _body({"scanner_version": "1.0.5"}))
    target = _target()
    held, reopens = lifecycle._held_dismissal(
        store, target, f"weight_file_scan:{ID}", "HIGH", identifier=ID,
        observations=[_observation(_body({"scanner_version": "1.0.5"}))],
    )  # fmt: skip
    assert (held, reopens) == (True, None)
    assert target.summary["dismissals_held"] == [alert_id]
    assert target.held == {"picklescan": [alert_id]}


def test_another_scanner_version_is_new_evidence(store: Store) -> None:
    alert_id = _dismissed(store, _body({"scanner_version": "1.0.5"}))
    held, reopens = lifecycle._held_dismissal(
        store, _target(), f"weight_file_scan:{ID}", "HIGH", identifier=ID,
        observations=[_observation(_body({"scanner_version": "1.0.6"}))],
    )  # fmt: skip
    assert held is False
    assert reopens == {
        "alert_id": alert_id,
        "dismissed_by": "Owner",
        "dismissal_reason": "risk_accepted",
        "closed_at": "2026-11-14T09:00:00Z",
    }


def test_a_higher_severity_is_new_evidence(store: Store) -> None:
    _dismissed(store, _body({"a": 1}), severity="MODERATE")
    held, _ = lifecycle._held_dismissal(
        store, _target(), f"weight_file_scan:{ID}", "HIGH", identifier=ID,
        observations=[_observation(_body({"a": 1}))],
    )  # fmt: skip
    assert held is False


def test_another_matched_identifier_is_new_evidence(store: Store) -> None:
    """A newly pinned package version is matched under another identifier (OSV path)."""
    alert_id = _dismissed(store, _body({"a": 1}), identifier="pkg:pypi/pillow@12.3.0")
    other = store.add_evidence(
        source="picklescan", url="file:///w.pkl", retrieved_at=NOW,
        matched_identifier="pkg:pypi/pillow@12.4.0", body=_body({"a": 1}),
    )  # fmt: skip
    held, reopens = lifecycle._held_dismissal(
        store, _target(), f"weight_file_scan:{ID}", "HIGH", evidence_ids=[other]
    )
    assert held is False and reopens["alert_id"] == alert_id


def test_stored_evidence_ids_that_match_hold(store: Store) -> None:
    """The OSV and upstream paths compare evidence rows already stored in the run."""
    _dismissed(store, _body({"a": 1}))
    again = store.add_evidence(
        source="picklescan", url="file:///w.pkl", retrieved_at=NOW,
        matched_identifier=ID, body=_body({"a": 1}),
    )  # fmt: skip
    held, _ = lifecycle._held_dismissal(
        store, _target(), f"weight_file_scan:{ID}", "HIGH", evidence_ids=[again]
    )
    assert held is True


@pytest.mark.parametrize("state", ["fixed", "cleared", "withdrawn"])
def test_another_closed_state_holds_nothing(store: Store, state: str) -> None:
    evidence_id = store.add_evidence(
        source="picklescan", url="u", retrieved_at=NOW, matched_identifier=ID, body=b"{}"
    )
    alert_id = store.insert_alert(
        model_id="m", kind="weight_file_scan", cause_key=f"weight_file_scan:{ID}", cause={},
        severity="HIGH", severity_origin="policy", opened_in_version=1,
        evidence_ids=[evidence_id],
    )  # fmt: skip
    store.close_alert(alert_id, state=state)
    held, reopens = lifecycle._held_dismissal(
        store, _target(), f"weight_file_scan:{ID}", "HIGH", identifier=ID,
        observations=[lifecycle._Observation("picklescan", "u", NOW, b"{}", {})],
    )  # fmt: skip
    assert (held, reopens) == (False, None)

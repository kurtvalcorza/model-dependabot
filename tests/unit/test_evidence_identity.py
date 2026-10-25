"""Evidence identity for JSON bodies (feature 006, E1; constitution I).

OSV can serve the same advisory as byte-different but semantically identical JSON a few seconds
apart. The raw bytes are still stored, but a JSON body also gets a ``canonical_sha256`` (sorted
keys, no insignificant whitespace, UTF-8), and two responses from the same source and URL with the
same canonical hash are the same evidence, so an unchanged advisory adds no evidence run to run.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from model_dependabot.lifecycle import run_check
from model_dependabot.reports import evidence_view
from model_dependabot.sources.fetcher import RecordedFetcher
from model_dependabot.store import Store, canonical_sha256

OSV = Path(__file__).resolve().parent.parent / "fixtures" / "osv"
CP9V = "GHSA-cp9v-662q-vvx9"
MOMENT = datetime(2026, 10, 24, 8, 0, tzinfo=UTC)
PILLOW = {
    "kind": "package",
    "identifier": "pkg:pypi/pillow@12.3.0",
    "pinned": True,
    "name": "pillow",
    "version": "12.3.0",
    "hashes": ["sha256:" + "0" * 64],
}
# The recorded batch answer is for pillow 12.3.0 and validators 0.12.2 together.
VALIDATORS = {
    **PILLOW,
    "identifier": "pkg:pypi/validators@0.12.2",
    "name": "validators",
    "version": "0.12.2",
}


@pytest.fixture
def store(tmp_path: Path) -> Store:
    with Store(tmp_path / "md.db", now=lambda: MOMENT) as opened:
        yield opened


def _canonical(value: Any) -> str:
    text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _evidence(store: Store, body: bytes) -> dict[str, Any]:
    evidence_id = store.add_evidence(
        source="osv.dev",
        url="https://api.osv.dev/v1/vulns/X",
        retrieved_at=MOMENT,
        matched_identifier="pkg:pypi/pillow@12.3.0",
        body=body,
    )
    return store.get_evidence(evidence_id)


def test_canonical_hash_ignores_key_order_and_whitespace() -> None:
    a = b'{"id": "X", "aliases": ["A", "B"], "modified": "2026-10-01T00:00:00Z"}'
    b = b'{\n  "modified":"2026-10-01T00:00:00Z",\n  "id":"X","aliases":["A","B"]}\n'
    assert a != b
    assert canonical_sha256(a) == canonical_sha256(b) == _canonical(json.loads(a))
    assert canonical_sha256(b'{"aliases": ["B", "A"]}') != canonical_sha256(
        b'{"aliases": ["A", "B"]}'
    )


def test_a_non_json_body_has_no_canonical_hash() -> None:
    assert canonical_sha256(b"<html>not json</html>") is None
    assert canonical_sha256(b"\xff\xfe") is None


def test_evidence_records_both_hashes(store: Store) -> None:
    body = b'{"b": 1,  "a": "\xc3\xa9"}'
    record = _evidence(store, body)
    assert record["body_sha256"] == hashlib.sha256(body).hexdigest()
    assert record["canonical_sha256"] == _canonical({"a": "é", "b": 1})
    assert store.read_body(record["body_sha256"]) == body  # the raw bytes are kept (Principle I)
    assert _evidence(store, b"plain text")["canonical_sha256"] is None


def test_evidence_view_shows_the_canonical_hash(store: Store) -> None:
    view = evidence_view(_evidence(store, b'{"a": 1}'))
    assert view["canonical_sha256"] == _canonical({"a": 1})
    assert view["body_sha256"] == hashlib.sha256(b'{"a": 1}').hexdigest()


def _register(store: Store) -> None:
    store.add_model("m")
    store.add_version("m", {"bomFormat": "CycloneDX"}, "0" * 64, [PILLOW, VALIDATORS])


def _check(store: Store, root: Path) -> None:
    run_check(store, RecordedFetcher(root), ["m"], ["osv"])


def _open(store: Store) -> dict[str, dict[str, Any]]:
    return {a["cause"]["advisory_id"]: a for a in store.alerts_for("m", ["open"])}


def _evidence_rows(store: Store) -> int:
    return int(store.conn.execute("SELECT count(*) FROM evidence").fetchone()[0])


def test_a_reserialised_unchanged_advisory_keeps_the_alert_evidence(
    store: Store, derive_osv: Callable[..., Path]
) -> None:
    def reordered(advisory: dict[str, Any]) -> dict[str, Any]:
        return dict(reversed(list(advisory.items())))  # same content, other key order and spacing

    root = derive_osv({f"vuln-{CP9V}": reordered})
    assert (root / f"vuln-{CP9V}.json").read_bytes() != (OSV / f"vuln-{CP9V}.json").read_bytes()
    _register(store)
    _check(store, OSV)
    alert_id = _open(store)[CP9V]["alert_id"]
    before = [e["evidence_id"] for e in store.alert_evidence(alert_id)]
    rows = _evidence_rows(store)

    _check(store, root)
    _check(store, OSV)
    assert [e["evidence_id"] for e in store.alert_evidence(alert_id)] == before
    assert _evidence_rows(store) == rows
    assert store.get_advisory("osv.dev", CP9V)["evidence_id"] == before[0]


@pytest.mark.parametrize(
    "change",
    [
        lambda advisory: {**advisory, "modified": "2026-10-25T00:00:00Z"},
        lambda advisory: {
            **advisory,
            "affected": [
                *advisory["affected"],
                {
                    "package": advisory["affected"][0]["package"],
                    "ranges": [
                        {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0"}]}
                    ],
                },
            ],
        },
    ],
    ids=["new-modified", "new-affected-range"],
)
def test_a_real_content_change_is_new_evidence(
    store: Store, derive_osv: Callable[..., Path], change: Callable[[dict[str, Any]], Any]
) -> None:
    _register(store)
    _check(store, OSV)
    alert_id = _open(store)[CP9V]["alert_id"]
    _check(store, derive_osv({f"vuln-{CP9V}": change}))
    evidence = store.alert_evidence(alert_id)
    assert len(evidence) == 2
    assert evidence[0]["canonical_sha256"] != evidence[1]["canonical_sha256"]


def test_an_older_store_gains_the_column_and_backfills_it(tmp_path: Path) -> None:
    db = tmp_path / "md.db"
    with Store(db, now=lambda: MOMENT) as store:
        kept = _evidence(store, b'{"z": 1, "a": 2}')
        lost = _evidence(store, b'{"gone": true}')
        text = _evidence(store, b"not json")
        store.conn.execute("ALTER TABLE evidence DROP COLUMN canonical_sha256")
        store.conn.commit()
        assert "canonical_sha256" not in store.columns("evidence")
    (tmp_path / "evidence" / lost["body_sha256"]).unlink()  # a body no longer on disk

    with Store(db, now=lambda: MOMENT) as store:
        assert "canonical_sha256" in store.columns("evidence")
        assert store.get_evidence(kept["evidence_id"])["canonical_sha256"] == _canonical(
            {"a": 2, "z": 1}
        )
        assert store.get_evidence(lost["evidence_id"])["canonical_sha256"] is None
        assert store.get_evidence(text["evidence_id"])["canonical_sha256"] is None

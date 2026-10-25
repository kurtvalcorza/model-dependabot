"""The ETag cache is kept bounded without ever losing evidence (research U13; Principle I).

Replacing a URL's entry deletes the previous body when nothing else refers to it, and ``check``
drops entries no run has used for ``ETAG_CACHE_MAX_AGE_DAYS`` days. A body that an evidence record
or another cache entry refers to is never deleted, and pruning twice is the same as pruning once.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

from model_dependabot import cli
from model_dependabot.sources.fetcher import Headers, RecordedFetcher, Response
from model_dependabot.store import ETAG_CACHE_MAX_AGE_DAYS, EtagCache, Store

FIRST = datetime(2026, 10, 24, 8, 0, tzinfo=UTC)
STALE = FIRST + timedelta(days=ETAG_CACHE_MAX_AGE_DAYS + 1)
URL = "https://api.osv.dev/v1/vulns/GHSA-1"
OTHER = "https://api.osv.dev/v1/vulns/GHSA-2"


def response(body: bytes, etag: str, url: str = URL, at: datetime = FIRST) -> Response:
    return Response(200, body, url, at, Headers({"ETag": etag}))


def digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def body_file(tmp_path: Path, body: bytes) -> Path:
    return tmp_path / "evidence" / digest(body)


def test_the_age_limit_is_ninety_days() -> None:
    assert ETAG_CACHE_MAX_AGE_DAYS == 90


def test_replacing_an_entry_deletes_the_orphaned_body(tmp_path: Path) -> None:
    with Store(tmp_path / "md.db") as store:
        cache = EtagCache(store)
        cache[URL] = response(b"old", '"1"')
        cache[URL] = response(b"new", '"2"')
        assert cache[URL].body == b"new"
    assert not body_file(tmp_path, b"old").exists()
    assert body_file(tmp_path, b"new").exists()


def test_replacing_with_the_same_body_keeps_it(tmp_path: Path) -> None:
    with Store(tmp_path / "md.db") as store:
        cache = EtagCache(store)
        cache[URL] = response(b"same", '"1"')
        cache[URL] = response(b"same", '"2"')
        assert cache[URL].body == b"same"
    assert body_file(tmp_path, b"same").exists()


def test_a_body_referenced_by_evidence_survives_replacement(tmp_path: Path) -> None:
    with Store(tmp_path / "md.db") as store:
        store.add_evidence(
            source="osv", url=URL, retrieved_at=FIRST, matched_identifier="GHSA-1", body=b"old"
        )
        cache = EtagCache(store)
        cache[URL] = response(b"old", '"1"')
        cache[URL] = response(b"new", '"2"')
        assert store.read_body(digest(b"old")) == b"old"


def test_a_body_another_entry_uses_survives_replacement(tmp_path: Path) -> None:
    with Store(tmp_path / "md.db") as store:
        cache = EtagCache(store)
        cache[URL] = response(b"shared", '"1"')
        cache[OTHER] = response(b"shared", '"1"', OTHER)
        cache[URL] = response(b"new", '"2"')
        assert cache[OTHER].body == b"shared"


def test_deleting_an_entry_deletes_its_orphaned_body(tmp_path: Path) -> None:
    with Store(tmp_path / "md.db") as store:
        cache = EtagCache(store)
        cache[URL] = response(b"gone", '"1"')
        del cache[URL]
    assert not body_file(tmp_path, b"gone").exists()


def test_entries_unused_past_the_limit_are_dropped(tmp_path: Path) -> None:
    clock = {"now": FIRST}
    with Store(tmp_path / "md.db", now=lambda: clock["now"]) as store:
        cache = EtagCache(store)
        cache[URL] = response(b"stale", '"1"')
        cache[OTHER] = response(b"fresh", '"1"', OTHER)
        clock["now"] = FIRST + timedelta(days=60)
        assert cache[OTHER].body == b"fresh"  # a lookup is a use
        clock["now"] = STALE
        assert store.prune_etag_cache() == 1
        assert list(cache) == [OTHER]
    assert not body_file(tmp_path, b"stale").exists()
    assert body_file(tmp_path, b"fresh").exists()


def test_pruning_keeps_bodies_evidence_refers_to_and_is_safe_to_rerun(tmp_path: Path) -> None:
    clock = {"now": FIRST}
    with Store(tmp_path / "md.db", now=lambda: clock["now"]) as store:
        store.add_evidence(
            source="osv", url=URL, retrieved_at=FIRST, matched_identifier="GHSA-1", body=b"kept"
        )
        EtagCache(store)[URL] = response(b"kept", '"1"')
        clock["now"] = STALE
        assert store.prune_etag_cache() == 1
        assert store.prune_etag_cache() == 0
        assert len(EtagCache(store)) == 0
        assert store.read_body(digest(b"kept")) == b"kept"


def test_an_entry_from_before_use_times_ages_from_its_retrieval(tmp_path: Path) -> None:
    with Store(tmp_path / "md.db", now=lambda: FIRST) as store:
        EtagCache(store)[URL] = response(b"old", '"1"')
        store.conn.execute("UPDATE etag_cache SET used_at = NULL")
        store.conn.commit()
    with Store(tmp_path / "md.db", now=lambda: STALE) as store:
        assert store.prune_etag_cache() == 1


def test_a_database_without_the_use_column_gains_it(tmp_path: Path) -> None:
    with Store(tmp_path / "md.db") as store:
        store.conn.execute("DROP TABLE etag_cache")
        store.conn.execute(
            "CREATE TABLE etag_cache (url TEXT PRIMARY KEY, etag TEXT NOT NULL, status INTEGER"
            " NOT NULL, headers TEXT NOT NULL, body_sha256 TEXT NOT NULL, original_sha256 TEXT"
            " NOT NULL, redacted_fields TEXT NOT NULL, retrieved_at TEXT NOT NULL)"
        )
        store.conn.commit()
    with Store(tmp_path / "md.db") as store:
        assert "used_at" in store.columns("etag_cache")


def test_check_prunes_the_cache(tmp_path: Path) -> None:
    db = tmp_path / "md.db"
    with Store(db, now=lambda: FIRST) as store:
        store.add_model("m")
        store.add_version("m", {"bomFormat": "CycloneDX"}, "0" * 64, [])
        EtagCache(store)[URL] = response(b"stale", '"1"')
    empty = tmp_path / "recorded"
    empty.mkdir()
    handlers = cli.make_handlers(fetcher=RecordedFetcher(empty), now=lambda: STALE)
    assert cli.main(["check", "m", "--db", str(db), "--source", "osv"], handlers=handlers) == 0
    with Store(db) as store:
        assert len(EtagCache(store)) == 0
    assert not body_file(tmp_path, b"stale").exists()

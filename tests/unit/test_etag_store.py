"""The ETag cache persists in the store, so later runs revalidate (review C2; research U13).

Within one run ``UrlFetcher`` already revalidates with ``If-None-Match``. The cache now lives in the
store's ``etag_cache`` table with the body in the evidence store, so a later ``check`` sends the
stored ETag and a ``304`` reuses the stored body as evidence, retrieved at this run's time with the
original body hash kept. Only redacted bodies are ever stored.
"""

from __future__ import annotations

import hashlib
import io
import json
import urllib.error
import urllib.request
from datetime import UTC, datetime, timedelta
from email.message import Message
from pathlib import Path
from typing import Any

import pytest

from model_dependabot import cli
from model_dependabot.sources import fetcher as fetcher_module
from model_dependabot.sources.fetcher import Headers, Response, UrlFetcher
from model_dependabot.store import EtagCache, Store

FIRST = datetime(2026, 10, 24, 8, 0, tzinfo=UTC)
LATER = FIRST + timedelta(days=1)
INDEX = "https://huggingface.co/datasets/huggingface-legal/takedown-notices/resolve/main/index.csv"
CSV = b"date,requesting_entity,reported_content,file\n2026-09-04,A Person,owner/name,f.md\n"
OSV = Path(__file__).resolve().parent.parent / "fixtures" / "osv"
CP9V = "GHSA-cp9v-662q-vvx9"
QUERYBATCH = "https://api.osv.dev/v1/querybatch"
VULN = f"https://api.osv.dev/v1/vulns/{CP9V}"


class _Raw:
    def __init__(self, url: str, status: int, body: bytes, headers: dict[str, str]) -> None:
        self._url, self.status, self._body = url, status, body
        self.headers = Message()
        for key, value in headers.items():
            self.headers[key] = value

    def read(self) -> bytes:
        return self._body

    def geturl(self) -> str:
        return self._url

    def __enter__(self) -> _Raw:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


class Opener:
    def __init__(self, answer: Any) -> None:
        self.answer = answer
        self.requests: list[urllib.request.Request] = []

    def __call__(self, request: urllib.request.Request, timeout: float) -> _Raw:
        self.requests.append(request)
        status, body, headers = self.answer(request)
        if status >= 300:
            hdrs = Message()
            for key, value in headers.items():
                hdrs[key] = value
            raise urllib.error.HTTPError(request.full_url, status, "x", hdrs, io.BytesIO(body))
        return _Raw(request.full_url, status, body, headers)


def _takedowns(request: urllib.request.Request) -> tuple[int, bytes, dict[str, str]]:
    if request.get_header("If-none-match") == '"v1"':
        return 304, b"", {"ETag": '"v1"'}
    return 200, CSV, {"ETag": '"v1"', "Content-Type": "text/csv", "Set-Cookie": "session=abc"}


def _fetcher(store: Store, opener: Opener, now: datetime) -> UrlFetcher:
    return UrlFetcher(opener=opener, utcnow=lambda: now, etag_cache=EtagCache(store))


def test_the_store_has_an_etag_cache_table(tmp_path: Path) -> None:
    with Store(tmp_path / "md.db") as store:
        assert "etag_cache" in store.tables()
        assert store.columns("etag_cache") >= {"url", "etag", "body_sha256", "retrieved_at"}


def test_the_cache_survives_reopening_the_store(tmp_path: Path) -> None:
    with Store(tmp_path / "md.db") as store:
        first = _fetcher(store, Opener(_takedowns), FIRST).get(INDEX)
    opener = Opener(_takedowns)
    with Store(tmp_path / "md.db") as store:
        second = _fetcher(store, opener, LATER).get(INDEX)
    assert opener.requests[0].get_header("If-none-match") == '"v1"'
    assert second.not_modified is True
    assert (second.status, second.body, second.url) == (200, first.body, INDEX)
    assert second.retrieved_at == LATER
    assert second.original_sha256 == first.original_sha256 == hashlib.sha256(CSV).hexdigest()
    assert second.redacted_fields == first.redacted_fields == ("file", "requesting_entity")
    assert second.headers.get("ETag") == '"v1"'


def test_only_the_redacted_body_is_stored(tmp_path: Path) -> None:
    with Store(tmp_path / "md.db") as store:
        _fetcher(store, Opener(_takedowns), FIRST).get(INDEX)
        cached = EtagCache(store)[INDEX]
        assert b"A Person" not in cached.body
        assert cached.headers.get("Set-Cookie") is None
    assert b"A Person" not in (tmp_path / "md.db").read_bytes()
    assert b"session=abc" not in (tmp_path / "md.db").read_bytes()
    stored = list((tmp_path / "evidence").iterdir())
    assert stored and not any(b"A Person" in path.read_bytes() for path in stored)


def test_a_cached_body_that_is_missing_is_a_miss(tmp_path: Path) -> None:
    with Store(tmp_path / "md.db") as store:
        _fetcher(store, Opener(_takedowns), FIRST).get(INDEX)
        for path in (tmp_path / "evidence").iterdir():
            path.unlink()
        cache = EtagCache(store)
        assert INDEX not in cache
        assert cache.get(INDEX) is None
        opener = Opener(_takedowns)
        _fetcher(store, opener, LATER).get(INDEX)
        assert opener.requests[0].get_header("If-none-match") is None


def test_the_mapping_can_be_set_listed_and_deleted(tmp_path: Path) -> None:
    response = Response(200, b"{}", "https://api.osv.dev/x", FIRST, Headers({"ETag": '"a"'}))
    with Store(tmp_path / "md.db") as store:
        cache = EtagCache(store)
        cache["https://api.osv.dev/x"] = response
        assert list(cache) == ["https://api.osv.dev/x"] and len(cache) == 1
        del cache["https://api.osv.dev/x"]
        assert len(cache) == 0
        with pytest.raises(KeyError):
            del cache["https://api.osv.dev/x"]


def _osv(etags: bool):
    def answer(request: urllib.request.Request) -> tuple[int, bytes, dict[str, str]]:
        if request.full_url == QUERYBATCH:
            body = json.dumps({"results": [{"vulns": [{"id": CP9V, "modified": "x"}]}]})
            return 200, body.encode(), {"Content-Type": "application/json"}
        assert request.full_url == VULN
        if etags and request.get_header("If-none-match") == '"osv-1"':
            return 304, b"", {"ETag": '"osv-1"'}
        body = (OSV / f"vuln-{CP9V}.json").read_bytes()
        return 200, body, {"Content-Type": "application/json", "ETag": '"osv-1"'}

    return answer


def test_a_later_check_run_revalidates_and_reuses_the_stored_body(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    db = tmp_path / "md.db"
    package = {
        "kind": "package",
        "identifier": "pkg:pypi/pillow@12.3.0",
        "pinned": True,
        "name": "pillow",
        "version": "12.3.0",
        "hashes": ["sha256:" + "0" * 64],
    }
    with Store(db) as store:
        store.add_model("m")
        store.add_version("m", {"bomFormat": "CycloneDX"}, "0" * 64, [package])
    clock = {"now": FIRST}
    opener = Opener(_osv(etags=True))
    monkeypatch.setattr(fetcher_module, "open_without_redirects", opener)
    handlers = cli.make_handlers(now=lambda: clock["now"])
    argv = ["check", "m", "--db", str(db), "--source", "osv", "--json"]

    assert cli.main(argv, handlers=handlers) == 0
    clock["now"] = LATER
    opener.requests.clear()
    capsys.readouterr()
    assert cli.main(argv, handlers=handlers) == 0
    second = json.loads(capsys.readouterr().out)

    [vuln_request] = [r for r in opener.requests if r.full_url == VULN]
    assert vuln_request.get_header("If-none-match") == '"osv-1"'
    assert second["sources"] == {"osv": "ok"}
    with Store(db) as store:
        [alert] = store.alerts_for("m")
        evidence = store.alert_evidence(alert["alert_id"])
    assert second["models"][0]["carried_forward"] == [alert["alert_id"]]
    # The 304 reuses the stored body: the evidence is the same record, with the same hash, as a
    # 200 with an unchanged body would give.
    body = (OSV / f"vuln-{CP9V}.json").read_bytes()
    assert [e["body_sha256"] for e in evidence if e["url"] == VULN] == [
        hashlib.sha256(body).hexdigest()
    ]

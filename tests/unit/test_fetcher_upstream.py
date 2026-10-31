"""Fetcher additions for the upstream sources (tasks T006, extending 001's fetcher tests).

Redirects are recorded rather than followed silently, each upstream source is paced at its published
limit (research U13), ETags are revalidated, redaction (research U10) happens before a body leaves
the fetcher and every request is an anonymous read.
"""

from __future__ import annotations

import hashlib
import io
import json
import urllib.error
import urllib.request
from datetime import UTC, datetime
from email.message import Message
from pathlib import Path

import pytest

from model_dependabot.sources.fetcher import (
    DEFAULT_LIMITS,
    RecordedFetcher,
    SourceFailedError,
    UrlFetcher,
)
from model_dependabot.store import Store

NOW = datetime(2026, 10, 24, 8, 0, 0, tzinfo=UTC)


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


class FakeHttpResponse:
    def __init__(self, url: str, status: int, body: bytes, headers: dict[str, str]) -> None:
        self._url, self.status, self._body = url, status, body
        self.headers = Message()
        for key, value in headers.items():
            self.headers[key] = value

    def read(self) -> bytes:
        return self._body

    def geturl(self) -> str:
        return self._url

    def __enter__(self) -> FakeHttpResponse:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


def http_error(url: str, status: int, body: bytes, headers: dict[str, str]) -> Exception:
    hdrs = Message()
    for key, value in headers.items():
        hdrs[key] = value
    return urllib.error.HTTPError(url, status, "error", hdrs, io.BytesIO(body))


class Opener:
    """Answers by a function of the request; ``raise_3xx`` mimics urllib with redirects off."""

    def __init__(self, answer, *, raise_3xx: bool = False) -> None:
        self.answer = answer
        self.raise_3xx = raise_3xx
        self.requests: list[urllib.request.Request] = []
        self.times: list[float] = []
        self.clock: FakeClock | None = None

    def __call__(self, request: urllib.request.Request, timeout: float) -> FakeHttpResponse:
        self.requests.append(request)
        if self.clock is not None:
            self.times.append(self.clock.now)
        status, body, headers = self.answer(request)
        if status >= 400 or (self.raise_3xx and 300 <= status < 400) or status == 304:
            raise http_error(request.full_url, status, body, headers)
        return FakeHttpResponse(request.full_url, status, body, headers)


def fetcher_for(opener: Opener, clock: FakeClock | None = None, **kwargs: object) -> UrlFetcher:
    clock = clock or FakeClock()
    opener.clock = clock
    return UrlFetcher(
        opener=opener, monotonic=clock.monotonic, sleep=clock.sleep, utcnow=lambda: NOW, **kwargs
    )


def ok(body: bytes = b"{}", **headers: str):
    return lambda request: (200, body, {"Content-Type": "application/json", **headers})


# --- redirects ------------------------------------------------------------------------------------

BOOKS3 = "https://huggingface.co/api/datasets/the_pile_books3?expand[]=disabled"
MOVED = "/api/datasets/defunct-datasets/the_pile_books3?expand[]=disabled"


@pytest.mark.parametrize("raise_3xx", [False, True])
def test_a_redirect_is_recorded_not_followed_when_the_call_opts_out(raise_3xx: bool) -> None:
    # 002's hub dataset and model info calls opt out so that a move is seen (research U5).
    opener = Opener(
        lambda request: (307, b"Temporary Redirect", {"Location": MOVED}), raise_3xx=raise_3xx
    )
    response = fetcher_for(opener).get(BOOKS3, follow_redirects=False)
    assert response.status == 307
    assert response.redirected_from == BOOKS3
    assert response.redirected_to == "https://huggingface.co" + MOVED
    assert len(opener.requests) == 1


def test_the_default_opener_does_not_follow_redirects() -> None:
    from model_dependabot.sources.fetcher import NoRedirectHandler

    handler = NoRedirectHandler()
    request = urllib.request.Request(BOOKS3)
    assert handler.redirect_request(request, None, 307, "x", Message(), MOVED) is None


def test_a_plain_answer_has_no_redirect_fields() -> None:
    response = fetcher_for(Opener(ok())).get("https://api.crossref.org/works/10.1/x")
    assert response.redirected_from is None and response.redirected_to is None


def test_a_recorded_redirect_replays_its_target(tmp_path: Path) -> None:
    (tmp_path / "moved.json").write_bytes(b"Temporary Redirect")
    meta = {
        "method": "GET",
        "url": BOOKS3,
        "status": 307,
        "headers": {"location": MOVED},
        "redirected_to": "https://huggingface.co" + MOVED,
        "retrieved_at": "2026-10-24T08:00:00Z",
        "body_file": "moved.json",
    }
    (tmp_path / "moved.meta.json").write_text(json.dumps(meta), "utf-8")
    response = RecordedFetcher(tmp_path).get(BOOKS3, follow_redirects=False)
    assert (response.status, response.redirected_from) == (307, BOOKS3)
    assert response.redirected_to == "https://huggingface.co" + MOVED


TARGET = "https://huggingface.co" + MOVED


def _moving(request: urllib.request.Request) -> tuple[int, bytes, dict[str, str]]:
    if request.full_url == BOOKS3:
        return 307, b"Temporary Redirect", {"Location": MOVED}
    return 200, b'{"id": "defunct-datasets/the_pile_books3"}', {"Content-Type": "application/json"}


@pytest.mark.parametrize("raise_3xx", [False, True])
def test_a_redirect_is_followed_by_default_as_in_001(raise_3xx: bool) -> None:
    opener = Opener(_moving, raise_3xx=raise_3xx)
    response = fetcher_for(opener).get(BOOKS3)
    assert response.status == 200
    assert response.url == TARGET
    assert response.redirected_from == BOOKS3
    assert response.redirected_to is None
    assert [request.full_url for request in opener.requests] == [BOOKS3, TARGET]


def test_head_follows_by_default_and_can_opt_out() -> None:
    assert fetcher_for(Opener(_moving)).head(BOOKS3).status == 200
    assert fetcher_for(Opener(_moving)).head(BOOKS3, follow_redirects=False).status == 307


def test_a_redirect_loop_fails_the_source_after_the_limit() -> None:
    from model_dependabot.sources.fetcher import MAX_REDIRECTS, SourceFailedError

    opener = Opener(lambda request: (302, b"", {"Location": request.full_url + "x"}))
    with pytest.raises(SourceFailedError, match="redirects"):
        fetcher_for(opener).get(BOOKS3)
    assert len(opener.requests) == MAX_REDIRECTS + 1


def _record(folder: Path, name: str, url: str, status: int, body: bytes, **extra: object) -> None:
    (folder / f"{name}.json").write_bytes(body)
    meta = {
        "method": "GET",
        "url": url,
        "status": status,
        "headers": {},
        "retrieved_at": "2026-10-24T08:00:00Z",
        "body_file": f"{name}.json",
        **extra,
    }
    (folder / f"{name}.meta.json").write_text(json.dumps(meta), "utf-8")


def test_a_recorded_redirect_is_followed_by_default(tmp_path: Path) -> None:
    _record(tmp_path, "moved", BOOKS3, 307, b"Temporary Redirect", redirected_to=TARGET)
    _record(tmp_path, "target", TARGET, 200, b'{"id": "x"}')
    fetcher = RecordedFetcher(tmp_path)
    response = fetcher.get(BOOKS3)
    assert (response.status, response.url, response.redirected_from) == (200, TARGET, BOOKS3)
    assert response.redirected_to is None
    assert response.body == b'{"id": "x"}'


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
GPT2_COMMIT = "607a30d783dfa663caf39e06633721c8d4cfcd7e"
GPT2_TREE = f"https://huggingface.co/api/models/openai-community/gpt2/tree/{GPT2_COMMIT}"
RENAMED_TREE = f"https://huggingface.co/api/models/gpt2/tree/{GPT2_COMMIT}"


def test_001_tree_adapter_follows_a_307_for_a_renamed_repository(tmp_path: Path) -> None:
    from model_dependabot.sources.hf import HuggingFace

    meta = json.loads((FIXTURES / "hf" / "gpt2-tree.meta.json").read_text("utf-8"))
    body = (FIXTURES / "hf" / meta["body_file"]).read_bytes()
    _record(tmp_path, "direct", GPT2_TREE, 200, body)
    _record(tmp_path, "renamed", RENAMED_TREE, 307, b"Temporary Redirect", redirected_to=GPT2_TREE)
    hub = HuggingFace(RecordedFetcher(tmp_path))
    direct = hub.tree("openai-community/gpt2", GPT2_COMMIT)
    renamed = hub.tree("gpt2", GPT2_COMMIT)
    assert direct.gap_reason is None and direct.files
    assert renamed == direct
    assert {path: f.sha256 for path, f in renamed.files.items()} == {
        path: f.sha256 for path, f in direct.files.items()
    }


def test_002_dataset_info_sees_the_recorded_307_unfollowed() -> None:
    meta = json.loads((FIXTURES / "hf_upstream" / "dataset-moved.meta.json").read_text("utf-8"))
    fetcher = RecordedFetcher(FIXTURES / "hf_upstream")
    response = fetcher.get(meta["url"], follow_redirects=False)
    assert response.status == 307
    assert response.redirected_from == meta["url"]
    assert response.redirected_to == meta["redirected_to"]
    assert len(fetcher.requests) == 1


# --- pacing (research U13) ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("host", "requests", "window"),
    [
        ("api.crossref.org", 1, 1.0),
        ("api.figshare.com", 1, 1.0),
        ("zenodo.org", 60, 60.0),
        ("huggingface.co", 500, 300.0),
    ],
)
def test_published_limits_per_source(host: str, requests: int, window: float) -> None:
    limit = DEFAULT_LIMITS[host]
    assert (limit.requests, limit.window) == (requests, window)


def test_crossref_requests_run_one_a_second() -> None:
    opener = Opener(ok())
    clock = FakeClock()
    fetcher = fetcher_for(opener, clock)
    for index in range(4):
        fetcher.get(f"https://api.crossref.org/works/10.1/{index}")
    gaps = [later - earlier for earlier, later in zip(opener.times, opener.times[1:], strict=False)]
    assert gaps == [1.0, 1.0, 1.0]


def test_figshare_requests_run_one_a_second() -> None:
    opener = Opener(ok())
    clock = FakeClock()
    fetcher = fetcher_for(opener, clock)
    for index in range(3):
        fetcher.get(f"https://api.figshare.com/v2/articles/{index}")
    assert opener.times[-1] - opener.times[0] == 2.0


def test_zenodo_allows_sixty_a_minute() -> None:
    opener = Opener(ok())
    clock = FakeClock()
    fetcher = fetcher_for(opener, clock)
    for index in range(61):
        fetcher.get(f"https://zenodo.org/api/records/{index}")
    assert opener.times[59] == opener.times[0]
    assert opener.times[60] - opener.times[0] == 60.0


def test_pacing_is_per_source() -> None:
    opener = Opener(ok())
    clock = FakeClock()
    fetcher = fetcher_for(opener, clock)
    fetcher.get("https://api.crossref.org/works/10.1/a")
    fetcher.get("https://api.figshare.com/v2/articles/1")
    fetcher.get("https://api.datacite.org/dois/10.5281/zenodo.1")
    assert clock.sleeps == []


# --- ETag caching ---------------------------------------------------------------------------------

INDEX = "https://huggingface.co/datasets/huggingface-legal/takedown-notices/resolve/main/index.csv"
CSV = b"date,requesting_entity,reported_content,file\n2026-09-04,A Person,owner/name,f.md\n"


def test_an_etag_is_revalidated_and_a_304_is_served_from_the_cache() -> None:
    def answer(request: urllib.request.Request):
        if request.get_header("If-none-match") == '"v1"':
            return 304, b"", {"ETag": '"v1"'}
        return 200, CSV, {"ETag": '"v1"', "Content-Type": "text/csv"}

    cache: dict = {}
    first = fetcher_for(Opener(answer), etag_cache=cache).get(INDEX)
    opener = Opener(answer)
    second = fetcher_for(opener, etag_cache=cache).get(INDEX)
    assert opener.requests[0].get_header("If-none-match") == '"v1"'
    assert second.status == 200
    assert second.body == first.body
    assert second.not_modified is True
    assert first.not_modified is False


def test_without_an_etag_nothing_is_revalidated() -> None:
    cache: dict = {}
    fetcher_for(Opener(ok()), etag_cache=cache).get("https://api.crossref.org/works/10.1/x")
    opener = Opener(ok())
    fetcher_for(opener, etag_cache=cache).get("https://api.crossref.org/works/10.1/x")
    assert opener.requests[0].get_header("If-none-match") is None


# --- redaction before storage ---------------------------------------------------------------------


def test_the_takedown_log_is_redacted_before_it_reaches_the_evidence_store(tmp_path: Path) -> None:
    response = fetcher_for(Opener(lambda request: (200, CSV, {}))).get(INDEX)
    assert b"A Person" not in response.body and b"f.md" not in response.body
    assert response.redacted_fields == ("file", "requesting_entity")
    assert response.original_sha256 == hashlib.sha256(CSV).hexdigest()
    assert response.body_sha256 == hashlib.sha256(response.body).hexdigest()
    with Store(tmp_path / "db.sqlite") as store:
        evidence_id = store.add_response_evidence(
            response, source="hf-takedowns", matched_identifier="x"
        )
        record = store.get_evidence(evidence_id)
        assert record["original_sha256"] == response.original_sha256
        assert record["body_sha256"] == response.body_sha256
        assert record["redacted_fields"] == ["file", "requesting_entity"]
        assert b"A Person" not in store.read_body(record["body_sha256"])
        assert not any(b"A Person" in path.read_bytes() for path in store.evidence_dir.iterdir())


def test_a_recorded_fixture_keeps_its_original_hash(tmp_path: Path) -> None:
    (tmp_path / "index.csv").write_bytes(
        b"date,reported_content,file\n2026-09-04,owner/name,f.md\n"
    )
    meta = {
        "method": "GET",
        "url": INDEX,
        "status": 200,
        "headers": {},
        "retrieved_at": "2026-10-24T08:00:00Z",
        "body_file": "index.csv",
        "original_sha256": "a" * 64,
        "redacted_fields": ["file", "requesting_entity"],
    }
    (tmp_path / "index.meta.json").write_text(json.dumps(meta), "utf-8")
    response = RecordedFetcher(tmp_path).get(INDEX)
    assert response.original_sha256 == "a" * 64
    assert response.redacted_fields == ("file", "requesting_entity")


def test_a_recorded_unredacted_body_is_redacted_on_replay(tmp_path: Path) -> None:
    (tmp_path / "index.csv").write_bytes(CSV)
    meta = {"method": "GET", "url": INDEX, "status": 200, "headers": {}}
    meta |= {"retrieved_at": "2026-10-24T08:00:00Z", "body_file": "index.csv"}
    (tmp_path / "index.meta.json").write_text(json.dumps(meta), "utf-8")
    response = RecordedFetcher(tmp_path).get(INDEX)
    assert b"A Person" not in response.body
    assert response.original_sha256 == hashlib.sha256(CSV).hexdigest()


def test_001_sources_keep_equal_hashes_and_no_redacted_fields() -> None:
    body = b'{"id":"GHSA-x","modified":"2026-01-01T00:00:00Z"}'
    response = fetcher_for(Opener(ok(body))).get("https://api.osv.dev/v1/vulns/GHSA-x")
    assert response.body == body
    assert response.original_sha256 == response.body_sha256 == hashlib.sha256(body).hexdigest()
    assert response.redacted_fields == ()


# --- anonymous reads only (FR-002, FR-017) --------------------------------------------------------

NEW_SOURCE_URLS = [
    "https://doi.org/doiRA/10.5281/zenodo.3242074",
    "https://api.crossref.org/works/10.1177/1758835919874651",
    "https://api.datacite.org/dois/10.5281/zenodo.3242074",
    "https://zenodo.org/api/records/3242074",
    "https://api.figshare.com/v2/articles/1",
    "https://huggingface.co/api/models/openai-community/gpt2?expand[]=disabled",
    "https://huggingface.co/api/datasets/yavon/muxue?expand[]=disabled",
    INDEX,
]


def test_every_request_to_a_new_source_is_an_anonymous_get() -> None:
    opener = Opener(ok(ETag='"e"'))
    fetcher = fetcher_for(opener, etag_cache={})
    for url in NEW_SOURCE_URLS:
        fetcher.get(url)
    assert len(opener.requests) == len(NEW_SOURCE_URLS)
    for request in opener.requests:
        assert request.get_method() in ("GET", "HEAD")
        headers = {name.lower() for name, _ in request.header_items()}
        headers |= {name.lower() for name in request.unredirected_hdrs}
        assert headers <= {"user-agent", "if-none-match"}
        assert "authorization" not in headers and "cookie" not in headers
        query = request.full_url.lower()
        for word in ("token", "mailto", "api_key", "apikey", "access_token", "@"):
            assert word not in query
        assert "@" not in request.get_header("User-agent")


def test_head_is_allowed_and_writes_are_not() -> None:
    opener = Opener(ok())
    fetcher = fetcher_for(opener)
    response = fetcher.head("https://zenodo.org/api/records/3242074")
    assert response.status == 200
    assert opener.requests[0].get_method() == "HEAD"
    for method in ("PUT", "DELETE", "PATCH"):
        with pytest.raises(ValueError, match="only reads"):
            fetcher._build(method, "https://zenodo.org/api/records/1", None)


# --- the takedown log redacted on every hop (review F4, amended 2026-10-31) -----------------------

CDN = [
    "https://cas-bridge.xethub.hf.co/xet-bridge-us/0123abcd/index.csv?X-Amz-Signature=s",
    "https://cdn-lfs.hf.co/repos/aa/bb/index.csv?Expires=1",
    "https://cdn.example.net/index.csv",
]


def _to(target: str, body: bytes, **headers: str):
    def answer(request: urllib.request.Request):
        if request.full_url == INDEX:
            return 302, b"", {"Location": target}
        return 200, body, {"Content-Type": "text/csv", **headers}

    return answer


@pytest.mark.parametrize("target", CDN)
def test_the_takedown_log_is_redacted_when_a_redirect_leaves_huggingface_co(target: str) -> None:
    cache: dict = {}
    response = fetcher_for(Opener(_to(target, CSV, ETag='"v1"')), etag_cache=cache).get(INDEX)
    assert response.url == target
    assert b"A Person" not in response.body and b"f.md" not in response.body
    assert response.redacted_fields == ("file", "requesting_entity")
    assert response.original_sha256 == hashlib.sha256(CSV).hexdigest()
    assert all(b"A Person" not in cached.body for cached in cache.values())


@pytest.mark.parametrize("target", CDN)
def test_a_recorded_takedown_redirect_off_huggingface_co_is_redacted(
    tmp_path: Path, target: str
) -> None:
    (tmp_path / "hop.csv").write_bytes(b"")
    (tmp_path / "index.csv").write_bytes(CSV)
    hop = {"method": "GET", "url": INDEX, "status": 302, "headers": {"location": target}}
    hop |= {"redirected_to": target, "retrieved_at": "2026-10-24T08:00:00Z", "body_file": "hop.csv"}
    final = {"method": "GET", "url": target, "status": 200, "headers": {}}
    final |= {"retrieved_at": "2026-10-24T08:00:00Z", "body_file": "index.csv"}
    (tmp_path / "hop.meta.json").write_text(json.dumps(hop), "utf-8")
    (tmp_path / "index.meta.json").write_text(json.dumps(final), "utf-8")
    response = RecordedFetcher(tmp_path).get(INDEX)
    assert b"A Person" not in response.body
    assert response.redacted_fields == ("file", "requesting_entity")


@pytest.mark.parametrize("body", [b"\xff\xfe\x00garbled", b"\x1f\x8b\x08\x00\x00\x00\x00\x00"])
def test_a_takedown_log_that_cannot_be_redacted_is_not_stored(body: bytes) -> None:
    cache: dict = {}
    fetcher = fetcher_for(Opener(_to(CDN[0], body, ETag='"v1"')), etag_cache=cache)
    with pytest.raises(SourceFailedError):
        fetcher.get(INDEX)
    assert cache == {}
    with pytest.raises(SourceFailedError):
        fetcher_for(Opener(lambda request: (200, body, {}))).get(INDEX)


def test_a_redirect_off_huggingface_co_for_another_request_is_not_redacted_as_the_log() -> None:
    model = "https://huggingface.co/gpt2/resolve/main/config.json"
    response = fetcher_for(
        Opener(
            lambda r: (302, b"", {"Location": CDN[0]}) if r.full_url == model else (200, CSV, {})
        )
    ).get(model)
    assert response.body == CSV
    assert response.redacted_fields == ()

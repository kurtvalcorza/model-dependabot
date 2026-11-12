"""Fetcher hardening from RFC #5: redirect destinations (SEC-02, #10), capped response bodies
(SEC-03, #11) and fail-closed redaction of a successful body that cannot be read (SEC-04, #12).
"""

from __future__ import annotations

import io
import json
import urllib.error
import urllib.request
from datetime import UTC, datetime
from email.message import Message
from pathlib import Path

import pytest

from model_dependabot.redact import RedactionError, redact
from model_dependabot.sources.fetcher import (
    DEFAULT_MAX_BODY_BYTES,
    RecordedFetcher,
    SourceFailedError,
    UrlFetcher,
)

NOW = datetime(2026, 11, 4, 8, 0, 0, tzinfo=UTC)


class FakeHttpResponse:
    def __init__(self, url: str, status: int, body: bytes, headers: dict[str, str]) -> None:
        self.url, self.status = url, status
        self._stream = io.BytesIO(body)
        self.reads: list[int] = []
        self.headers = Message()
        for key, value in headers.items():
            self.headers[key] = value

    def read(self, amount: int = -1) -> bytes:
        self.reads.append(amount)
        return self._stream.read(amount)

    def __enter__(self) -> FakeHttpResponse:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


class Opener:
    def __init__(self, answer) -> None:
        self.answer = answer
        self.requests: list[str] = []
        self.responses: list[FakeHttpResponse] = []

    def __call__(self, request: urllib.request.Request, timeout: float) -> FakeHttpResponse:
        self.requests.append(request.full_url)
        status, body, headers = self.answer(request)
        if status >= 300:
            hdrs = Message()
            for key, value in headers.items():
                hdrs[key] = value
            raise urllib.error.HTTPError(request.full_url, status, "x", hdrs, io.BytesIO(body))
        response = FakeHttpResponse(request.full_url, status, body, headers)
        self.responses.append(response)
        return response


def fetcher_for(opener: Opener, **kwargs: object) -> UrlFetcher:
    return UrlFetcher(
        opener=opener, sleep=lambda seconds: None, utcnow=lambda: NOW, retries=0, **kwargs
    )


def redirect(start: str, target: str, body: bytes = b"{}"):
    return lambda r: (302, b"", {"Location": target}) if r.full_url == start else (200, body, {})


# --- SEC-02: redirect destinations ----------------------------------------------------------------

START = "https://huggingface.co/api/models/o/n"


@pytest.mark.parametrize(
    "target",
    [
        "file:///etc/passwd",
        "ftp://example.org/x",
        "data:text/plain,hello",
        "http://cdn.example.net/x",  # a downgrade from https
        "https://127.0.0.1/x",
        "https://127.8.9.10:8080/x",
        "https://localhost/x",
        "https://LOCALHOST./x",
        "https://10.0.0.5/x",
        "https://172.16.0.1/x",
        "https://192.168.1.1/x",
        "https://169.254.169.254/latest/meta-data/",
        "https://0.0.0.0/x",
        "https://[::1]/x",
        "https://[fe80::1]/x",
        "https://[fd00::1]/x",
        "https://[::ffff:127.0.0.1]/x",
        "https://2130706433/x",  # 127.0.0.1 written as one number
        "https://0x7f.1/x",
        "https://127.1/x",
    ],
)
def test_a_redirect_to_an_unsafe_destination_fails_the_source(target: str) -> None:
    opener = Opener(redirect(START, target))
    with pytest.raises(SourceFailedError, match="redirect"):
        fetcher_for(opener).get(START)
    assert opener.requests == [START]


@pytest.mark.parametrize(
    "target",
    [
        "https://cdn-lfs.hf.co/repos/aa/bb/x?Expires=1",
        "https://cas-bridge.xethub.hf.co/x",
        "https://8.8.8.8/x",
        "/api/models/moved/n",
    ],
)
def test_a_redirect_to_a_public_https_destination_is_followed(target: str) -> None:
    opener = Opener(redirect(START, target))
    response = fetcher_for(opener).get(START)
    assert response.status == 200
    assert len(opener.requests) == 2


def test_a_local_mirror_may_redirect_within_its_own_origin() -> None:
    mirror = "http://127.0.0.1:8080/api/models/o/n"
    opener = Opener(redirect(mirror, "/api/models/moved/n"))
    assert fetcher_for(opener).get(mirror).status == 200


def test_a_local_mirror_may_not_redirect_to_another_private_origin() -> None:
    mirror = "http://127.0.0.1:8080/api/models/o/n"
    opener = Opener(redirect(mirror, "http://127.0.0.1:9999/admin"))
    with pytest.raises(SourceFailedError, match="redirect"):
        fetcher_for(opener).get(mirror)


def test_every_hop_is_checked_not_only_the_first() -> None:
    hop = "https://cdn.example.net/hop"
    answers = {
        START: (302, b"", {"Location": hop}),
        hop: (302, b"", {"Location": "https://10.1.1.1/"}),
    }
    opener = Opener(lambda r: answers.get(r.full_url, (200, b"{}", {})))
    with pytest.raises(SourceFailedError, match="redirect"):
        fetcher_for(opener).get(START)
    assert opener.requests == [START, hop]


def test_an_unfollowed_redirect_is_still_returned_as_it_is() -> None:
    """A caller that opts out sees the 3xx and its target; nothing is requested there."""
    opener = Opener(redirect(START, "https://10.0.0.5/x"))
    response = fetcher_for(opener).get(START, follow_redirects=False)
    assert response.redirected_to == "https://10.0.0.5/x"
    assert opener.requests == [START]


def test_a_recorded_redirect_to_an_unsafe_destination_fails_the_source(tmp_path: Path) -> None:
    target = "https://169.254.169.254/latest/meta-data/"
    (tmp_path / "hop.json").write_bytes(b"")
    hop = {"method": "GET", "url": START, "status": 302, "headers": {"location": target}}
    hop |= {
        "redirected_to": target,
        "retrieved_at": "2026-11-04T08:00:00Z",
        "body_file": "hop.json",
    }
    (tmp_path / "hop.meta.json").write_text(json.dumps(hop), "utf-8")
    with pytest.raises(SourceFailedError, match="redirect"):
        RecordedFetcher(tmp_path).get(START)


# --- SEC-03: capped response bodies --------------------------------------------------------------

OSV = "https://api.osv.dev/v1/vulns/GHSA-x"


def test_the_default_cap_is_generous_but_finite() -> None:
    assert 16 * 2**20 <= DEFAULT_MAX_BODY_BYTES <= 1024 * 2**20


def test_a_body_at_the_cap_is_read_whole() -> None:
    body = b"x" * 100
    response = fetcher_for(Opener(lambda r: (200, body, {})), max_body_bytes=100).get(OSV)
    assert response.body == body


def test_a_body_over_the_cap_fails_the_source_and_is_not_cached() -> None:
    cache: dict = {}
    opener = Opener(lambda r: (200, b"x" * 101, {"ETag": '"v1"'}))
    fetcher = fetcher_for(opener, max_body_bytes=100, etag_cache=cache)
    with pytest.raises(SourceFailedError, match="larger than"):
        fetcher.get(OSV)
    assert cache == {}


def test_the_body_is_never_read_unbounded() -> None:
    opener = Opener(lambda r: (200, b"x" * 1000, {}))
    with pytest.raises(SourceFailedError):
        fetcher_for(opener, max_body_bytes=100).get(OSV)
    reads = opener.responses[0].reads
    assert reads and all(0 <= amount <= 101 for amount in reads)


@pytest.mark.parametrize("status", [404, 302])
def test_an_error_or_redirect_body_is_capped_too(status: int) -> None:
    opener = Opener(lambda r: (status, b"x" * 101, {"Location": "https://cdn.example.net/"}))
    with pytest.raises(SourceFailedError, match="larger than"):
        fetcher_for(opener, max_body_bytes=100).get(OSV, follow_redirects=False)


def test_no_compressed_encoding_is_asked_for() -> None:
    seen: list[urllib.request.Request] = []

    def answer(request: urllib.request.Request):
        seen.append(request)
        return 200, b"{}", {}

    fetcher_for(Opener(answer)).get(OSV)
    assert seen[0].get_header("Accept-encoding") in (None, "identity")


# --- SEC-04: fail closed on a successful body that cannot be redacted ----------------------------

SENSITIVE = {
    "crossref": "https://api.crossref.org/works/10.1/x",
    "datacite": "https://api.datacite.org/dois/10.1/x",
    "zenodo": "https://zenodo.org/api/records/1",
    "figshare": "https://api.figshare.com/v2/articles/1",
}
MALFORMED = b'{"author": [{"family": "Person"}], truncated'


@pytest.mark.parametrize("source", sorted(SENSITIVE))
def test_redact_strict_refuses_a_body_that_is_not_json(source: str) -> None:
    with pytest.raises(RedactionError):
        redact(source, MALFORMED, strict=True)
    assert redact(source, MALFORMED).body == MALFORMED  # not strict: unchanged, as before


def test_redact_strict_does_not_touch_sources_without_rules() -> None:
    assert redact("hf-hub", b"not json", strict=True).body == b"not json"
    assert redact(None, b"not json", strict=True).body == b"not json"


@pytest.mark.parametrize("source", sorted(SENSITIVE))
def test_a_malformed_successful_body_with_an_etag_is_never_cached(source: str) -> None:
    cache: dict = {}
    opener = Opener(lambda r: (200, MALFORMED, {"ETag": '"v1"'}))
    with pytest.raises(SourceFailedError):
        fetcher_for(opener, etag_cache=cache).get(SENSITIVE[source])
    assert cache == {}


def test_a_plain_text_not_found_answer_is_still_returned() -> None:
    """Crossref answers an unknown DOI with a plain-text 404; adapters read the status."""
    opener = Opener(lambda r: (404, b"Resource not found.", {}))
    response = fetcher_for(opener).get(SENSITIVE["crossref"])
    assert response.status == 404
    assert response.body == b"Resource not found."


def test_a_recorded_malformed_successful_body_fails_the_source(tmp_path: Path) -> None:
    (tmp_path / "x.json").write_bytes(MALFORMED)
    meta = {"method": "GET", "url": SENSITIVE["zenodo"], "status": 200, "headers": {}}
    meta |= {"retrieved_at": "2026-11-04T08:00:00Z", "body_file": "x.json"}
    (tmp_path / "x.meta.json").write_text(json.dumps(meta), "utf-8")
    with pytest.raises(SourceFailedError):
        RecordedFetcher(tmp_path).get(SENSITIVE["zenodo"])


# --- feature 003: bounded ranged reads (T011, research A4) ----------------------------------------

RESOLVE = "https://huggingface.co/o/n/resolve/" + "a" * 40 + "/model.safetensors"
CDN = "https://cdn.example.net/xet/abc"


def _ranged(total: bytes, *, honour: bool = True, redirect_from: str | None = RESOLVE):
    """An opener answer: a redirect from the resolve URL, then ``total`` served by range."""

    def answer(request: urllib.request.Request):
        if redirect_from is not None and request.full_url == redirect_from:
            return 302, b"", {"Location": CDN}
        wanted = request.get_header("Range")
        if not honour or wanted is None:
            return 200, total, {"Content-Length": str(len(total))}
        start, end = (int(part) for part in wanted.removeprefix("bytes=").split("-"))
        part = total[start : end + 1]
        headers = {"Content-Range": f"bytes {start}-{start + len(part) - 1}/{len(total)}"}
        return 206, part, headers | {"Content-Length": str(len(part))}

    return answer


def test_get_range_asks_for_the_first_bytes_and_follows_the_redirect() -> None:
    content = bytes(range(256)) * 100
    opener = Opener(_ranged(content))
    seen: list[str | None] = []
    inner = opener.answer
    opener.answer = lambda r: seen.append(r.get_header("Range")) or inner(r)
    response = fetcher_for(opener).get_range(RESOLVE, 1000)
    assert response.status == 206
    assert response.body == content[:1000]
    assert response.headers["Content-Range"] == f"bytes 0-999/{len(content)}"
    assert response.redirected_from == RESOLVE
    assert seen == ["bytes=0-999", "bytes=0-999"]


def test_get_range_reads_at_most_the_length_when_the_range_is_ignored() -> None:
    content = b"x" * 5000
    opener = Opener(_ranged(content, honour=False))
    response = fetcher_for(opener).get_range(RESOLVE, 1000)
    assert response.status == 200
    assert response.body == content[:1000]
    assert response.headers["Content-Length"] == "5000"
    assert sum(amount for amount in opener.responses[-1].reads if amount > 0) <= 1000


def test_get_range_checks_every_redirect_like_get() -> None:
    opener = Opener(lambda r: (302, b"", {"Location": "https://127.0.0.1/x"}))
    with pytest.raises(SourceFailedError, match="not a public host"):
        fetcher_for(opener).get_range(RESOLVE, 1000)


def test_get_range_never_writes_the_etag_cache_and_caches_by_url_and_range() -> None:
    content = b"y" * 3000
    opener = Opener(_ranged(content, redirect_from=None))
    cache: dict[str, object] = {}
    fetcher = fetcher_for(opener, etag_cache=cache)
    first = fetcher.get_range(RESOLVE, 1000)
    again = fetcher.get_range(RESOLVE, 1000)
    longer = fetcher.get_range(RESOLVE, 2000)
    assert again is first
    assert len(longer.body) == 2000
    assert len(opener.requests) == 2
    assert cache == {}


def test_get_range_cut_off_before_its_length_fails_the_source() -> None:
    """A 206 that ends before the bytes its Content-Range promises was cut off mid-read."""

    def answer(request: urllib.request.Request):
        return 206, b"z" * 10, {"Content-Range": "bytes 0-999/5000"}

    with pytest.raises(SourceFailedError, match="cut off"):
        fetcher_for(Opener(answer)).get_range(RESOLVE, 1000)


def test_get_range_returns_a_refusal_as_it_is() -> None:
    opener = Opener(lambda r: (403, b"denied", {}))
    assert fetcher_for(opener).get_range(RESOLVE, 1000).status == 403


def test_recorded_get_range_matches_the_range_key(tmp_path: Path) -> None:
    body = b"\x01" * 2048
    (tmp_path / "lead.bin").write_bytes(body)
    for name, wanted in (("a", "bytes=0-1023"), ("b", None)):
        meta = {
            "method": "GET",
            "url": RESOLVE,
            "status": 206 if wanted else 200,
            "headers": {"Content-Range": "bytes 0-1023/2048"} if wanted else {},
            "retrieved_at": "2026-11-12T00:00:00Z",
            "body_file": "lead.bin",
        }
        if wanted:
            meta["range"] = wanted
        (tmp_path / f"{name}.meta.json").write_text(json.dumps(meta), encoding="utf-8")
    recorded = RecordedFetcher(tmp_path)
    ranged = recorded.get_range(RESOLVE, 1024)
    assert ranged.status == 206 and ranged.body == body[:1024]
    assert recorded.get(RESOLVE).status == 200
    with pytest.raises(LookupError):
        recorded.get_range(RESOLVE, 512)

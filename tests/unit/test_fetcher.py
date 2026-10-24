"""Tests for the fetcher: recorded responses for tests, urllib for real use (research R8)."""

from __future__ import annotations

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
    DEFAULT_USER_AGENT,
    Fetcher,
    NoRecordingError,
    RateLimit,
    RecordedFetcher,
    Response,
    SourceFailedError,
    UrlFetcher,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "fetcher"
FIXED_NOW = datetime(2026, 10, 24, 8, 0, 0, tzinfo=UTC)


# --- test doubles -------------------------------------------------------------------------------


class FakeClock:
    """A monotonic clock that only moves when the fetcher sleeps."""

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
        self._url = url
        self.status = status
        self._body = body
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


def http_error(url: str, status: int, body: bytes = b"", headers: dict[str, str] | None = None):
    hdrs = Message()
    for key, value in (headers or {}).items():
        hdrs[key] = value
    return urllib.error.HTTPError(url, status, "error", hdrs, io.BytesIO(body))


class FakeOpener:
    """Plays back a script of results; each is (status, body, headers) or an exception."""

    def __init__(self, *script: object) -> None:
        self.script = list(script)
        self.calls: list[tuple[urllib.request.Request, float]] = []

    def __call__(self, request: urllib.request.Request, timeout: float) -> FakeHttpResponse:
        self.calls.append((request, timeout))
        item = self.script.pop(0) if len(self.script) > 1 else self.script[0]
        if isinstance(item, BaseException):
            raise item
        status, body, headers = item
        if status >= 400:
            raise http_error(request.full_url, status, body, headers)
        return FakeHttpResponse(request.full_url, status, body, headers)


def make_fetcher(
    opener: FakeOpener, clock: FakeClock | None = None, **kwargs: object
) -> UrlFetcher:
    clock = clock or FakeClock()
    return UrlFetcher(
        opener=opener,
        monotonic=clock.monotonic,
        sleep=clock.sleep,
        utcnow=lambda: FIXED_NOW,
        **kwargs,
    )


OK = (200, b'{"ok":true}', {"Content-Type": "application/json"})


# --- RecordedFetcher -----------------------------------------------------------------------------


def test_recorded_fetcher_serves_get_by_url() -> None:
    fetcher = RecordedFetcher(FIXTURES)
    response = fetcher.get("https://api.example.test/v1/items/EXAMPLE-0001")
    assert isinstance(response, Response)
    assert response.status == 200
    assert json.loads(response.body) == {"id": "EXAMPLE-0001", "summary": "recorded example"}
    assert response.url == "https://api.example.test/v1/items/EXAMPLE-0001"
    assert response.retrieved_at == datetime(2026, 10, 23, 8, 0, 0, tzinfo=UTC)
    assert response.headers["X-Example"] == "yes"


def test_recorded_fetcher_body_is_byte_exact() -> None:
    fetcher = RecordedFetcher(FIXTURES)
    response = fetcher.get("https://api.example.test/v1/items/EXAMPLE-0001")
    assert response.body == (FIXTURES / "example-get.json").read_bytes()


def test_recorded_fetcher_matches_post_by_body() -> None:
    fetcher = RecordedFetcher(FIXTURES)
    url = "https://api.example.test/v1/querybatch"
    body_a = {"queries": [{"package": {"name": "a", "ecosystem": "PyPI"}, "version": "1.0"}]}
    body_b = {"queries": [{"package": {"name": "b", "ecosystem": "PyPI"}, "version": "2.0"}]}
    a = fetcher.post(url, json.dumps(body_a).encode())
    b = fetcher.post(url, json.dumps(body_b, indent=2).encode())
    assert json.loads(a.body)["results"][0]["vulns"][0]["id"] == "EXAMPLE-0001"
    assert json.loads(b.body) == {"results": [{}]}


def test_recorded_fetcher_unknown_request_fails_loudly() -> None:
    fetcher = RecordedFetcher(FIXTURES)
    with pytest.raises(NoRecordingError):
        fetcher.get("https://api.example.test/v1/not-recorded")
    with pytest.raises(NoRecordingError):
        fetcher.post("https://api.example.test/v1/querybatch", b'{"queries": []}')
    with pytest.raises(NoRecordingError):
        fetcher.post("https://api.example.test/v1/items/EXAMPLE-0001", b"{}")


def test_recorded_fetcher_returns_error_status_as_response() -> None:
    response = RecordedFetcher(FIXTURES).get("https://api.example.test/v1/private")
    assert response.status == 401


def test_recorded_fetcher_replays_a_recorded_failure() -> None:
    fetcher = RecordedFetcher(FIXTURES)
    with pytest.raises(SourceFailedError) as info:
        fetcher.get("https://api.example.test/v1/slow")
    assert info.value.source == "api.example.test"
    assert "timed out" in info.value.reason


def test_recorded_fetcher_logs_requests() -> None:
    fetcher = RecordedFetcher(FIXTURES)
    fetcher.get("https://api.example.test/v1/items/EXAMPLE-0001")
    assert fetcher.requests == [("GET", "https://api.example.test/v1/items/EXAMPLE-0001", None)]


@pytest.mark.parametrize("fetcher_type", [RecordedFetcher, UrlFetcher])
def test_fetchers_only_read(fetcher_type: type) -> None:
    # FR-017 and research R8: GET, plus POST for read-only queries; never PUT, PATCH or DELETE.
    for method in ("put", "patch", "delete", "request"):
        assert not hasattr(fetcher_type, method)
    assert isinstance(RecordedFetcher(FIXTURES), Fetcher)
    assert isinstance(make_fetcher(FakeOpener(OK)), Fetcher)


# --- UrlFetcher ----------------------------------------------------------------------------------


def test_url_fetcher_sends_generic_user_agent() -> None:
    opener = FakeOpener(OK)
    make_fetcher(opener).get("https://api.example.test/a")
    request, _ = opener.calls[0]
    user_agent = request.get_header("User-agent")
    assert user_agent == DEFAULT_USER_AGENT
    assert user_agent.startswith("model-dependabot/")
    assert "@" not in user_agent
    assert request.get_method() == "GET"
    assert {key.lower() for key, _ in request.header_items()} <= {"user-agent", "accept"}


def test_url_fetcher_refuses_a_user_agent_with_an_email_address() -> None:
    with pytest.raises(ValueError):
        make_fetcher(FakeOpener(OK), user_agent="model-dependabot/0.1 (someone@example.org)")


def test_url_fetcher_applies_a_timeout() -> None:
    opener = FakeOpener(OK)
    make_fetcher(opener, timeout=12.5).get("https://api.example.test/a")
    assert opener.calls[0][1] == 12.5


def test_url_fetcher_response_has_body_status_url_and_time() -> None:
    response = make_fetcher(FakeOpener(OK)).get("https://api.example.test/a")
    assert response.body == b'{"ok":true}'
    assert response.status == 200
    assert response.url == "https://api.example.test/a"
    assert response.retrieved_at == FIXED_NOW
    assert response.retrieved_at.tzinfo is not None
    assert response.headers["Content-Type"] == "application/json"


def test_url_fetcher_post_sends_body() -> None:
    opener = FakeOpener(OK)
    make_fetcher(opener).post("https://api.example.test/q", b'{"q":1}')
    request, _ = opener.calls[0]
    assert request.get_method() == "POST"
    assert request.data == b'{"q":1}'
    assert request.get_header("Content-type") == "application/json"


def test_url_fetcher_retries_5xx_with_back_off() -> None:
    clock = FakeClock()
    opener = FakeOpener((503, b"", {}), (502, b"", {}), OK)
    response = make_fetcher(opener, clock, retries=3, backoff=1.0).get("https://api.example.test/a")
    assert response.status == 200
    assert len(opener.calls) == 3
    assert clock.sleeps == [1.0, 2.0]


def test_url_fetcher_honours_retry_after_on_429() -> None:
    clock = FakeClock()
    opener = FakeOpener((429, b"", {"Retry-After": "7"}), OK)
    response = make_fetcher(opener, clock, backoff=1.0).get("https://api.example.test/a")
    assert response.status == 200
    assert clock.sleeps == [7.0]


def test_url_fetcher_gives_up_after_retries_on_5xx() -> None:
    opener = FakeOpener((500, b"", {}))
    fetcher = make_fetcher(opener, retries=2)
    with pytest.raises(SourceFailedError) as info:
        fetcher.get("https://api.example.test/a")
    assert len(opener.calls) == 3
    assert info.value.source == "api.example.test"
    assert "500" in info.value.reason


def test_url_fetcher_retries_network_errors_then_fails() -> None:
    opener = FakeOpener(urllib.error.URLError("connection refused"))
    with pytest.raises(SourceFailedError):
        make_fetcher(opener, retries=1).get("https://api.example.test/a")
    assert len(opener.calls) == 2


def test_url_fetcher_returns_other_client_errors_without_retry() -> None:
    opener = FakeOpener((401, b'{"error":"unauthorised"}', {}))
    response = make_fetcher(opener).get("https://api.example.test/private")
    assert response.status == 401
    assert response.body == b'{"error":"unauthorised"}'
    assert len(opener.calls) == 1


def test_url_fetcher_caches_by_url_and_body() -> None:
    opener = FakeOpener(OK)
    fetcher = make_fetcher(opener)
    first = fetcher.get("https://api.example.test/a")
    second = fetcher.get("https://api.example.test/a")
    assert second == first
    assert len(opener.calls) == 1
    fetcher.post("https://api.example.test/q", b'{"q":1}')
    fetcher.post("https://api.example.test/q", b'{"q":1}')
    assert len(opener.calls) == 2
    fetcher.post("https://api.example.test/q", b'{"q":2}')
    assert len(opener.calls) == 3


def test_url_fetcher_does_not_cache_failures() -> None:
    opener = FakeOpener((500, b"", {}), OK)
    fetcher = make_fetcher(opener, retries=0)
    with pytest.raises(SourceFailedError):
        fetcher.get("https://api.example.test/a")
    assert fetcher.get("https://api.example.test/a").status == 200


def test_default_limits_follow_the_hugging_face_published_figures() -> None:
    # research R8: 500 API requests per five-minute window for anonymous use.
    assert DEFAULT_LIMITS["huggingface.co"] == RateLimit(requests=500, window=300.0)


def test_url_fetcher_throttles_to_the_per_source_ceiling() -> None:
    clock = FakeClock()
    opener = FakeOpener(OK)
    fetcher = make_fetcher(opener, clock, limits={"huggingface.co": RateLimit(2, 10.0)})
    for name in ("a", "b", "c"):
        fetcher.get(f"https://huggingface.co/api/models/{name}")
    assert clock.sleeps == [10.0]
    assert len(opener.calls) == 3
    # A host without a ceiling is not throttled.
    for name in ("a", "b", "c"):
        fetcher.get(f"https://api.example.test/{name}")
    assert clock.sleeps == [10.0]


def test_repeated_429s_mark_the_source_failed_for_the_run() -> None:
    opener = FakeOpener((429, b"", {"Retry-After": "1"}))
    fetcher = make_fetcher(opener, retries=5, max_429s=3)
    with pytest.raises(SourceFailedError) as info:
        fetcher.get("https://huggingface.co/api/models/a")
    assert info.value.source == "huggingface.co"
    assert len(opener.calls) == 3
    assert "huggingface.co" in fetcher.failed_sources
    # The rest of the run does not query that source again.
    with pytest.raises(SourceFailedError):
        fetcher.get("https://huggingface.co/api/models/b")
    assert len(opener.calls) == 3
    # Other sources are unaffected.
    opener.script = [OK]
    assert fetcher.get("https://api.example.test/a").status == 200
    assert "api.example.test" not in fetcher.failed_sources

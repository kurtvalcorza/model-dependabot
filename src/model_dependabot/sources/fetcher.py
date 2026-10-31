"""HTTP access for every source (research R8).

``Fetcher`` is the interface the source adapters use. ``UrlFetcher`` talks to the real sources with
the standard library; ``RecordedFetcher`` serves recorded responses so tests make no network calls
(constitution V). Both only read: they offer ``get``, ``head`` and ``post`` (for read-only queries
such as OSV's ``/v1/querybatch``) and nothing that could change a remote resource (FR-017).

Feature 002 additions (research U5, U10, U13): urllib never follows a redirect; the fetcher follows
it itself (at most ``MAX_REDIRECTS`` hops, so each hop is paced and redacted) and marks the final
answer with ``redirected_from``, which keeps feature 001's adapters working as before. A call that
must see a move (002's hub dataset and model info) passes ``follow_redirects=False`` and gets the
3xx as it is, with ``redirected_from`` and ``redirected_to``. Every body passes through the
source's redaction rule (``redact.py``) before it leaves the fetcher, so nothing personal can reach
the evidence store; each upstream source is paced at its published limit, one request at a time;
and an optional ETag cache revalidates with ``If-None-Match`` and serves a 304 from the cache.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from collections.abc import Callable, Iterable, Mapping, MutableMapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Protocol, runtime_checkable
from urllib.parse import urljoin, urlsplit

from model_dependabot import __version__
from model_dependabot.redact import RedactionError, redact, source_for_url

DEFAULT_USER_AGENT = f"model-dependabot/{__version__}"
MAX_REDIRECTS = 5


class Headers(dict[str, str]):
    """Response headers with case-insensitive lookup."""

    def __init__(self, items: Iterable[tuple[str, str]] | Mapping[str, str] = ()) -> None:
        pairs = items.items() if isinstance(items, Mapping) else items
        super().__init__((key.lower(), value) for key, value in pairs)

    def __getitem__(self, key: str) -> str:
        return super().__getitem__(key.lower())

    def __contains__(self, key: object) -> bool:
        return isinstance(key, str) and super().__contains__(key.lower())

    def get(self, key: str, default: Any = None) -> Any:  # type: ignore[override]
        return super().get(key.lower(), default)


@dataclass(frozen=True)
class Response:
    """One response from a source, with what evidence needs: body, status, URL and time."""

    status: int
    body: bytes
    url: str
    retrieved_at: datetime
    headers: Headers = field(default_factory=Headers)
    redirected_from: str | None = None
    redirected_to: str | None = None
    original_sha256: str = ""
    redacted_fields: tuple[str, ...] = ()
    not_modified: bool = False

    def __post_init__(self) -> None:
        if not self.original_sha256:
            object.__setattr__(self, "original_sha256", hashlib.sha256(self.body).hexdigest())

    @property
    def body_sha256(self) -> str:
        """The SHA-256 of the body as it may be stored (redacted where research U10 applies)."""
        return hashlib.sha256(self.body).hexdigest()


class SourceFailedError(Exception):
    """A source could not be read in this run; callers record it as ``failed`` (FR-016)."""

    def __init__(self, source: str, reason: str) -> None:
        super().__init__(f"{source}: {reason}")
        self.source = source
        self.reason = reason


class NoRecordingError(LookupError):
    """A test asked ``RecordedFetcher`` for a request that was never recorded."""


@runtime_checkable
class Fetcher(Protocol):
    """Read-only HTTP access: GET, plus POST for read-only queries."""

    def get(self, url: str, *, follow_redirects: bool = True) -> Response: ...

    def post(self, url: str, body: bytes) -> Response: ...


@dataclass(frozen=True)
class RateLimit:
    """At most ``requests`` requests in any ``window`` seconds."""

    requests: int
    window: float


# Published ceilings per host (research R8). The Hugging Face Hub documents 500 API requests per
# five-minute window for anonymous use (September 2025 figures, "subject to change"). OSV.dev states
# no limit, so it relies on the cache and back-off alone.
# Feature 002 (research U13): Crossref's anonymous public pool and Figshare allow one request a
# second, Zenodo 60 a minute for guests.
DEFAULT_LIMITS: Mapping[str, RateLimit] = {
    "huggingface.co": RateLimit(requests=500, window=300.0),
    "api.crossref.org": RateLimit(requests=1, window=1.0),
    "api.figshare.com": RateLimit(requests=1, window=1.0),
    "zenodo.org": RateLimit(requests=60, window=60.0),
}
READ_METHODS = ("GET", "HEAD", "POST")


def source_of(url: str) -> str:
    """The source a URL belongs to: its host name."""
    return urlsplit(url).hostname or url


def _canonical_body(body: object) -> str | None:
    """A comparable form of a request body: sorted compact JSON when it is JSON, else the text."""
    if body is None:
        return None
    if isinstance(body, bytes):
        body = body.decode("utf-8")
    if isinstance(body, str):
        try:
            body = json.loads(body)
        except ValueError:
            return body
    return json.dumps(body, sort_keys=True, separators=(",", ":"))


TAKEDOWNS = "hf-takedowns"


def _redacted(
    response: Response, recorded: Mapping[str, Any] | None = None, asked: str | None = None
) -> Response:
    """``response`` with its body passed through the source's redaction rule (research U10).

    A recording made redacted carries the original hash and fields in its meta file; they are kept.
    ``asked`` is the source of the URL the caller asked for: when that is the takedown log, every
    hop is redacted as the log, whatever host a redirect led to, and a body that cannot be
    redacted fails the source instead of being kept (review F4, amended 2026-10-31).
    """
    source = TAKEDOWNS if asked == TAKEDOWNS else source_for_url(response.url)
    try:
        result = redact(source, response.body)
    except RedactionError as error:
        raise SourceFailedError(source_of(response.url), str(error)) from None
    original = result.original_sha256
    fields = set(result.redacted_fields)
    if recorded:
        original = recorded.get("original_sha256") or original
        fields |= set(recorded.get("redacted_fields") or ())
    return replace(
        response, body=result.body, original_sha256=original, redacted_fields=tuple(sorted(fields))
    )


def _location(url: str, headers: Any) -> str | None:
    value = headers.get("Location") if headers is not None else None
    return urljoin(url, value) if value else None


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Makes urllib return a 3xx as an error; the fetcher decides whether to follow it (U5)."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def open_without_redirects(request: urllib.request.Request, timeout: float) -> Any:
    """The default opener: ``urlopen`` without silent redirects."""
    return urllib.request.build_opener(NoRedirectHandler()).open(request, timeout=timeout)


def _follow(
    send: Callable[[str, str, bytes | None, str | None], Response],
    method: str,
    url: str,
    body: bytes | None,
    follow_redirects: bool,
) -> Response:
    """``send`` one request and, unless the caller opts out, follow its redirects (GET and HEAD).

    Every hop is redacted under the rule of the URL asked for as well as its own (``_redacted``).
    """
    asked = source_for_url(url)
    response = send(method, url, body, asked)
    if not follow_redirects or method == "POST":
        return response
    hops = 0
    while 300 <= response.status < 400 and response.redirected_to:
        if hops >= MAX_REDIRECTS:
            raise SourceFailedError(source_of(url), f"more than {MAX_REDIRECTS} redirects")
        hops += 1
        response = send(method, response.redirected_to, None, asked)
    return replace(response, redirected_from=url) if hops else response


def _parse_time(text: str) -> datetime:
    value = datetime.fromisoformat(text.replace("Z", "+00:00"))
    return value if value.tzinfo else value.replace(tzinfo=UTC)


class RecordedFetcher:
    """Serves recorded responses, matched by method, URL and request body.

    Each recording is a ``NAME.meta.json`` file anywhere under ``root`` with ``method``, ``url``,
    an optional ``request_body`` (JSON or text), ``status``, ``headers``, ``retrieved_at`` and
    ``body_file`` (the raw response body, beside it). A recording with ``error`` instead replays a
    failed request as ``SourceFailedError``.
    """

    def __init__(self, root: Path | str) -> None:
        self.requests: list[tuple[str, str, bytes | None]] = []
        self._recordings: dict[tuple[str, str, str | None], tuple[Path, dict[str, Any]]] = {}
        for meta_path in sorted(Path(root).rglob("*.meta.json")):
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            key = (meta["method"].upper(), meta["url"], _canonical_body(meta.get("request_body")))
            if key in self._recordings:
                raise ValueError(f"two recordings for {key[0]} {key[1]}: {meta_path}")
            self._recordings[key] = (meta_path, meta)

    def get(self, url: str, *, follow_redirects: bool = True) -> Response:
        return _follow(self._serve, "GET", url, None, follow_redirects)

    def head(self, url: str, *, follow_redirects: bool = True) -> Response:
        return _follow(self._serve, "HEAD", url, None, follow_redirects)

    def post(self, url: str, body: bytes) -> Response:
        return self._serve("POST", url, body)

    def _serve(
        self, method: str, url: str, body: bytes | None, asked: str | None = None
    ) -> Response:
        self.requests.append((method, url, body))
        key = (method, url, _canonical_body(body))
        if key not in self._recordings:
            raise NoRecordingError(f"no recording for {method} {url} with this body")
        meta_path, meta = self._recordings[key]
        if "error" in meta:
            raise SourceFailedError(source_of(url), meta["error"])
        response = Response(
            status=int(meta["status"]),
            body=(meta_path.parent / meta["body_file"]).read_bytes(),
            url=url,
            retrieved_at=_parse_time(meta["retrieved_at"]),
            headers=Headers(meta.get("headers", {})),
            redirected_from=url if meta.get("redirected_to") else None,
            redirected_to=meta.get("redirected_to"),
        )
        return _redacted(response, meta, asked)


Opener = Callable[..., Any]


class UrlFetcher:
    """Fetches from the real sources with ``urllib.request``.

    Sends a generic User-Agent and nothing personal, applies a timeout, retries ``429`` and ``5xx``
    responses and network errors with exponential back-off, honours ``Retry-After``, keeps each
    host within its published ceiling and caches responses by method, URL and body. After
    ``max_429s`` consecutive ``429`` responses a host is failed for the rest of the run.
    """

    def __init__(
        self,
        *,
        user_agent: str = DEFAULT_USER_AGENT,
        timeout: float = 30.0,
        retries: int = 3,
        backoff: float = 1.0,
        max_429s: int = 3,
        max_retry_after: float = 300.0,
        limits: Mapping[str, RateLimit] | None = None,
        opener: Opener | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        utcnow: Callable[[], datetime] = lambda: datetime.now(UTC),
        etag_cache: MutableMapping[str, Response] | None = None,
    ) -> None:
        if "@" in user_agent:
            raise ValueError("the User-Agent must be generic and must not carry an email address")
        self._user_agent = user_agent
        self._timeout = timeout
        self._retries = retries
        self._backoff = backoff
        self._max_429s = max_429s
        self._max_retry_after = max_retry_after
        self._limits = dict(DEFAULT_LIMITS if limits is None else limits)
        self._opener = opener or open_without_redirects
        self._etags = etag_cache
        self._locks: dict[str, threading.Lock] = {}
        self._monotonic = monotonic
        self._sleep = sleep
        self._utcnow = utcnow
        self._cache: dict[tuple[str, str, bytes | None], Response] = {}
        self._sent: dict[str, deque[float]] = {}
        self._429s: dict[str, int] = {}
        self.failed_sources: dict[str, str] = {}

    def get(self, url: str, *, follow_redirects: bool = True) -> Response:
        return _follow(self._send, "GET", url, None, follow_redirects)

    def head(self, url: str, *, follow_redirects: bool = True) -> Response:
        return _follow(self._send, "HEAD", url, None, follow_redirects)

    def post(self, url: str, body: bytes) -> Response:
        return self._send("POST", url, body)

    def _send(
        self, method: str, url: str, body: bytes | None, asked: str | None = None
    ) -> Response:
        # One request at a time per source (research U13).
        with self._locks.setdefault(source_of(url), threading.Lock()):
            return self._send_one(method, url, body, asked)

    def _send_one(
        self, method: str, url: str, body: bytes | None, asked: str | None = None
    ) -> Response:
        source = source_of(url)
        if source in self.failed_sources:
            raise SourceFailedError(source, self.failed_sources[source])
        key = (method, url, body)
        if key in self._cache:
            return self._cache[key]

        cached = self._etags.get(url) if self._etags is not None and method == "GET" else None
        etag = cached.headers.get("ETag") if cached is not None else None

        reason = "no attempt made"
        for attempt in range(self._retries + 1):
            self._throttle(source)
            delay = self._backoff * 2**attempt
            try:
                request = self._build(method, url, body, etag=etag)
                with self._opener(request, timeout=self._timeout) as raw:
                    response = self._answer(url, raw.status, raw.read(), raw.headers, cached, asked)
                self._429s[source] = 0
                self._cache[key] = response
                return response
            except urllib.error.HTTPError as error:
                status = error.code
                reason = f"HTTP {status}"
                if status < 400:
                    response = self._answer(url, status, error.read(), error.headers, cached, asked)
                    self._cache[key] = response
                    return response
                if status == 429:
                    self._429s[source] = self._429s.get(source, 0) + 1
                    if self._429s[source] >= self._max_429s:
                        self._fail(source, f"HTTP 429 {self._429s[source]} times")
                elif status < 500:
                    response = self._answer(url, status, error.read(), error.headers, None, asked)
                    self._cache[key] = response
                    return response
                retry_after = self._retry_after(error.headers)
                if retry_after is not None:
                    if retry_after > self._max_retry_after:
                        self._fail(source, f"{reason}, asked to wait {retry_after:.0f} s")
                    delay = retry_after
            except (urllib.error.URLError, TimeoutError, OSError) as error:
                reason = f"{type(error).__name__}: {error}"
            if attempt < self._retries:
                self._sleep(delay)
        raise SourceFailedError(source, f"{reason} after {self._retries + 1} attempts")

    def _build(
        self, method: str, url: str, body: bytes | None, *, etag: str | None = None
    ) -> urllib.request.Request:
        if method not in READ_METHODS:
            raise ValueError(f"the fetcher only reads; {method} is not allowed")
        headers = {"User-Agent": self._user_agent}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if etag:
            headers["If-None-Match"] = etag
        return urllib.request.Request(url, data=body, headers=headers, method=method)

    def _response(
        self, status: int, body: bytes, url: str, headers: Any, asked: str | None = None
    ) -> Response:
        items = headers.items() if headers is not None else ()
        return _redacted(Response(status, body, url, self._utcnow(), Headers(items)), None, asked)

    def _answer(
        self,
        url: str,
        status: int,
        body: bytes,
        headers: Any,
        cached: Response | None,
        asked: str | None = None,
    ) -> Response:
        """A response as recorded: a 304 served from the ETag cache, a 3xx with its target."""
        if status == 304 and cached is not None:
            return replace(cached, retrieved_at=self._utcnow(), not_modified=True)
        response = self._response(status, body, url, headers, asked)
        if 300 <= status < 400:
            target = _location(url, headers)
            return replace(response, redirected_from=url, redirected_to=target)
        if self._etags is not None and 200 <= status < 300 and response.headers.get("ETag"):
            self._etags[url] = response
        return response

    def _fail(self, source: str, reason: str) -> None:
        self.failed_sources[source] = reason
        raise SourceFailedError(source, reason)

    def _retry_after(self, headers: Any) -> float | None:
        value = headers.get("Retry-After") if headers is not None else None
        if not value:
            return None
        try:
            return max(0.0, float(value))
        except ValueError:
            pass
        try:
            when = parsedate_to_datetime(value)
        except (TypeError, ValueError):
            return None
        return max(0.0, (when - self._utcnow()).total_seconds())

    def _throttle(self, source: str) -> None:
        limit = self._limits.get(source)
        if limit is None:
            return
        sent = self._sent.setdefault(source, deque())
        now = self._monotonic()
        while sent and sent[0] <= now - limit.window:
            sent.popleft()
        if len(sent) >= limit.requests:
            self._sleep(sent[0] + limit.window - now)
            now = self._monotonic()
            while sent and sent[0] <= now - limit.window:
                sent.popleft()
        sent.append(now)

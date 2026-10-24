"""HTTP access for every source (research R8).

``Fetcher`` is the interface the source adapters use. ``UrlFetcher`` talks to the real sources with
the standard library; ``RecordedFetcher`` serves recorded responses so tests make no network calls
(constitution V). Both only read: they offer ``get`` and ``post`` (for read-only queries such as
OSV's ``/v1/querybatch``) and nothing that could change a remote resource (FR-017).
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from collections import deque
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Protocol, runtime_checkable
from urllib.parse import urlsplit

from model_dependabot import __version__

DEFAULT_USER_AGENT = f"model-dependabot/{__version__}"


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

    def get(self, url: str) -> Response: ...

    def post(self, url: str, body: bytes) -> Response: ...


@dataclass(frozen=True)
class RateLimit:
    """At most ``requests`` requests in any ``window`` seconds."""

    requests: int
    window: float


# Published ceilings per host (research R8). The Hugging Face Hub documents 500 API requests per
# five-minute window for anonymous use (September 2025 figures, "subject to change"). OSV.dev states
# no limit, so it relies on the cache and back-off alone.
DEFAULT_LIMITS: Mapping[str, RateLimit] = {"huggingface.co": RateLimit(requests=500, window=300.0)}


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

    def get(self, url: str) -> Response:
        return self._serve("GET", url, None)

    def post(self, url: str, body: bytes) -> Response:
        return self._serve("POST", url, body)

    def _serve(self, method: str, url: str, body: bytes | None) -> Response:
        self.requests.append((method, url, body))
        key = (method, url, _canonical_body(body))
        if key not in self._recordings:
            raise NoRecordingError(f"no recording for {method} {url} with this body")
        meta_path, meta = self._recordings[key]
        if "error" in meta:
            raise SourceFailedError(source_of(url), meta["error"])
        return Response(
            status=int(meta["status"]),
            body=(meta_path.parent / meta["body_file"]).read_bytes(),
            url=url,
            retrieved_at=_parse_time(meta["retrieved_at"]),
            headers=Headers(meta.get("headers", {})),
        )


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
        self._opener = opener or urllib.request.urlopen
        self._monotonic = monotonic
        self._sleep = sleep
        self._utcnow = utcnow
        self._cache: dict[tuple[str, str, bytes | None], Response] = {}
        self._sent: dict[str, deque[float]] = {}
        self._429s: dict[str, int] = {}
        self.failed_sources: dict[str, str] = {}

    def get(self, url: str) -> Response:
        return self._send("GET", url, None)

    def post(self, url: str, body: bytes) -> Response:
        return self._send("POST", url, body)

    def _send(self, method: str, url: str, body: bytes | None) -> Response:
        source = source_of(url)
        if source in self.failed_sources:
            raise SourceFailedError(source, self.failed_sources[source])
        key = (method, url, body)
        if key in self._cache:
            return self._cache[key]

        reason = "no attempt made"
        for attempt in range(self._retries + 1):
            self._throttle(source)
            delay = self._backoff * 2**attempt
            try:
                with self._opener(self._build(method, url, body), timeout=self._timeout) as raw:
                    response = self._response(raw.status, raw.read(), raw.geturl(), raw.headers)
                self._429s[source] = 0
                self._cache[key] = response
                return response
            except urllib.error.HTTPError as error:
                status = error.code
                reason = f"HTTP {status}"
                if status == 429:
                    self._429s[source] = self._429s.get(source, 0) + 1
                    if self._429s[source] >= self._max_429s:
                        self._fail(source, f"HTTP 429 {self._429s[source]} times")
                elif status < 500:
                    response = self._response(status, error.read(), url, error.headers)
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

    def _build(self, method: str, url: str, body: bytes | None) -> urllib.request.Request:
        if method not in ("GET", "POST"):
            raise ValueError(f"the fetcher only reads; {method} is not allowed")
        headers = {"User-Agent": self._user_agent}
        if body is not None:
            headers["Content-Type"] = "application/json"
        return urllib.request.Request(url, data=body, headers=headers, method=method)

    def _response(self, status: int, body: bytes, url: str, headers: Any) -> Response:
        items = headers.items() if headers is not None else ()
        return Response(status, body, url, self._utcnow(), Headers(items))

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

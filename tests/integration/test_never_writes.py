"""The service never writes to a model, its files or its repository (T054a; FR-017).

Constitution III. Feature 002 (T056a) extends it to the upstream sources: every request is a
``GET`` or ``HEAD`` and none carries an ``Authorization`` header or a token (FR-002).

The worked example (``tests/fixtures/manifests/example.toml``) is copied into ``tmp_path`` with its
weight files; its lock is replaced by the recorded affected-pillow lock so that ``check`` raises an
alert to dismiss. A spying fetcher wraps the recordings and logs every request: none may be
``PUT``, ``PATCH`` or ``DELETE`` and the only ``POST`` is OSV's read-only ``/v1/querybatch``. The
SHA-256 and modification time of every local weight file, the manifest and the lock are unchanged
after ``register`` and after ``check``.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

import pytest

from model_dependabot.cli import EXIT_OK, main, make_handlers
from model_dependabot.sources.fetcher import RecordedFetcher, Response, UrlFetcher

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
MODEL = "example-detector"
OSV_QUERYBATCH = "https://api.osv.dev/v1/querybatch"


class SpyFetcher:
    """Logs every request, then answers it from the recordings."""

    def __init__(self, inner: RecordedFetcher) -> None:
        self.inner = inner
        self.log: list[tuple[str, str]] = []

    def get(self, url: str, *, follow_redirects: bool = True) -> Response:
        self.log.append(("GET", url))
        return self.inner.get(url, follow_redirects=follow_redirects)

    def post(self, url: str, body: bytes) -> Response:
        self.log.append(("POST", url))
        return self.inner.post(url, body)


def _state(paths: list[Path]) -> dict[str, tuple[str, int]]:
    return {
        path.name: (hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_mtime_ns)
        for path in paths
    }


@pytest.fixture
def example(tmp_path: Path) -> tuple[Path, list[Path]]:
    model = tmp_path / "model"
    shutil.copytree(FIXTURES / "manifests" / "weights", model / "weights")
    shutil.copy(FIXTURES / "locks" / "vulnerable.txt", model / "requirements.txt")
    text = (FIXTURES / "manifests" / "example.toml").read_text("utf-8")
    text = text.replace('lock = "../locks/uv-export-trimmed.txt"', 'lock = "requirements.txt"')
    manifest = model / "example.toml"
    manifest.write_text(text, encoding="utf-8")
    watched = [manifest, model / "requirements.txt", *sorted((model / "weights").iterdir())]
    return manifest, watched


def test_no_command_writes_to_a_model_or_its_repository(
    example: tuple[Path, list[Path]], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    manifest, watched = example
    recordings = tmp_path / "recordings"
    shutil.copytree(FIXTURES / "hf", recordings)
    shutil.copytree(FIXTURES / "osv", recordings, dirs_exist_ok=True)
    # The upstream watch asks the hub about the base model (its licence, FR-008).
    shutil.copytree(FIXTURES / "hf_upstream", recordings, dirs_exist_ok=True)
    spy = SpyFetcher(RecordedFetcher(recordings))
    handlers = make_handlers(fetcher=spy)
    db = tmp_path / "db" / "md.db"

    def cli(*argv: str) -> tuple[int, Any]:
        code = main([*argv, "--db", str(db), "--json"], handlers=handlers)
        out = capsys.readouterr().out
        return code, json.loads(out) if out.strip() else None

    before = _state(watched)
    assert cli("register", str(manifest))[0] == EXIT_OK
    assert _state(watched) == before

    code, _ = cli("check", MODEL)
    assert code == EXIT_OK
    assert _state(watched) == before

    assert cli("policy", MODEL, "--format", "strict", "--by", "Owner")[0] == EXIT_OK
    _, listed = cli("alerts", MODEL)
    assert listed["alerts"], "the affected pillow raises an alert to dismiss"
    first = listed["alerts"][0]["alert_id"]
    reason = ["--reason", "risk_accepted", "--by", "Owner"]
    assert cli("alert", "dismiss", str(first), *reason)[0] == EXIT_OK
    out = tmp_path / "export" / "bom.json"
    out.parent.mkdir()
    assert cli("inventory", "export", MODEL, "-o", str(out))[0] == EXIT_OK
    assert _state(watched) == before

    methods = {method for method, _ in spy.log}
    assert spy.log, "the commands consulted the sources"
    assert methods <= {"GET", "POST"}
    assert {url for method, url in spy.log if method == "POST"} == {OSV_QUERYBATCH}
    # Hub requests are reads of the public API only.
    hub = [url for _, url in spy.log if "huggingface.co" in url]
    assert hub and all(url.startswith("https://huggingface.co/api/models/") for url in hub)


def test_the_real_fetcher_can_only_read() -> None:
    """``UrlFetcher`` has no way to send ``PUT``, ``PATCH`` or ``DELETE``."""
    for name in ("put", "patch", "delete", "request"):
        assert not hasattr(UrlFetcher, name)
    assert {"get", "post"} <= set(dir(UrlFetcher))


# --- Feature 002 (T056a; FR-002, FR-017, constitution III) -------------------------------------

UPSTREAM_HOSTS = {
    "https://doi.org/doiRA/": "doiRA",
    "https://api.crossref.org/": "Crossref",
    "https://api.datacite.org/": "DataCite",
    "https://zenodo.org/api/": "Zenodo",
    "https://api.figshare.com/": "Figshare",
    "https://huggingface.co/api/": "the hub",
    "https://huggingface.co/datasets/huggingface-legal/takedown-notices/": "the takedown log",
}


class HeadSpyFetcher(SpyFetcher):
    """Also logs ``HEAD`` requests, which the upstream readers may send."""

    def head(self, url: str, *, follow_redirects: bool = True) -> Response:
        self.log.append(("HEAD", url))
        return self.inner.head(url, follow_redirects=follow_redirects)


def test_register_and_scheduled_check_only_read_every_upstream_source(
    tmp_path: Path, derive_upstream: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    from test_source_failure_upstream import LOG, figshare_extra, manifest

    root = derive_upstream(changes={"hf_takedowns/index": lambda _: LOG}, extra=figshare_extra())
    spy = HeadSpyFetcher(RecordedFetcher(root))
    handlers = make_handlers(fetcher=spy)
    db = tmp_path / "db" / "md.db"
    path = manifest(tmp_path / "model")
    before = _state([path])
    for argv in (("register", str(path)), ("check", "--all", "--scheduled")):
        code = main([*argv, "--db", str(db), "--json"], handlers=handlers)
        capsys.readouterr()
        assert code == EXIT_OK
    assert _state([path]) == before
    asked = {
        name for prefix, name in UPSTREAM_HOSTS.items() for _, u in spy.log if u.startswith(prefix)
    }
    assert asked == set(UPSTREAM_HOSTS.values())
    upstream = [(m, u) for m, u in spy.log if any(u.startswith(p) for p in UPSTREAM_HOSTS)]
    assert {method for method, _ in upstream} <= {"GET", "HEAD"}
    for _, url in upstream:
        assert not any(word in url.lower() for word in ("token", "authorization", "api_key"))


def test_the_real_fetcher_sends_no_authorization_header() -> None:
    """FR-002: anonymous reads; the only request headers are the generic User-Agent and ETag."""
    sent: list[Any] = []

    def opener(request: Any, timeout: float) -> Any:
        sent.append(request)
        raise OSError("no network in the default run")

    fetcher = UrlFetcher(opener=opener, retries=0, sleep=lambda _: None)
    for read in (fetcher.get, fetcher.head):
        with pytest.raises(Exception):  # noqa: B017 - the opener refuses every request
            read("https://huggingface.co/api/models/openai-community/gpt2")
    assert sent
    for request in sent:
        assert request.get_method() in ("GET", "HEAD")
        names = {name.lower() for name in request.header_items() for name in [name[0]]}
        assert "authorization" not in names
        assert names <= {"user-agent", "if-none-match"}

"""The service never writes to a model, its files or its repository (T054a; FR-017).

Constitution III.

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

    def get(self, url: str) -> Response:
        self.log.append(("GET", url))
        return self.inner.get(url)

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

"""Shared test configuration.

Constitution V: the default test run makes no network calls. Every test not marked ``live`` runs
with socket connections and name resolution blocked, so an accidental network call fails loudly.
"""

from __future__ import annotations

import json
import shutil
import socket
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest


class NetworkBlockedError(RuntimeError):
    """Raised when a test not marked ``live`` tries to use the network."""


def _blocked(*args: object, **kwargs: object) -> None:
    raise NetworkBlockedError(
        "network access is blocked in tests; mark the test 'live' if it needs a real source"
    )


@pytest.fixture(autouse=True)
def _block_network(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    if request.node.get_closest_marker("live") is not None:
        return
    monkeypatch.setattr(socket.socket, "connect", _blocked)
    monkeypatch.setattr(socket.socket, "connect_ex", _blocked)
    monkeypatch.setattr(socket, "create_connection", _blocked)
    monkeypatch.setattr(socket, "getaddrinfo", _blocked)


FIXTURES = Path(__file__).resolve().parent / "fixtures"
OSV_FIXTURES = FIXTURES / "osv"

Change = Callable[[Any], Any]


@pytest.fixture
def derive_osv(tmp_path: Path) -> Callable[..., Path]:
    """Copy the recorded OSV fixtures into a new directory and change some bodies.

    ``changes`` maps a recording name (``vuln-GHSA-…``) to a function from the parsed body to the
    new body; ``errors`` maps a recording name to a failure reason, so ``RecordedFetcher`` replays a
    failed request (FR-016). Every derived state is therefore written out in the test that uses it.
    """
    counter = iter(range(1000))

    def derive(
        changes: dict[str, Change] | None = None, errors: dict[str, str] | None = None
    ) -> Path:
        root = tmp_path / f"osv-derived-{next(counter)}"
        shutil.copytree(OSV_FIXTURES, root)
        for name, change in (changes or {}).items():
            body = root / f"{name}.json"
            body.write_text(json.dumps(change(json.loads(body.read_text("utf-8")))), "utf-8")
        for name, reason in (errors or {}).items():
            meta_path = root / f"{name}.meta.json"
            meta = json.loads(meta_path.read_text("utf-8"))
            for key in ("status", "headers", "body_file", "trimmed"):
                meta.pop(key, None)
            meta["error"] = reason
            meta_path.write_text(json.dumps(meta), "utf-8")
        return root

    return derive

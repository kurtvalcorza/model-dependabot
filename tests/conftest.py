"""Shared test configuration.

Constitution V: the default test run makes no network calls. Every test not marked ``live`` runs
with socket connections and name resolution blocked, so an accidental network call fails loudly.
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import socket
import sqlite3
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
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


_connect = sqlite3.connect


def _connect_unsynced(*args: Any, **kwargs: Any) -> sqlite3.Connection:
    connection = _connect(*args, **kwargs)
    connection.execute("PRAGMA synchronous = OFF")
    return connection


@pytest.fixture(autouse=True)
def _unsynced_sqlite(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test speed only: the store's database skips the disk sync on each commit in tests.

    Production opens it with SQLite's default (``synchronous = FULL``); nothing the tests assert
    depends on durability across a power loss.
    """
    monkeypatch.setattr(sqlite3, "connect", _connect_unsynced)


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


PICKLE_FIXTURES = FIXTURES / "pickles"
HF_FIXTURES = FIXTURES / "hf"
EICAR_REPO = "mcpotato/42-eicar-street"
EICAR_COMMIT = "8fb61c4d511e9aaff0ea55396a124aa292830efc"
EICAR_BIN_SHA256 = "f9343d7d7ec5c3d8bcced056c438fc9f1d3819e9ca3d42418a40857050e10e20"


def _load_craft() -> ModuleType:
    spec = importlib.util.spec_from_file_location("craft_pickles", PICKLE_FIXTURES / "craft.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def craft() -> ModuleType:
    """The pickle fixture builder (``tests/fixtures/pickles/craft.py``); nothing it builds is
    ever loaded. Dangerous fixtures are built from it into ``tmp_path`` only."""
    return _load_craft()


@pytest.fixture
def derive_hf(tmp_path: Path) -> Callable[..., Path]:
    """Recordings for the hub's security status, from the real ones in ``tests/fixtures/hf``.

    ``security`` and ``tree`` change the parsed bodies of ``eicar-security`` (``GET
    /api/models/{repo}?securityStatus=true``) and ``eicar-tree-expand`` (the tree at the verdict's
    commit with ``expand=true``); ``errors`` maps either name to a failure reason. The tree and
    revision answers that registering a file of that repository needs are derived from the same
    two recordings (the expanded tree without ``securityFileStatus``; the model info's ``sha``),
    so every derived state is written out in the test that uses it.
    """
    counter = iter(range(1000))

    def derive(
        security: Change | None = None,
        tree: Change | None = None,
        errors: dict[str, str] | None = None,
    ) -> Path:
        root = tmp_path / f"hf-derived-{next(counter)}"
        root.mkdir()
        for name in ("eicar-security", "eicar-tree-expand", "gpt2-security"):
            for suffix in (".json", ".meta.json"):
                shutil.copy(HF_FIXTURES / f"{name}{suffix}", root / f"{name}{suffix}")
        expanded = json.loads((root / "eicar-tree-expand.json").read_text("utf-8"))
        plain = [{k: v for k, v in item.items() if k != "securityFileStatus"} for item in expanded]
        info = json.loads((root / "eicar-security.json").read_text("utf-8"))
        api = f"https://huggingface.co/api/models/{EICAR_REPO}"
        for name, url, body in (
            ("eicar-tree", f"{api}/tree/{EICAR_COMMIT}", plain),
            ("eicar-revision", f"{api}/revision/{EICAR_COMMIT}", info),
        ):
            (root / f"{name}.json").write_text(json.dumps(body), "utf-8")
            meta = {"method": "GET", "url": url, "status": 200, "headers": {}}
            meta |= {"retrieved_at": "2026-10-24T04:11:44Z", "body_file": f"{name}.json"}
            (root / f"{name}.meta.json").write_text(json.dumps(meta), "utf-8")
        for name, change in (("eicar-security", security), ("eicar-tree-expand", tree)):
            if change is not None:
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

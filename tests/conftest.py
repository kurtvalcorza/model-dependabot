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


UPSTREAM_DIRS = (
    "crossref",
    "datacite",
    "zenodo",
    "figshare",
    "doi_ra",
    "hf_upstream",
    "hf_takedowns",
)
UPSTREAM_TIME = "2026-10-24T06:00:00Z"
TextChange = Callable[[Any], Any]


@pytest.fixture
def derive_upstream(tmp_path: Path) -> Callable[..., Path]:
    """Recordings for the upstream sources, from the real ones under ``tests/fixtures``.

    The recordings of ``UPSTREAM_DIRS`` are copied into a new directory. ``changes`` maps a
    recording name (``crossref/retracted``) to a function from its parsed body (JSON, or text for
    any other body) to the new body; ``errors`` maps a name to a failure reason, so
    ``RecordedFetcher`` replays a failed request (FR-018); ``extra`` adds recordings, each
    ``{"url", "status", "body"}`` plus an optional ``redirected_to``, for states no recording has
    (a recorded body moved to another identifier); an extra recording replaces a copied one of the
    same URL. Every derived state is written out in the test that uses it.
    """
    counter = iter(range(1000))

    def derive(
        changes: dict[str, TextChange] | None = None,
        errors: dict[str, str] | None = None,
        extra: dict[str, dict[str, Any]] | None = None,
    ) -> Path:
        root = tmp_path / f"upstream-derived-{next(counter)}"
        for name in UPSTREAM_DIRS:
            shutil.copytree(FIXTURES / name, root / name, ignore=shutil.ignore_patterns("*.md"))
        for name, change in (changes or {}).items():
            meta_path = root / f"{name}.meta.json"
            meta = json.loads(meta_path.read_text("utf-8"))
            body = meta_path.parent / meta["body_file"]
            text = body.read_text("utf-8")
            if body.suffix == ".json":
                body.write_text(json.dumps(change(json.loads(text))), "utf-8")
            else:
                body.write_text(change(text), "utf-8")
            for key in ("original_sha256", "body_sha256"):
                meta.pop(key, None)
            meta_path.write_text(json.dumps(meta), "utf-8")
        for name, reason in (errors or {}).items():
            meta_path = root / f"{name}.meta.json"
            meta = json.loads(meta_path.read_text("utf-8"))
            for key in ("status", "headers", "body_file", "trimmed"):
                meta.pop(key, None)
            meta["error"] = reason
            meta_path.write_text(json.dumps(meta), "utf-8")
        replaced = {spec["url"] for spec in (extra or {}).values()}
        for meta_path in list(root.rglob("*.meta.json")) if replaced else []:
            meta = json.loads(meta_path.read_text("utf-8"))
            if meta["url"] in replaced:
                body_file = meta.get("body_file")
                if body_file:
                    (meta_path.parent / body_file).unlink()
                meta_path.unlink()
        for name, spec in (extra or {}).items():
            path = root / "extra" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            body = spec["body"]
            if not isinstance(body, (str, bytes)):
                body = json.dumps(body)
            raw = body.encode("utf-8") if isinstance(body, str) else body
            (path.parent / f"{path.name}.body").write_bytes(raw)
            meta = {"method": "GET", "url": spec["url"], "status": spec["status"], "headers": {}}
            meta |= {"retrieved_at": spec.get("retrieved_at", UPSTREAM_TIME)}
            meta |= {"body_file": f"{path.name}.body"}
            if spec.get("redirected_to"):
                meta["redirected_to"] = spec["redirected_to"]
            (path.parent / f"{path.name}.meta.json").write_text(json.dumps(meta), "utf-8")
        return root

    return derive


def fixture_json(name: str) -> Any:
    """The parsed body of a recording under ``tests/fixtures`` (``crossref/retracted``)."""
    meta = json.loads((FIXTURES / f"{name}.meta.json").read_text("utf-8"))
    return json.loads((FIXTURES / name).parent.joinpath(meta["body_file"]).read_text("utf-8"))


# --- feature 003: recorded hub trees and ranged reads (tests/fixtures/format_check/NOTES.md) ------

FORMAT_CHECK_FIXTURES = FIXTURES / "format_check"
LEAD_RANGE = "bytes=0-1048575"
GPT2_REPO = "openai-community/gpt2"
GPT2_COMMIT = "607a30d783dfa663caf39e06633721c8d4cfcd7e"
GPT2_SAFETENSORS = "248dfc3911869ec493c76e65bf2fcf7f615828b0254c12b473182f0f81d3a707"
GPT2_PICKLE = "7c5d3f4b8b76583b422fcb9189ad6c89d5d97a094541ce8932dce3ecabde1421"
GGUF_REPO = "TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF"
GGUF_COMMIT = "52e7645ba7c309695bec7ac98f4f005b139cf465"
GGUF_FILE = "tinyllama-1.1b-chat-v1.0.Q2_K.gguf"
GGUF_SHA256 = "030a469a63576d59f601ef5608846b7718eaa884dd820e9aa7493efec1788afa"
ZIP_REPO = "hf-internal-testing/tiny-random-bert"
ZIP_COMMIT = "f171d7baecaf37b5da5a3616d8833b9969753535"
ZIP_SHA256 = "9922e8996d0c7e24c7f4e7a5d9c5b7303549f4ee94de0f1138b103014b51be13"
GATED_REPO = "hf-internal-testing/dummy-gated-model"
GATED_COMMIT = "9a039e123af345a94ba89c5e4cc3a0f6dac50bd9"
# A repository that exists only in derived recordings: its ``model.safetensors`` is listed with the
# hash of gpt2's pickle and serves that pickle's recorded first bytes (a forged code-free claim).
FORGED_REPO = "model-dependabot-fixture/forged"
FORGED_COMMIT = "f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0"


def resolve(repo: str, commit: str, file: str) -> str:
    return f"https://huggingface.co/{repo}/resolve/{commit}/{file}"


def tree_url(repo: str, commit: str) -> str:
    return f"https://huggingface.co/api/models/{repo}/tree/{commit}"


def recorded_body(name: str) -> bytes:
    """The body of a recording in ``tests/fixtures/format_check``."""
    meta = json.loads((FORMAT_CHECK_FIXTURES / f"{name}.meta.json").read_text("utf-8"))
    return (FORMAT_CHECK_FIXTURES / meta["body_file"]).read_bytes()


def tree_item(path: str, sha256: str | None, size: int) -> dict[str, Any]:
    item: dict[str, Any] = {"type": "file", "oid": "0" * 40, "size": size, "path": path}
    if sha256 is not None:
        item["lfs"] = {"oid": sha256, "size": size, "pointerSize": 134}
    return item


@pytest.fixture
def derive_format_check(tmp_path: Path) -> Callable[..., Path]:
    """The recorded ``format_check`` answers plus derived ones, written out by the test.

    ``extra`` maps a name to ``{"url", "status", "body"}`` with optional ``headers``, ``range``
    (default the 1 MiB lead; ``None`` for an unranged request such as a tree), ``redirected_to``
    and ``error`` (a failed request, replayed as ``SourceFailedError``). An extra recording
    replaces a copied one with the same URL and range. ``forged`` adds the forged repository: a
    tree listing ``model.safetensors`` with gpt2's pickle hash, and that pickle's recorded lead
    served for it.
    """
    counter = iter(range(1000))

    def derive(extra: dict[str, dict[str, Any]] | None = None, *, forged: bool = True) -> Path:
        root = tmp_path / f"format-check-{next(counter)}"
        shutil.copytree(FORMAT_CHECK_FIXTURES, root, ignore=shutil.ignore_patterns("*.md"))
        specs = dict(extra or {})
        if forged:
            pickle = json.loads(
                (FORMAT_CHECK_FIXTURES / "gpt2-pickle-range-1.meta.json").read_text()
            )
            forged_specs = {
                "forged-tree": {
                    "url": tree_url(FORGED_REPO, FORGED_COMMIT),
                    "status": 200,
                    "range": None,
                    "body": json.dumps([tree_item("model.safetensors", GPT2_PICKLE, 548_118_077)]),
                },
                "forged-range": {
                    "url": resolve(FORGED_REPO, FORGED_COMMIT, "model.safetensors"),
                    "status": 206,
                    "headers": pickle["headers"],
                    "body": recorded_body("gpt2-pickle-range-1"),
                },
            }
            specs = forged_specs | specs
        replaced = {(spec["url"], spec.get("range", LEAD_RANGE)) for spec in specs.values()}
        for meta_path in list(root.glob("*.meta.json")):
            meta = json.loads(meta_path.read_text("utf-8"))
            if (meta["url"], meta.get("range")) in replaced:
                (root / meta["body_file"]).unlink()
                meta_path.unlink()
        for name, spec in specs.items():
            meta: dict[str, Any] = {"method": "GET", "url": spec["url"]}
            wanted = spec.get("range", LEAD_RANGE)
            if wanted is not None:
                meta["range"] = wanted
            if "error" in spec:
                meta |= {"error": spec["error"], "retrieved_at": UPSTREAM_TIME}
            else:
                body = spec["body"]
                raw = body.encode("utf-8") if isinstance(body, str) else body
                (root / f"{name}.body").write_bytes(raw)
                meta |= {"status": spec["status"], "headers": spec.get("headers", {})}
                meta |= {"retrieved_at": spec.get("retrieved_at", UPSTREAM_TIME)}
                meta["body_file"] = f"{name}.body"
                if spec.get("redirected_to"):
                    meta["redirected_to"] = spec["redirected_to"]
            (root / f"{name}.meta.json").write_text(json.dumps(meta), "utf-8")
        return root

    return derive

"""Candidates compared with each other and with a manifest (T038; FR-019)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from model_dependabot.discover.candidate import candidate
from model_dependabot.discover.compare import compare, mark_version_conflicts
from model_dependabot.manifest import load_manifest

NOW = "2026-11-13T00:00:00Z"
DECLARED = "declared-but-unverified"


def package(name: str, version: str | None, file: str, gaps: list[str] | None = None):
    identity = {"name": name, "version": version, "hashes": []}
    return candidate("package", identity, {"file": file, "line": 1}, DECLARED, NOW, gaps)


def weight(path: str) -> dict[str, Any]:
    identity = {"path": path, "sha256": "a" * 64, "size": 1, "format": "pickle"}
    return candidate("weight_file", identity, {"file": path}, "verified", NOW)


def base(repo: str) -> dict[str, Any]:
    identity = {"hub_repo": repo, "revision": None}
    origin = {"file": "README.md", "key": "base_model"}
    return candidate("base_model", identity, origin, DECLARED, NOW, ["no revision"])


def dataset(repo: str) -> dict[str, Any]:
    origin = {"file": "README.md", "key": "datasets"}
    return candidate("dataset", {"hub_repo": repo}, origin, DECLARED, NOW, ["no revision"])


def environment(lock: str) -> dict[str, Any]:
    return candidate("environment", {"lock": lock, "packages": 1}, {"file": lock}, DECLARED, NOW)


def manifest(root: Path, text: str):
    path = root / "model.toml"
    path.write_text('[model]\nid = "m"\n' + text, encoding="utf-8")
    return load_manifest(path, weights_present=False)


def test_two_files_with_different_versions_both_conflict() -> None:
    items = [
        package("numpy", "2.1.0", "requirements.lock.txt"),
        package("numpy", "2.0.2", "requirements-dev.txt", ["not locked"]),
        package("numpy", None, "pyproject.toml", ["not locked"]),
        package("torch", "2.5.1", "requirements.lock.txt"),
    ]
    mark_version_conflicts(items)
    assert [item["status"] for item in items] == [
        "conflicting",
        "conflicting",
        DECLARED,
        DECLARED,
    ]
    assert items[0]["note"] == "declared at versions 2.0.2, 2.1.0"


def test_weights_match_miss_and_are_not_seen(tmp_path: Path) -> None:
    items = [weight("runs/best.pt"), weight("extra.pt")]
    text = (
        '[[weights]]\npath = "runs/best.pt"\n'
        '[[weights]]\npath = "gone.pt"\n'
        '[[weights]]\nhub = "hf:org/repo"\nfile = "model.safetensors"\n'
    )
    not_seen = compare(items, manifest(tmp_path, text), tmp_path)
    assert [item["manifest"] for item in items] == ["matches", "missing_from_manifest"]
    assert {item["identity"].get("path") or item["identity"]["hub_repo"] for item in not_seen} == {
        "gone.pt",
        "org/repo",
    }


def test_a_different_base_model_conflicts_with_the_manifest_value(tmp_path: Path) -> None:
    item = base("org/base")
    not_seen = compare([item], manifest(tmp_path, '[base_model]\nhub = "hf:org/other"\n'), tmp_path)
    assert item["manifest"] == "conflicts"
    assert item["manifest_value"] == {"hub_repo": "org/other"}
    assert not_seen == []


def test_a_matching_base_model_takes_the_manifest_revision(tmp_path: Path) -> None:
    item = base("Org/Base")
    text = '[base_model]\nhub = "hf:org/base"\nrevision = "' + "c" * 40 + '"\n'
    compare([item], manifest(tmp_path, text), tmp_path)
    assert item["manifest"] == "matches"
    assert item["gaps"] == []
    assert item["manifest_value"]["revision"] == "c" * 40


def test_a_manifest_base_model_discovery_did_not_see(tmp_path: Path) -> None:
    not_seen = compare([], manifest(tmp_path, '[base_model]\nhub = "hf:org/other"\n'), tmp_path)
    assert not_seen == [
        {
            "kind": "base_model",
            "identity": {"hub_repo": "org/other", "revision": None},
            "origin": {"key": "base_model"},
        }
    ]


def test_the_lock_and_its_packages(tmp_path: Path) -> None:
    lock = environment("requirements.lock.txt")
    other = environment("other.lock.txt")
    locked = package("torch", "2.5.1", "requirements.lock.txt")
    same = package("torch", "2.5.1", "requirements-dev.txt", ["not locked"])
    newer = package("torch", "2.6.0", "requirements-dev.txt", ["not locked"])
    loose = package("scipy", None, "pyproject.toml", ["not locked"])
    items = [lock, other, locked, same, newer, loose]
    (tmp_path / "requirements.lock.txt").write_text("", encoding="utf-8")
    compare(items, manifest(tmp_path, '[environment]\nlock = "requirements.lock.txt"\n'), tmp_path)
    assert [item["manifest"] for item in items] == [
        "matches",
        "conflicts",
        "matches",
        "matches",
        "conflicts",
        "missing_from_manifest",
    ]
    assert other["manifest_value"] == {"lock": "requirements.lock.txt"}
    assert newer["manifest_value"] == {"name": "torch", "version": "2.5.1"}


def test_datasets_and_licences(tmp_path: Path) -> None:
    seen, extra = dataset("org/data"), dataset("org/extra")
    licence = candidate(
        "licence", {"licence": "mit", "spdx": "MIT"}, {"file": "README.md"}, DECLARED, NOW
    )
    text = (
        '[[datasets]]\nhub = "hf:datasets/org/data"\nrevision = "' + "d" * 40 + '"\n'
        '[[datasets]]\ndoi = "10.5555/example"\n'
    )
    not_seen = compare([seen, extra, licence], manifest(tmp_path, text), tmp_path)
    assert (seen["manifest"], extra["manifest"]) == ("matches", "missing_from_manifest")
    assert licence["manifest"] == "missing_from_manifest"
    assert not_seen == [
        {
            "kind": "dataset",
            "identity": {"doi": "10.5555/example"},
            "origin": {"key": "datasets[1]"},
        }
    ]


def test_a_manifest_path_outside_the_project_is_not_seen(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    not_seen = compare([], manifest(root, '[[weights]]\npath = "../elsewhere.pt"\n'), root)
    assert not_seen[0]["reason"] == "outside the project"

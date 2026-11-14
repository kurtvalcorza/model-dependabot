"""The safe list of pickle globals and its loader (T028, FR-009, research S3, S14)."""

from __future__ import annotations

from pathlib import Path

import pytest

from model_dependabot.assurance import globals_policy

# The SHA-256 of each version's entries (``globals_policy.entries_sha256``). A change to the entries
# without a new ``version`` fails here; a new version adds its line.
ENTRIES_SHA256 = {
    1: "1b6121c15719d71d8326544413559d2866fab8badd90a8c583f23a7a96c206d0",
}


def _write(tmp_path: Path, entries: str, version: int = 1) -> Path:
    path = tmp_path / "safe-globals.toml"
    path.write_text(
        f"version = {version}\n\n{entries}\n"
        '[[changes]]\nversion = 1\ndate = "2026-11-14"\nsummary = "test"\n',
        encoding="utf-8",
    )
    return path


def _entry(module: str, name: str) -> str:
    return f'[[entries]]\nmodule = "{module}"\nname = "{name}"\nwhy = "test"\nadded_in = 1\n\n'


def test_version_1_holds_30_exact_entries() -> None:
    safe = globals_policy.load_safe_list()
    assert safe.version == 1
    assert len(safe.entries) == 30
    assert ("__builtin__", "set") in safe.entries
    assert ("_codecs", "encode") in safe.entries
    assert ("numpy.core.multiarray", "scalar") in safe.entries
    assert ("builtins", "frozenset") not in safe.entries  # dropped by the owner (2026-11-14)
    assert ("__builtin__", "frozenset") not in safe.entries
    assert ("__builtin__", "getattr") not in safe.entries
    assert len(safe.sha256) == 64


def test_the_entries_match_the_recorded_hash_of_their_version() -> None:
    safe = globals_policy.load_safe_list()
    assert globals_policy.entries_sha256(safe.entries) == ENTRIES_SHA256[safe.version]


@pytest.mark.parametrize(
    ("entries", "message"),
    [
        (_entry("torch.*", "Size"), "wildcard"),
        (_entry("torch", "*"), "wildcard"),
        (_entry("", "Size"), "empty"),
        (_entry("torch", ""), "empty"),
        (_entry("torch", "Size") + _entry("torch", "Size"), "twice"),
        (_entry("unknown", "eval"), "unknown"),
        (_entry("torch", "my_unknown"), "unknown"),
    ],
)
def test_the_loader_refuses_a_bad_entry(tmp_path: Path, entries: str, message: str) -> None:
    with pytest.raises(globals_policy.SafeListError, match=message):
        globals_policy.load_safe_list(_write(tmp_path, entries))


def test_a_capitalised_unknown_is_accepted(tmp_path: Path) -> None:
    safe = globals_policy.load_safe_list(_write(tmp_path, _entry("Unknown", "Thing")))
    assert safe.entries == frozenset({("Unknown", "Thing")})


def test_the_file_hash_is_of_the_file_as_read(tmp_path: Path) -> None:
    import hashlib

    path = _write(tmp_path, _entry("torch", "Size"), version=7)
    safe = globals_policy.load_safe_list(path)
    assert safe.version == 7
    assert safe.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()

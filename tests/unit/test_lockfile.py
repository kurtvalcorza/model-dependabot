"""Hash-locked requirements parsing (T012, research R10, FR-003)."""

from __future__ import annotations

from pathlib import Path

import pytest

from model_dependabot.lockfile import LockEntry, parse_lock, read_lock

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "locks"
UV_LOCK = FIXTURES / "uv-export-trimmed.txt"
GAPS = FIXTURES / "hand-made-gaps.txt"


def _by_name(entries: list[LockEntry]) -> dict[str, LockEntry]:
    return {entry.name: entry for entry in entries}


def test_a_uv_generated_lock_is_read_with_every_entry_pinned() -> None:
    entries = _by_name(read_lock(UV_LOCK))
    assert {"attrs", "colorama", "jsonschema", "packaging"} <= set(entries)
    attrs = entries["attrs"]
    assert attrs.pinned is True
    assert attrs.gap_reason is None
    assert attrs.version == "26.1.0"
    assert attrs.hashes == (
        "sha256:c647aa4a12dfbad9333ca4e71fe62ddc36f4e63b2d260a37a8b83d2f043ac309",
        "sha256:d03ceb89cb322a8fd706d4fb91940737b6642aa36998fe130a9bc96c985eff32",
    )
    assert attrs.purl == "pkg:pypi/attrs@26.1.0"


def test_an_environment_marker_does_not_hide_the_version_or_hashes() -> None:
    colorama = _by_name(read_lock(UV_LOCK))["colorama"]
    assert (colorama.version, colorama.pinned, len(colorama.hashes)) == ("0.4.6", True, 2)


def test_comment_lines_after_an_entry_are_not_entries() -> None:
    names = [entry.name for entry in read_lock(UV_LOCK)]
    assert "via" not in names
    assert len(names) == len(set(names)) == 5


def test_an_editable_install_is_a_gap_with_no_exact_version() -> None:
    editable = [entry for entry in read_lock(UV_LOCK) if not entry.pinned]
    assert len(editable) == 1
    assert editable[0].gap_reason == "no exact version"
    assert editable[0].version is None
    assert editable[0].purl is None


def test_names_are_normalised() -> None:
    entries = _by_name(read_lock(GAPS))
    assert "jinja2" in entries
    assert "typing-extensions" in entries
    assert "zope-interface" in entries
    assert "Jinja2" not in entries


def test_a_missing_exact_version_is_a_gap() -> None:
    entries = _by_name(read_lock(GAPS))
    for name in ("typing-extensions", "numpy", "torch"):
        assert entries[name].pinned is False, name
        assert entries[name].gap_reason == "no exact version", name
        assert entries[name].version is None, name


def test_a_missing_hash_is_a_gap() -> None:
    requests = _by_name(read_lock(GAPS))["requests"]
    assert requests.pinned is False
    assert requests.gap_reason == "no hash"
    assert requests.version == "2.32.5"
    assert requests.hashes == ()


def test_spaces_around_the_operator_and_a_single_line_hash_are_pinned() -> None:
    pillow = _by_name(read_lock(GAPS))["pillow"]
    assert (pillow.version, pillow.pinned) == ("12.0.0", True)
    assert pillow.hashes == ("sha256:" + "c" * 64,)


def test_several_hash_algorithms_are_kept() -> None:
    zope = _by_name(read_lock(GAPS))["zope-interface"]
    assert zope.pinned is True
    assert zope.hashes == ("sha256:" + "e" * 64, "sha512:" + "e" * 128)


def test_option_lines_are_not_entries() -> None:
    names = {entry.name for entry in read_lock(GAPS)}
    assert names == {
        "jinja2",
        "typing-extensions",
        "requests",
        "numpy",
        "pillow",
        "torch",
        "zope-interface",
    }


@pytest.mark.parametrize(
    ("text", "pinned", "reason"),
    [
        ("a==1.0 --hash=sha256:" + "a" * 64, True, None),
        ("a==1.0", False, "no hash"),
        ("a>=1.0 --hash=sha256:" + "a" * 64, False, "no exact version"),
        ("a", False, "no exact version"),
        ("a==1.0 \\\n    --hash=sha256:" + "a" * 64, True, None),
    ],
)
def test_pinned_needs_both_an_exact_version_and_a_hash(
    text: str, pinned: bool, reason: str | None
) -> None:
    (entry,) = parse_lock(text + "\n")
    assert (entry.pinned, entry.gap_reason) == (pinned, reason)


def test_numbered_lines_give_the_line_each_requirement_starts_on() -> None:
    from model_dependabot.lockfile import numbered_lines

    text = "# header\n\nnumpy==2.1.0 \\\n    --hash=sha256:" + "a" * 64 + "\n# c\ntorch==2.5.1\n"
    assert [number for number, _ in numbered_lines(text)] == [3, 6]
    first = numbered_lines(text)[0][1]
    assert first.startswith("numpy==2.1.0") and "--hash=sha256:" in first


# --- environment markers (issue #28) -------------------------------------------------------------

HASH = " --hash=sha256:" + "ab" * 32


def test_an_environment_marker_is_kept_normalised() -> None:
    entries = _by_name(read_lock(UV_LOCK))
    assert entries["colorama"].marker == 'sys_platform == "win32"'
    assert entries["attrs"].marker is None


@pytest.mark.parametrize(
    ("line", "marker"),
    [
        ('pillow==12.3.0 ; sys_platform == "linux"' + HASH, 'sys_platform == "linux"'),
        ("pillow==12.3.0;python_version<'3.12'" + HASH, 'python_version < "3.12"'),
        ("pillow==12.3.0" + HASH, None),
        ('numpy>=2.0 ; platform_machine == "x86_64"', 'platform_machine == "x86_64"'),
        ("requests==2.32.5", None),
    ],
)
def test_a_marker_is_kept_on_pinned_entries_and_gaps(line: str, marker: str | None) -> None:
    [entry] = parse_lock(line)
    assert entry.marker == marker


def test_a_marker_does_not_change_pinning_or_hashes() -> None:
    [gated] = parse_lock('pillow==12.3.0 ; sys_platform == "linux"' + HASH)
    [plain] = parse_lock("pillow==12.3.0" + HASH)
    assert (gated.name, gated.version, gated.hashes, gated.pinned, gated.gap_reason) == (
        plain.name,
        plain.version,
        plain.hashes,
        plain.pinned,
        plain.gap_reason,
    )

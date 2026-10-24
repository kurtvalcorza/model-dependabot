"""Licence normalisation against the vendored SPDX list (T035; research U8, FR-009, FR-010)."""

from __future__ import annotations

import shutil
import tomllib
from pathlib import Path

import pytest

from model_dependabot.upstream import licences
from model_dependabot.upstream.licences import (
    LICENCE_DIR,
    LicenceListError,
    load_licence_list,
    normalise,
    same_licence,
)


@pytest.mark.parametrize(
    ("declared", "expected"),
    [
        # 1. An exact SPDX identifier, ignoring case (the hub's lower-case tags).
        ("apache-2.0", "Apache-2.0"),
        ("Apache-2.0", "Apache-2.0"),
        ("mit", "MIT"),
        ("cc-by-nc-4.0", "CC-BY-NC-4.0"),
        # 2. An SPDX full name, ignoring case (DataCite's rightsList of zenodo.3242074).
        ('BSD 3-Clause "New" or "Revised" License', "BSD-3-Clause"),
        ("creative commons attribution 4.0 international", "CC-BY-4.0"),
        # A full name shared by a deprecated identifier gives the current one.
        ("GNU General Public License v2.0 or later", "GPL-2.0-or-later"),
        # 3. An entry in aliases.toml (Figshare's spelling).
        ("CC BY 4.0", "CC-BY-4.0"),
        ("cc by 4.0", "CC-BY-4.0"),
    ],
)
def test_a_single_licence_normalises_in_order(declared: str, expected: str) -> None:
    licence = normalise(declared)
    assert (licence.declared, licence.normalised, licence.form) == (declared, expected, "spdx")
    assert licence.recognised


@pytest.mark.parametrize(
    ("declared", "expected"),
    [
        ("mit or apache-2.0", "MIT OR Apache-2.0"),
        ("MIT  AND  CC BY 4.0", "MIT AND CC-BY-4.0"),
        ("(mit OR apache-2.0) and bsd-3-clause", "(MIT OR Apache-2.0) AND BSD-3-Clause"),
    ],
)
def test_an_expression_is_normalised_term_by_term_with_operators_upper_cased(
    declared: str, expected: str
) -> None:
    licence = normalise(declared)
    assert (licence.normalised, licence.form) == (expected, "expression")


@pytest.mark.parametrize(
    "declared",
    ["llama3.1", "openrail", "other", "All Rights Reserved", "MIT OR llama3.1", "unknown"],
)
def test_anything_else_is_unrecognised_and_kept_as_declared(declared: str) -> None:
    licence = normalise(declared)
    assert (licence.declared, licence.normalised, licence.form) == (
        declared,
        declared,
        "unrecognised",
    )
    assert not licence.recognised


@pytest.mark.parametrize("declared", [None, "", "   "])
def test_no_licence_is_form_none(declared: str | None) -> None:
    licence = normalise(declared)
    assert (licence.normalised, licence.form) == (None, "none")


def test_same_licence_compares_normalised_forms() -> None:
    assert same_licence(normalise("apache-2.0"), normalise("Apache-2.0"))
    assert same_licence(normalise("CC BY 4.0"), normalise("CC-BY-4.0"))
    assert not same_licence(normalise("apache-2.0"), normalise("cc-by-nc-4.0"))
    # Unrecognised licences are compared as text.
    assert same_licence(normalise("llama3.1"), normalise("llama3.1"))
    assert not same_licence(normalise("llama3.1"), normalise("Llama3.1 "))


def test_every_alias_names_a_listed_identifier_and_its_source() -> None:
    table = tomllib.loads((LICENCE_DIR / "aliases.toml").read_text("utf-8"))
    entries = table["alias"]
    assert entries
    listed = load_licence_list()
    for entry in entries:
        assert set(entry) == {"alias", "spdx", "source"}
        assert listed.identifier(entry["spdx"]) == entry["spdx"]


def _copy(tmp_path: Path) -> Path:
    directory = tmp_path / "licences"
    shutil.copytree(LICENCE_DIR, directory)
    return directory


def test_the_vendored_list_is_checked_against_sha256sums(tmp_path: Path) -> None:
    listed = load_licence_list(_copy(tmp_path))
    assert listed.version == "3.29.0"
    assert listed.identifier("mit") == "MIT"
    tampered = _copy(tmp_path / "tampered")
    path = tampered / "spdx-licenses-3.29.0.json"
    path.write_bytes(path.read_bytes().replace(b'"MIT"', b'"MIT-0"', 1))
    with pytest.raises(LicenceListError, match="SHA256SUMS"):
        load_licence_list(tampered)


def test_a_list_missing_from_sha256sums_is_refused(tmp_path: Path) -> None:
    directory = _copy(tmp_path)
    (directory / "SHA256SUMS").write_text("", "utf-8")
    with pytest.raises(LicenceListError, match="SHA256SUMS"):
        load_licence_list(directory)


def test_an_alias_to_an_unlisted_identifier_is_refused(tmp_path: Path) -> None:
    directory = _copy(tmp_path)
    (directory / "aliases.toml").write_text(
        '[[alias]]\nalias = "Made Up"\nspdx = "Not-A-Licence"\nsource = "figshare"\n', "utf-8"
    )
    with pytest.raises(LicenceListError, match="Not-A-Licence"):
        load_licence_list(directory)


def test_the_default_list_is_loaded_once() -> None:
    assert licences.default_list() is licences.default_list()

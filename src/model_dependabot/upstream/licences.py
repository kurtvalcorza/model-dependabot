"""Licence normalisation against the vendored SPDX licence list (research U8, FR-009, FR-010).

A declared licence is normalised in this order: an exact SPDX identifier ignoring case; an SPDX
full name ignoring case; an entry in ``licences/aliases.toml``. A licence expression
(``MIT OR Apache-2.0``) is normalised term by term with its operators upper-cased. Anything else
is ``unrecognised``: kept as declared and compared as text, never an alert. The vendored list is
checked against ``SHA256SUMS`` when it is loaded, and an alias must name a listed identifier.
"""

from __future__ import annotations

import hashlib
import json
import re
import tomllib
from dataclasses import dataclass
from functools import cache
from pathlib import Path

LICENCE_DIR = Path(__file__).resolve().parent.parent / "licences"
LIST_FILE = "spdx-licenses-3.29.0.json"
OPERATORS = ("AND", "OR", "WITH")
RECOGNISED_FORMS = ("spdx", "expression")
# Parentheses and the operators between terms, matched ignoring case.
_TOKENS = re.compile(r"(\(|\)|\s+(?:AND|OR|WITH)\s+)", re.IGNORECASE)


class LicenceListError(RuntimeError):
    """The vendored licence list or the alias table cannot be trusted."""


@dataclass(frozen=True)
class Licence:
    """A declared licence and its normalised form (data-model.md, ``licence_form``)."""

    declared: str | None
    normalised: str | None
    form: str

    @property
    def recognised(self) -> bool:
        return self.form in RECOGNISED_FORMS


def same_licence(a: Licence, b: Licence) -> bool:
    """Whether two licences are the same once normalised (unrecognised ones as text)."""
    return (a.normalised, a.form) == (b.normalised, b.form)


@dataclass(frozen=True)
class LicenceList:
    """The SPDX identifiers, full names and repository aliases, keyed in lower case."""

    version: str
    ids: dict[str, str]
    names: dict[str, str]
    aliases: dict[str, str]

    def identifier(self, text: str) -> str | None:
        """The SPDX identifier one term means, or ``None``."""
        key = text.strip().lower()
        return self.ids.get(key) or self.names.get(key) or self.aliases.get(key)

    def normalise(self, declared: str | None) -> Licence:
        if declared is None or not declared.strip():
            return Licence(declared, None, "none")
        found = self.identifier(declared)
        if found is not None:
            return Licence(declared, found, "spdx")
        expression = self._expression(declared)
        if expression is not None:
            return Licence(declared, expression, "expression")
        return Licence(declared, declared, "unrecognised")

    def _expression(self, declared: str) -> str | None:
        parts: list[str] = []
        operators = 0
        for token in _TOKENS.split(declared):
            word = token.strip()
            if not word:
                continue
            if word in ("(", ")"):
                parts.append(word)
            elif word.upper() in OPERATORS and token != word:
                parts.append(f" {word.upper()} ")
                operators += 1
            else:
                found = self.identifier(word)
                if found is None:
                    return None
                parts.append(found)
        return "".join(parts) if operators else None


def _checked(directory: Path) -> bytes:
    path = directory / LIST_FILE
    raw = path.read_bytes()
    sums = {}
    for line in (directory / "SHA256SUMS").read_text("utf-8").splitlines():
        if line.strip():
            digest, _, name = line.strip().partition("  ")
            sums[name.strip()] = digest.lower()
    actual = hashlib.sha256(raw).hexdigest()
    if sums.get(LIST_FILE) != actual:
        raise LicenceListError(f"{path} does not match its SHA-256 in SHA256SUMS")
    return raw


def load_licence_list(directory: Path = LICENCE_DIR) -> LicenceList:
    """Load the vendored list, refusing a file that does not match ``SHA256SUMS``."""
    document = json.loads(_checked(directory))
    ids: dict[str, str] = {}
    names: dict[str, str] = {}
    # Current identifiers first, so a full name shared with a deprecated one gives the current.
    for item in sorted(document["licenses"], key=lambda i: bool(i.get("isDeprecatedLicenseId"))):
        ids.setdefault(item["licenseId"].lower(), item["licenseId"])
        names.setdefault(item["name"].lower(), item["licenseId"])
    aliases: dict[str, str] = {}
    table = tomllib.loads((directory / "aliases.toml").read_text("utf-8"))
    for entry in table.get("alias", []):
        spdx = ids.get(str(entry.get("spdx", "")).lower())
        if spdx != entry.get("spdx") or not entry.get("source") or not entry.get("alias"):
            raise LicenceListError(
                f"alias {entry.get('alias')!r} must name a listed SPDX identifier and its source,"
                f" got {entry.get('spdx')!r}"
            )
        aliases[entry["alias"].lower()] = spdx
    return LicenceList(document["licenseListVersion"], ids, names, aliases)


@cache
def default_list() -> LicenceList:
    return load_licence_list()


def normalise(declared: str | None) -> Licence:
    """Normalise a declared licence against the vendored list (research U8)."""
    return default_list().normalise(declared)


def recorded(licence: str | None, form: str | None) -> Licence | None:
    """An inventory's recorded licence as a ``Licence``; ``None`` when nothing was recorded."""
    if not licence:
        return None
    if form == "unrecognised":
        return Licence(licence, licence, "unrecognised")
    return normalise(licence)

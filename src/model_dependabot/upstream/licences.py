"""Licence normalisation against the vendored SPDX licence list (research U8, FR-009, FR-010).

A declared licence is normalised in this order: an exact SPDX identifier ignoring case; an SPDX
full name ignoring case; an entry in ``licences/aliases.toml``. A licence expression
(``MIT OR Apache-2.0``) is normalised term by term with its operators upper-cased; the term after
``WITH`` must be an exception identifier from the vendored SPDX exceptions list, ignoring case, and
an unknown exception leaves the expression unrecognised. Anything else is ``unrecognised``: kept as
declared and compared as text, never an alert. The vendored lists are checked against
``SHA256SUMS`` when they are loaded, and an alias must name a listed identifier.

A source can declare several licence entries (owner decision of 2026-10-24). They travel as one
text, one entry per line (``SEPARATOR``), and are compared as the normalised set of their entries,
order and repeats ignored: ``normalise`` returns a ``LicenceSet``.
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
EXCEPTIONS_FILE = "spdx-exceptions-3.29.0.json"
# Several declared licence entries are joined one per line.
SEPARATOR = "\n"
OPERATORS = ("AND", "OR", "WITH")
RECOGNISED_FORMS = ("spdx", "expression")
# Parentheses and the operators between terms, matched ignoring case.
_TOKENS = re.compile(r"(\(|\)|\s+(?:AND|OR|WITH)\s+)", re.IGNORECASE)


class LicenceListError(RuntimeError):
    """The vendored licence list or the alias table cannot be trusted."""


@dataclass(frozen=True)
class Licence:
    """One declared licence entry and its normalised form (data-model.md, ``licence_form``)."""

    declared: str | None
    normalised: str | None
    form: str

    @property
    def recognised(self) -> bool:
        return self.form in RECOGNISED_FORMS


@dataclass(frozen=True)
class LicenceSet:
    """Every licence entry a source declares, compared as a normalised set (owner, 2026-10-24).

    ``normalised`` is the set's entries, normalised, unique and sorted, one per line; ``form`` is
    ``none`` for no entry, ``unrecognised`` if any entry is, ``expression`` if any entry is one,
    else ``spdx``.
    """

    declared: str | None
    entries: tuple[Licence, ...]

    @property
    def key(self) -> frozenset[tuple[str | None, str]]:
        return frozenset((entry.normalised, entry.form) for entry in self.entries)

    @property
    def normalised(self) -> str | None:
        names = sorted({str(entry.normalised) for entry in self.entries})
        return SEPARATOR.join(names) if names else None

    @property
    def form(self) -> str:
        forms = {entry.form for entry in self.entries}
        for form in ("unrecognised", "expression", "spdx"):
            if form in forms:
                return form
        return "none"

    @property
    def recognised(self) -> bool:
        return self.form in RECOGNISED_FORMS


def split_licences(text: str | None) -> list[str]:
    """The entries of a declared or recorded licence text, in order, blank ones left out."""
    return [part.strip() for part in (text or "").split(SEPARATOR) if part.strip()]


def join_licences(entries: list[str]) -> str | None:
    """Declared entries as one text, one per line, in order without repeats; ``None`` for none."""
    kept: list[str] = []
    for entry in entries:
        if entry.strip() and entry.strip() not in kept:
            kept.append(entry.strip())
    return SEPARATOR.join(kept) if kept else None


def same_licence(a: LicenceSet, b: LicenceSet) -> bool:
    """Whether two licences are the same set once normalised (unrecognised ones as text)."""
    return a.key == b.key


@dataclass(frozen=True)
class LicenceList:
    """The SPDX identifiers, full names, repository aliases and exceptions, keyed in lower case."""

    version: str
    ids: dict[str, str]
    names: dict[str, str]
    aliases: dict[str, str]
    exceptions: dict[str, str]

    def identifier(self, text: str) -> str | None:
        """The SPDX identifier one term means, or ``None``."""
        key = text.strip().lower()
        return self.ids.get(key) or self.names.get(key) or self.aliases.get(key)

    def exception(self, text: str) -> str | None:
        """The SPDX exception identifier one term means, ignoring case, or ``None``."""
        return self.exceptions.get(text.strip().lower())

    def normalise_set(self, declared: str | None) -> LicenceSet:
        """Every entry of a declared licence text, normalised one by one."""
        return LicenceSet(declared, tuple(self.normalise(e) for e in split_licences(declared)))

    def normalise(self, declared: str | None) -> Licence:
        """One licence entry, normalised."""
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
        after_with = False
        for token in _TOKENS.split(declared):
            word = token.strip()
            if not word:
                continue
            if word in ("(", ")"):
                if after_with:
                    return None
                parts.append(word)
            elif word.upper() in OPERATORS and token != word:
                if after_with:
                    return None
                parts.append(f" {word.upper()} ")
                operators += 1
                after_with = word.upper() == "WITH"
            else:
                found = self.exception(word) if after_with else self.identifier(word)
                if found is None:
                    return None
                parts.append(found)
                after_with = False
        return "".join(parts) if operators and not after_with else None


def _checked(directory: Path, name: str) -> bytes:
    path = directory / name
    raw = path.read_bytes()
    sums = {}
    for line in (directory / "SHA256SUMS").read_text("utf-8").splitlines():
        if line.strip():
            digest, _, listed = line.strip().partition("  ")
            sums[listed.strip()] = digest.lower()
    actual = hashlib.sha256(raw).hexdigest()
    if sums.get(name) != actual:
        raise LicenceListError(f"{path} does not match its SHA-256 in SHA256SUMS")
    return raw


def load_licence_list(directory: Path = LICENCE_DIR) -> LicenceList:
    """Load the vendored lists, refusing a file that does not match ``SHA256SUMS``."""
    document = json.loads(_checked(directory, LIST_FILE))
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
    listed = json.loads(_checked(directory, EXCEPTIONS_FILE))
    exceptions = {
        item["licenseExceptionId"].lower(): item["licenseExceptionId"]
        for item in listed["exceptions"]
    }
    return LicenceList(document["licenseListVersion"], ids, names, aliases, exceptions)


@cache
def default_list() -> LicenceList:
    return load_licence_list()


def normalise(declared: str | None) -> LicenceSet:
    """Normalise every entry of a declared licence against the vendored lists (research U8)."""
    return default_list().normalise_set(declared)


def recorded(licence: str | None, form: str | None) -> LicenceSet | None:
    """An inventory's recorded licence as a ``LicenceSet``; ``None`` when nothing was recorded.

    A single entry recorded as ``unrecognised`` (a CycloneDX ``license.name``) stays text.
    """
    if not licence:
        return None
    entries = split_licences(licence)
    if form == "unrecognised" and len(entries) == 1:
        return LicenceSet(licence, (Licence(entries[0], entries[0], "unrecognised"),))
    return normalise(licence)

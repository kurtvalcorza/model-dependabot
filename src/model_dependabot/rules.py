"""The rule registry: one stable rule ID and one documentation page per alert kind (US4).

IDs are ``MDB`` plus three digits, grouped by family, and never reused (owner's ruling D1,
FR-016); ``tests/fixtures/rules/assigned.json`` records every ID ever assigned. Each page in
``docs/rules/`` says what raises the alert, what it does not prove, how it closes and how to fix or
accept it (FR-015), and lists the watch kinds that belong with it. Every alert view carries the
rule's ``rule_id`` and ``rule_doc`` (FR-014).

Feature 010: the fixed text of each rule ID (what the check cannot see, how the alert closes, how
to fix or accept it, what the evidence does not establish and the numbered review steps) is one
data file, ``rule_texts/rule-texts.toml``, read here once and checked (``load_rule_texts``). The
advisory view and the rule pages both use it (FR-014). ``RELATIONSHIPS`` is the fixed list of how
an entry relates to the model, per entry kind and alert kind (FR-005, data-model.md).
"""

from __future__ import annotations

import functools
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Rule:
    rule_id: str
    kind: str
    title: str
    family: str
    watch_kinds: tuple[str, ...] = ()

    @property
    def page(self) -> str:
        return f"docs/rules/{self.rule_id}.md"


RULES = (
    Rule(
        "MDB101",
        "weight_file_scan",
        "A local pickle weight file imports a dangerous global",
        "weight files",
        ("scan_suspicious", "scan_incomplete", "hash_mismatch", "weight_file_absent"),
    ),
    Rule(
        "MDB102",
        "hub_scan",
        "The hub's own scan calls a pinned hub weight file unsafe",
        "weight files",
        ("hub_scan_unknown",),
    ),
    Rule(
        "MDB103",
        "format_policy",
        "A code-capable weight file under the strict format policy",
        "weight files",
        ("pickle_format", "format_claim_contradicted", "format_claim_unreadable"),
    ),
    Rule(
        "MDB104",
        "globals_policy",
        "Pickle globals neither on the safe list nor excepted, under the strict globals policy",
        "weight files",
    ),
    Rule(
        "MDB201",
        "package_advisory",
        "A pinned package version is affected by a published advisory",
        "packages",
        ("advisory_unmatched", "advisory_gone"),
    ),
    Rule(
        "MDB301",
        "dataset_retracted",
        "A pinned dataset is retracted",
        "datasets and papers",
        ("upstream_notice",),
    ),
    Rule(
        "MDB302",
        "paper_retracted",
        "A paper a pinned dataset cites is retracted",
        "datasets and papers",
        ("paper_not_found",),
    ),
    Rule(
        "MDB303",
        "dataset_removed",
        "A pinned dataset is removed",
        "datasets and papers",
        ("dataset_moved", "dataset_replaced"),
    ),
    Rule(
        "MDB304",
        "dataset_not_findable",
        "A pinned dataset's DOI is no longer findable",
        "datasets and papers",
        ("dataset_unreachable", "dataset_new_version"),
    ),
    Rule(
        "MDB401",
        "licence_changed",
        "The licence of a pinned dependency changed",
        "licences",
        ("licence_unrecognised", "licence_missing"),
    ),
    Rule(
        "MDB501",
        "base_model_disabled",
        "The pinned base model is disabled",
        "base model",
        (
            "base_model_new_revision",
            "base_model_new_version_pointer",
            "gating_changed",
            "card_changed",
            "base_model_moved",
        ),
    ),
    Rule(
        "MDB502",
        "base_model_unavailable",
        "The pinned base model is no longer publicly available",
        "base model",
        ("base_model_refused", "base_model_unrecognised"),
    ),
)
# Feature 011 (owner's ruling on review R8): a page for a watch kind with no alert kind of its own.
# Its ID is assigned like any other and never reused; it has rule texts and a page, but no alert
# carries it, so ``rule_for`` does not return it.
WATCH_RULES = (
    Rule(
        "MDB601",
        "lineage_inherited",
        "A registered parent's finding reaches this model",
        "lineage",
        ("lineage_inherited",),
    ),
)
# Every rule ID with a page and rule texts.
PAGES = (*RULES, *WATCH_RULES)
_BY_KIND = {rule.kind: rule for rule in RULES}


def rule_for(kind: str) -> Rule:
    """The rule of an alert kind; every kind in ``store.ALERT_KINDS`` has one."""
    return _BY_KIND[kind]


# --- rule texts (feature 010, FR-014, research R4) -----------------------------------------------

RULE_TEXTS = Path(__file__).resolve().parent / "rule_texts" / "rule-texts.toml"
PLACEHOLDERS = frozenset(
    {
        "alert_id",
        "model_id",
        "identifier",
        "location",
        "package",
        "version",
        "advisory_ids",
        "dataset",
        "paper_doi",
        "repo",
        "item",
        "rule_doc",
    }
)
IMPACT_QUESTION = "whether this alert affects model {model_id}"
CLOSING = "How this alert closes: "
# Feature 011 (review R2-2): a watch event does not close, so its last step is worded for an event.
WATCH_CLOSING = "When a check stops recording it: "
_TEXT_FIELDS = ("limitations", "closes", "fix")
_LIST_FIELDS = ("not_established", "steps")
_PLACEHOLDER = re.compile(r"\{([^}]*)\}")


class RuleTextsError(ValueError):
    """The rule texts file is malformed; the message names the rule ID or field."""


@dataclass(frozen=True)
class RuleTexts:
    limitations: str
    closes: str
    fix: str
    not_established: tuple[str, ...]
    steps: tuple[str, ...]


def _rule_texts(rule_id: str, table: Any) -> RuleTexts:
    if not isinstance(table, dict):
        raise RuleTextsError(f"{rule_id} is not a table")
    missing = sorted(set(_TEXT_FIELDS + _LIST_FIELDS) - set(table))
    extra = sorted(set(table) - set(_TEXT_FIELDS + _LIST_FIELDS))
    if missing or extra:
        raise RuleTextsError(f"{rule_id}: missing {missing}, unknown {extra}")
    for name in _TEXT_FIELDS:
        value = table[name]
        if not isinstance(value, str) or not value.strip():
            raise RuleTextsError(f"{rule_id}: {name} is empty")
        if _PLACEHOLDER.search(value):
            raise RuleTextsError(f"{rule_id}: {name} may hold no placeholder")
    for name in _LIST_FIELDS:
        value = table[name]
        if not isinstance(value, list) or len(value) < 2:
            raise RuleTextsError(f"{rule_id}: {name} needs at least two items")
        for item in value:
            if not isinstance(item, str) or not item.strip():
                raise RuleTextsError(f"{rule_id}: {name} has an empty item")
            unknown = set(_PLACEHOLDER.findall(item)) - PLACEHOLDERS
            if unknown:
                raise RuleTextsError(f"{rule_id}: {name} uses an unknown placeholder {unknown}")
    if table["not_established"][0] != IMPACT_QUESTION:
        raise RuleTextsError(f"{rule_id}: the impact question must come first")
    return RuleTexts(
        limitations=table["limitations"],
        closes=table["closes"],
        fix=table["fix"],
        not_established=tuple(table["not_established"]),
        steps=tuple(table["steps"]),
    )


def load_rule_texts(path: Path | str = RULE_TEXTS) -> tuple[int, dict[str, RuleTexts]]:
    """Read and check the rule texts: one table per rule ID of ``PAGES``, every field present
    and not empty, only the placeholders of ``PLACEHOLDERS``, the impact question first."""
    with open(path, "rb") as handle:
        data = tomllib.load(handle)
    version = data.get("version")
    if not isinstance(version, int) or isinstance(version, bool):
        raise RuleTextsError("version must be an integer")
    tables = {key: value for key, value in data.items() if key != "version"}
    wanted = {rule.rule_id for rule in PAGES}
    if set(tables) != wanted:
        raise RuleTextsError(
            f"rule IDs missing {sorted(wanted - set(tables))},"
            f" unknown {sorted(set(tables) - wanted)}"
        )
    return version, {rule_id: _rule_texts(rule_id, tables[rule_id]) for rule_id in sorted(tables)}


@functools.cache
def _loaded() -> tuple[int, dict[str, RuleTexts]]:
    return load_rule_texts()


def closing_for(rule: Rule) -> str:
    """The words that introduce a page's last review step: an alert closes, a watch event stops."""
    return WATCH_CLOSING if rule in WATCH_RULES else CLOSING


def rule_texts_version() -> int:
    return _loaded()[0]


def texts_for(rule_id: str) -> RuleTexts:
    """The fixed texts of one rule ID."""
    return _loaded()[1][rule_id]


# --- relationships (feature 010, FR-005, data-model.md) ------------------------------------------


@dataclass(frozen=True)
class Relationship:
    value: str
    steps_from_model: int


_WEIGHT = Relationship("weight file of this model", 1)
_PACKAGE = Relationship("package pinned in this model's environment lock", 1)
_BASE = Relationship("declared base model", 1)
_DATASET = Relationship("declared dataset", 1)
RELATIONSHIPS: dict[tuple[str, str], Relationship] = {
    ("weight_file", "weight_file_scan"): _WEIGHT,
    ("weight_file", "hub_scan"): _WEIGHT,
    ("weight_file", "format_policy"): _WEIGHT,
    ("weight_file", "globals_policy"): _WEIGHT,
    ("package", "package_advisory"): _PACKAGE,
    ("base_model", "base_model_disabled"): _BASE,
    ("base_model", "base_model_unavailable"): _BASE,
    ("base_model", "licence_changed"): _BASE,
    ("dataset", "dataset_retracted"): _DATASET,
    ("dataset", "dataset_removed"): _DATASET,
    ("dataset", "dataset_not_findable"): _DATASET,
    ("dataset", "licence_changed"): _DATASET,
    ("dataset", "paper_retracted"): Relationship("paper cited by a declared dataset", 2),
}

"""The rule registry: one stable rule ID and one documentation page per alert kind (US4).

IDs are ``MDB`` plus three digits, grouped by family, and never reused (owner's ruling D1,
FR-016); ``tests/fixtures/rules/assigned.json`` records every ID ever assigned. Each page in
``docs/rules/`` says what raises the alert, what it does not prove, how it closes and how to fix or
accept it (FR-015), and lists the watch kinds that belong with it. Every alert view carries the
rule's ``rule_id`` and ``rule_doc`` (FR-014).
"""

from __future__ import annotations

from dataclasses import dataclass


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
_BY_KIND = {rule.kind: rule for rule in RULES}


def rule_for(kind: str) -> Rule:
    """The rule of an alert kind; every kind in ``store.ALERT_KINDS`` has one."""
    return _BY_KIND[kind]

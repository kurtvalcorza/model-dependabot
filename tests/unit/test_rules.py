"""The rule registry and its pages (T046, FR-014 to FR-016, research S1)."""

from __future__ import annotations

import json
import re
from pathlib import Path

from model_dependabot import rules
from model_dependabot.store import ALERT_KINDS, WATCH_KINDS

ROOT = Path(__file__).resolve().parent.parent.parent
ASSIGNED = json.loads((ROOT / "tests" / "fixtures" / "rules" / "assigned.json").read_text("utf-8"))[
    "assigned"
]
HEADINGS = [
    "What raises it",
    "What it does not prove",
    "How it closes",
    "How to fix or accept it",
]


def test_one_rule_per_alert_kind() -> None:
    kinds = [rule.kind for rule in rules.RULES]
    assert sorted(kinds) == sorted(ALERT_KINDS)
    assert len(kinds) == len(set(kinds)) == 12


def test_ids_are_unique_and_well_formed() -> None:
    ids = [rule.rule_id for rule in rules.PAGES]
    assert len(ids) == len(set(ids))
    assert all(re.fullmatch(r"MDB\d{3}", rule_id) for rule_id in ids)


def test_no_assigned_id_is_gone_or_names_another_kind() -> None:
    by_id = {rule.rule_id: rule.kind for rule in rules.PAGES}
    for rule_id, kind in ASSIGNED.items():
        assert by_id.get(rule_id) == kind, rule_id
    assert set(by_id) <= set(ASSIGNED), "a new ID must be added to assigned.json"


def test_lookup_by_kind() -> None:
    assert rules.rule_for("weight_file_scan").rule_id == "MDB101"
    assert rules.rule_for("globals_policy").page == "docs/rules/MDB104.md"


def _page(rule: rules.Rule) -> str:
    return (ROOT / rule.page).read_text("utf-8")


def test_every_page_has_exactly_the_four_headings() -> None:
    for rule in rules.PAGES:
        text = _page(rule)
        assert text.startswith(f"# {rule.rule_id}"), rule.rule_id
        assert re.findall(r"^## (.+)$", text, re.MULTILINE) == HEADINGS, rule.rule_id


def test_every_watch_kind_is_on_exactly_one_page() -> None:
    listed: list[str] = []
    for rule in rules.PAGES:
        match = re.search(r"^Related watch kinds: (.+)$", _page(rule), re.MULTILINE)
        on_page = re.findall(r"`([a-z_]+)`", match.group(1)) if match else []
        assert sorted(on_page) == sorted(rule.watch_kinds), rule.rule_id
        listed += on_page
    assert sorted(listed) == sorted(WATCH_KINDS)


def test_the_index_links_every_page() -> None:
    index = (ROOT / "docs" / "rules" / "README.md").read_text("utf-8")
    for rule in rules.PAGES:
        assert f"]({rule.rule_id}.md)" in index
        assert f"`{rule.kind}`" in index
    assert "lead nowhere" not in index


# --- feature 010: rule texts and relationships (T009) -------------------------------------------


def _renderer():
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "render_rule_pages", ROOT / "tools" / "render_rule_pages.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_every_page_is_in_step_with_the_rule_texts() -> None:
    renderer = _renderer()
    for rule in rules.PAGES:
        page = ROOT / rule.page
        texts = rules.texts_for(rule.rule_id)
        rendered = renderer.render(page.read_text("utf-8"), texts, rules.closing_for(rule))
        assert rendered.encode("utf-8") == page.read_bytes(), f"{rule.page}: run the renderer"


def test_every_alert_kind_has_a_relationship() -> None:
    kinds = {alert_kind for _, alert_kind in rules.RELATIONSHIPS}
    assert kinds == set(ALERT_KINDS)
    assert ("base_model", "licence_changed") in rules.RELATIONSHIPS
    assert ("dataset", "licence_changed") in rules.RELATIONSHIPS
    assert rules.RELATIONSHIPS[("dataset", "paper_retracted")].steps_from_model == 2


def test_the_lineage_page_is_its_own_and_mdb501_is_about_disabled_bases() -> None:
    """Feature 011 (owner's ruling on review R8)."""
    [page] = rules.WATCH_RULES
    assert (page.rule_id, page.kind, page.family) == ("MDB601", "lineage_inherited", "lineage")
    assert "lineage_inherited" not in rules.rule_for("base_model_disabled").watch_kinds
    text = _page(page)
    assert "never counts for `check --fail-on`" in text
    for kind in ("weight_file_scan", "dataset_retracted", "licence_changed", "base_model_disabled"):
        assert f"`{kind}`" in text
    assert "lineage" not in _page(rules.rule_for("base_model_disabled"))


def test_the_lineage_page_never_says_its_event_closes() -> None:
    """Review R2-2: a watch event's last step is not "How this alert closes"."""
    [page] = rules.WATCH_RULES
    text = _page(page)
    assert "How this alert closes" not in text
    assert "It is not an alert and does not close" not in text
    assert rules.closing_for(page) == rules.WATCH_CLOSING
    assert rules.closing_for(rules.rule_for("base_model_disabled")) == rules.CLOSING

"""The rule texts file and its loader (T008, FR-014, SC-001, research R4 and R10)."""

from __future__ import annotations

import hashlib
import json
import re
import tomllib
from pathlib import Path

import pytest

from model_dependabot import rules

ROOT = Path(__file__).resolve().parent.parent.parent
TEXTS = ROOT / "src" / "model_dependabot" / "rule_texts" / "rule-texts.toml"
VERDICTS = json.loads((ROOT / "tests" / "fixtures" / "advice" / "verdicts.json").read_text("utf-8"))
# The SHA-256 of each version of the file: a change to the text needs a new version and a new line.
RECORDED = {1: "0b4abde933dd879d2a6fd1ba0dd9084a97140c0e253f14c6393cd8970e1b0819"}
FIELDS = ("limitations", "closes", "fix", "not_established", "steps")


def _data() -> dict:
    return tomllib.loads(TEXTS.read_text("utf-8"))


def test_one_table_per_rule_id_and_no_other() -> None:
    data = _data()
    tables = {key for key, value in data.items() if isinstance(value, dict)}
    assert tables == {rule.rule_id for rule in rules.RULES}
    assert set(data) - tables == {"version"}


def test_every_field_is_present_and_not_empty() -> None:
    for rule_id, table in ((k, v) for k, v in _data().items() if isinstance(v, dict)):
        assert sorted(table) == sorted(FIELDS), rule_id
        for name in ("limitations", "closes", "fix"):
            assert isinstance(table[name], str) and table[name].strip(), (rule_id, name)
        assert len(table["steps"]) >= 2, rule_id
        assert len(table["not_established"]) >= 2, rule_id
        assert table["not_established"][0] == "whether this alert affects model {model_id}"
        assert all(isinstance(item, str) and item.strip() for item in table["steps"])
        assert all(isinstance(item, str) and item.strip() for item in table["not_established"])


def test_only_the_allowed_placeholders_appear() -> None:
    for rule_id, table in ((k, v) for k, v in _data().items() if isinstance(v, dict)):
        for name in FIELDS:
            values = table[name] if isinstance(table[name], list) else [table[name]]
            for text in values:
                used = set(re.findall(r"\{([^}]*)\}", text))
                assert used <= rules.PLACEHOLDERS, (rule_id, name, used)
                if name in ("limitations", "closes", "fix"):
                    assert not used, (rule_id, name)


def test_the_text_changes_only_with_a_new_version() -> None:
    version = _data()["version"]
    assert isinstance(version, int)
    digest = hashlib.sha256(TEXTS.read_bytes()).hexdigest()
    assert RECORDED.get(version) == digest, f"version {version} is recorded as another text"


def _fields() -> list[tuple[str, str, str]]:
    found = []
    for rule_id, table in ((k, v) for k, v in _data().items() if isinstance(v, dict)):
        for name in FIELDS:
            values = table[name] if isinstance(table[name], list) else [table[name]]
            found += [(rule_id, name, text) for text in values]
    return found


def test_no_field_states_an_impact_verdict() -> None:
    allowed = VERDICTS["allowed"]
    for rule_id, name, text in _fields():
        for item in allowed:
            if (item["rule_id"], item["field"]) == (rule_id, name):
                text = text.replace(item["sentence"], "")
        for phrase in VERDICTS["phrases"]:
            assert phrase["phrase"] not in text.lower(), (rule_id, name, phrase["phrase"])


def test_every_allowed_sentence_still_occurs_in_its_field() -> None:
    data = _data()
    for item in VERDICTS["allowed"]:
        assert item["sentence"] in data[item["rule_id"]][item["field"]], item


def test_the_loader_reads_every_rule() -> None:
    version, texts = rules.load_rule_texts()
    assert version == _data()["version"]
    for rule in rules.RULES:
        assert rules.texts_for(rule.rule_id) == texts[rule.rule_id]
        assert len(texts[rule.rule_id].steps) >= 2


def _write(tmp_path: Path, change: str, by: str) -> Path:
    text = TEXTS.read_text("utf-8")
    assert change in text
    path = tmp_path / "rule-texts.toml"
    path.write_text(text.replace(change, by, 1), encoding="utf-8")
    return path


def test_a_rule_without_steps_is_refused(tmp_path: Path) -> None:
    text = TEXTS.read_text("utf-8")
    start = text.index("steps = [", text.index("[MDB302]"))
    end = text.index("]\n", start) + 2
    path = tmp_path / "rule-texts.toml"
    path.write_text(text[:start] + text[end:], encoding="utf-8")
    with pytest.raises(rules.RuleTextsError, match="MDB302"):
        rules.load_rule_texts(path)


@pytest.mark.parametrize(
    ("change", "by", "message"),
    [
        ("[MDB502]", "[MDB999]", "MDB"),
        (
            '"whether this alert affects model {model_id}",',
            '"whether {model_id} is used",',
            "impact",
        ),
        ("{alert_id}", "{secret}", "placeholder"),
        ("version = 1", 'version = "one"', "version"),
    ],
)
def test_a_malformed_file_is_refused(tmp_path: Path, change: str, by: str, message: str) -> None:
    with pytest.raises(rules.RuleTextsError, match=message):
        rules.load_rule_texts(_write(tmp_path, change, by))


def test_an_empty_field_is_refused(tmp_path: Path) -> None:
    text = TEXTS.read_text("utf-8")
    start = text.index("closes = ", text.index("[MDB201]"))
    end = text.index("\n", start)
    path = tmp_path / "rule-texts.toml"
    path.write_text(text[:start] + 'closes = ""' + text[end:], encoding="utf-8")
    with pytest.raises(rules.RuleTextsError, match="MDB201"):
        rules.load_rule_texts(path)

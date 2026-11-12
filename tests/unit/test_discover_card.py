"""Model card front matter read by discovery (T036; FR-018, research A6)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from model_dependabot.discover.model_card import (
    AliasRefusedError,
    discover_card,
    load_front_matter,
)
from model_dependabot.discover.walk import LIMITS, Limits, walk

NOW = "2026-11-13T00:00:00Z"


def card(root: Path, front: str, body: str = "\n# A model\n") -> None:
    (root / "README.md").write_text(f"---\n{front}---\n{body}", encoding="utf-8")


def run(root: Path, limits: Limits = LIMITS) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    return discover_card(walk(root, limits), NOW, limits)


def by_kind(candidates: list[dict[str, Any]], kind: str) -> list[dict[str, Any]]:
    return [item for item in candidates if item["kind"] == kind]


def test_only_the_named_keys_are_read(tmp_path: Path) -> None:
    card(
        tmp_path,
        "base_model: org/base\nbase_model_relation: finetune\ndatasets:\n  - org/data\n"
        "license: apache-2.0\nlicense_link: https://example.org/licence\n"
        "language: en\ntags: [vision]\n",
    )
    candidates, skipped = run(tmp_path)
    [base] = by_kind(candidates, "base_model")
    assert base["identity"] == {"hub_repo": "org/base", "revision": None, "relation": "finetune"}
    assert base["origin"] == {"file": "README.md", "key": "base_model"}
    assert base["status"] == "declared-but-unverified"
    assert base["gaps"] == ["no revision"]
    [dataset] = by_kind(candidates, "dataset")
    assert dataset["identity"] == {"hub_repo": "org/data"}
    assert dataset["gaps"] == ["no revision"]
    [licence] = by_kind(candidates, "licence")
    assert licence["identity"] == {
        "licence": "apache-2.0",
        "spdx": "Apache-2.0",
        "link": "https://example.org/licence",
    }
    assert skipped == [
        {"path": "README.md", "reason": "front matter keys not read", "keys": ["language", "tags"]}
    ]


def test_several_base_models_each_get_the_lineage_gap(tmp_path: Path) -> None:
    card(tmp_path, "base_model:\n  - org/one\n  - org/two\n")
    candidates, _ = run(tmp_path)
    assert [item["identity"]["hub_repo"] for item in candidates] == ["org/one", "org/two"]
    for item in candidates:
        assert item["gaps"] == ["no revision", "several base models; multi-parent lineage is #9"]


def test_other_licence_uses_the_licence_name(tmp_path: Path) -> None:
    card(tmp_path, "license: other\nlicense_name: my-own-terms\n")
    [licence] = run(tmp_path)[0]
    assert licence["identity"]["licence"] == "my-own-terms"
    assert licence["identity"]["spdx"] is None
    assert licence["gaps"] == ["licence not recognised"]
    assert licence["origin"]["key"] == "license_name"


def test_nothing_is_inferred_from_the_body(tmp_path: Path) -> None:
    body = "\nFine-tuned from org/hidden-base on org/hidden-data under the MIT licence.\n"
    card(tmp_path, "language: en\n", body)
    candidates, _ = run(tmp_path)
    assert candidates == []
    (tmp_path / "README.md").write_text(body, encoding="utf-8")
    assert run(tmp_path) == ([], [])


@pytest.mark.parametrize(
    "front",
    [
        "base_model: &b org/base\ndatasets: [*b]\n",
        "base_model: &only org/base\n",
        "a: &x [1, 2]\nb: *x\n",
        "<<: *missing\n",
    ],
)
def test_an_anchor_or_alias_is_refused(tmp_path: Path, front: str) -> None:
    with pytest.raises(yaml.YAMLError):
        load_front_matter(front)
    card(tmp_path, front)
    candidates, [skipped] = run(tmp_path)
    assert candidates == []
    assert skipped["path"] == "README.md"
    assert skipped["reason"].startswith("model card front matter unreadable")


def test_the_loader_refuses_aliases_with_its_own_error() -> None:
    with pytest.raises(AliasRefusedError):
        load_front_matter("a: &x 1\nb: *x\n")
    with pytest.raises(AliasRefusedError):
        load_front_matter("a: &x 1\n")
    assert load_front_matter("a: [1, 2]\n") == {"a": [1, 2]}


def test_the_loader_is_safe() -> None:
    with pytest.raises(yaml.YAMLError):
        load_front_matter("a: !!python/object/apply:os.system ['echo hi']\n")


@pytest.mark.parametrize(
    ("front", "reason"),
    [
        ("base_model: [unclosed\n", "unreadable"),
        ("- just\n- a list\n", "not a mapping"),
        ("base_model: {a: 1}\n", "not text or a list of text"),
    ],
)
def test_malformed_front_matter_is_unreadable_and_discovery_continues(
    tmp_path: Path, front: str, reason: str
) -> None:
    card(tmp_path, front)
    candidates, skipped = run(tmp_path)
    assert candidates == []
    assert reason in skipped[0]["reason"]


def test_a_deeply_nested_card_is_unreadable(tmp_path: Path) -> None:
    depth = 20_000
    card(tmp_path, "a: " + "[" * depth + "]" * depth + "\n")
    candidates, [skipped] = run(tmp_path)
    assert candidates == []
    assert skipped["reason"] == "model card front matter unreadable: nested too deeply"


def test_front_matter_beyond_the_limit_is_unreadable(tmp_path: Path) -> None:
    card(tmp_path, "base_model: org/base\n" + "# padding\n" * 200)
    candidates, [skipped] = run(tmp_path, Limits(card_bytes=1024))
    assert candidates == []
    assert "larger than 1 KiB" in skipped["reason"]


def test_a_large_body_after_small_front_matter_is_fine(tmp_path: Path) -> None:
    card(tmp_path, "base_model: org/base\n", "\n" + "body text\n" * 300_000)
    [base] = run(tmp_path)[0]
    assert base["identity"]["hub_repo"] == "org/base"


def test_a_name_that_is_not_a_hub_repository(tmp_path: Path) -> None:
    card(tmp_path, "base_model: gpt2\n")
    [base] = run(tmp_path)[0]
    assert base["status"] == "unavailable"
    assert "not a hub repository name (owner/name)" in base["gaps"]

"""Local evaluation of OSV affected ranges under PEP 440 (T025, research R2)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from model_dependabot.matching.versions import (
    advisory_affects,
    affected_ranges,
    evaluate_advisory,
    fixed_versions,
    version_affected,
)

OSV = Path(__file__).resolve().parent.parent / "fixtures" / "osv"


def _recorded(advisory_id: str) -> dict[str, Any]:
    return json.loads((OSV / f"vuln-{advisory_id}.json").read_text(encoding="utf-8"))


def _range(*events: dict[str, str], kind: str = "ECOSYSTEM") -> dict[str, Any]:
    return {"ranges": [{"type": kind, "events": list(events)}]}


@pytest.mark.parametrize(
    ("version", "expected"),
    [("0.0.1", True), ("0.9", True), ("1.0rc1", True), ("1.0", False), ("1.0.1", False)],
)
def test_introduced_zero_to_fixed(version: str, expected: bool) -> None:
    affected = _range({"introduced": "0"}, {"fixed": "1.0"})
    assert version_affected(version, affected) is expected


@pytest.mark.parametrize(
    ("version", "expected"),
    [("0.9", False), ("1.0", True), ("1.5", True), ("1.5.post1", False), ("1.5.1", False)],
)
def test_last_affected_is_inclusive(version: str, expected: bool) -> None:
    affected = _range({"introduced": "1.0"}, {"last_affected": "1.5"})
    assert version_affected(version, affected) is expected


@pytest.mark.parametrize(
    ("version", "expected"),
    [("1.1", True), ("1.2", False), ("1.5", False), ("2.0.5", True), ("2.1", False)],
)
def test_several_intervals_in_one_range(version: str, expected: bool) -> None:
    affected = _range(
        {"introduced": "1.0"}, {"fixed": "1.2"}, {"introduced": "2.0"}, {"fixed": "2.1"}
    )
    assert version_affected(version, affected) is expected


@pytest.mark.parametrize(("version", "expected"), [("1.1", True), ("1.5", False), ("2.0.5", True)])
def test_several_ranges(version: str, expected: bool) -> None:
    affected = {
        "ranges": [
            {"type": "ECOSYSTEM", "events": [{"introduced": "1.0"}, {"fixed": "1.2"}]},
            {"type": "ECOSYSTEM", "events": [{"introduced": "2.0"}, {"fixed": "2.1"}]},
        ]
    }
    assert version_affected(version, affected) is expected


@pytest.mark.parametrize(
    ("version", "expected"),
    [
        ("2.0.0a1", False),
        ("2.0.0b1", True),
        ("2.0.0b2", True),
        ("2.0.0rc1", True),
        ("2.0.0", False),
    ],
)
def test_pre_releases_are_ordered_by_pep_440(version: str, expected: bool) -> None:
    affected = _range({"introduced": "2.0.0b1"}, {"fixed": "2.0.0"})
    assert version_affected(version, affected) is expected


def test_events_are_evaluated_in_version_order() -> None:
    affected = _range({"fixed": "1.2"}, {"introduced": "1.0"})
    assert version_affected("1.1", affected) is True
    assert version_affected("1.3", affected) is False


@pytest.mark.parametrize(
    ("version", "expected"), [("1.0", True), ("1.0.0", True), ("1.1", True), ("1.2", False)]
)
def test_listed_versions_compare_under_pep_440(version: str, expected: bool) -> None:
    assert version_affected(version, {"versions": ["1.0", "1.1"]}) is expected


def test_ranges_other_than_ecosystem_are_ignored() -> None:
    affected = _range({"introduced": "0"}, {"fixed": "abc123"}, kind="GIT")
    assert version_affected("1.0", affected) is False


def test_an_invalid_version_matches_only_a_listed_string() -> None:
    affected = {**_range({"introduced": "0"}), "versions": ["not-a-version"]}
    assert version_affected("not-a-version", affected) is True
    assert version_affected("other-invalid", affected) is False


def test_recorded_advisory_affects_the_pinned_version_only() -> None:
    advisory = _recorded("GHSA-cp9v-662q-vvx9")
    assert advisory_affects(advisory, "pillow", "12.3.0") is True
    assert advisory_affects(advisory, "Pillow", "12.3.0") is True
    assert advisory_affects(advisory, "pillow", "13.0.0") is False
    assert advisory_affects(advisory, "pillow", "11.3.0") is False
    assert advisory_affects(advisory, "validators", "12.3.0") is False


def test_other_ecosystems_are_ignored() -> None:
    advisory = {
        "affected": [
            {"package": {"name": "pillow", "ecosystem": "npm"}, **_range({"introduced": "0"})}
        ]
    }
    assert advisory_affects(advisory, "pillow", "1.0") is False


def test_fixed_versions_and_ranges_of_a_recorded_advisory() -> None:
    advisory = _recorded("GHSA-24rc-8hj2-v98c")
    assert fixed_versions(advisory, "pillow") == ["13.0.0"]
    assert affected_ranges(advisory, "pillow") == [
        {"type": "ECOSYSTEM", "events": [{"introduced": "9.1.0"}, {"fixed": "13.0.0"}]}
    ]
    assert fixed_versions(advisory, "validators") == []


def test_no_fixed_version_published() -> None:
    advisory = {
        "affected": [{"package": {"name": "a", "ecosystem": "PyPI"}, **_range({"introduced": "0"})}]
    }
    assert fixed_versions(advisory, "a") == []
    assert advisory_affects(advisory, "a", "99.0") is True


# --- OSV ``limit`` events and unevaluable ranges (review F5, phase B1) ---------------------------


@pytest.mark.parametrize(
    ("version", "expected"),
    [("0.9", False), ("1.0", True), ("1.9.9", True), ("2.0", False), ("3.0", False)],
)
def test_limit_is_an_exclusive_upper_bound(version: str, expected: bool) -> None:
    affected = _range({"introduced": "1.0"}, {"limit": "2.0"})
    assert version_affected(version, affected) is expected


@pytest.mark.parametrize(("version", "expected"), [("0.9", False), ("1.5", True), ("99", True)])
def test_limit_star_is_infinity(version: str, expected: bool) -> None:
    affected = _range({"introduced": "1.0"}, {"limit": "*"})
    assert version_affected(version, affected) is expected


@pytest.mark.parametrize(
    ("version", "expected"),
    [("1.0", True), ("1.5", False), ("2.0", True), ("2.4", True), ("2.5", False), ("3.1", False)],
)
def test_limit_with_several_introduced_and_fixed_pairs(version: str, expected: bool) -> None:
    affected = _range(
        {"introduced": "1.0"},
        {"fixed": "1.5"},
        {"introduced": "2.0"},
        {"fixed": "2.5"},
        {"introduced": "3.0"},
        {"limit": "3.1"},
    )
    assert version_affected(version, affected) is expected


@pytest.mark.parametrize(("version", "expected"), [("1.2", True), ("1.4", False), ("1.7", False)])
def test_limit_below_fixed_bounds_the_open_interval(version: str, expected: bool) -> None:
    affected = _range({"introduced": "1.0"}, {"limit": "1.4"}, {"fixed": "1.6"})
    assert version_affected(version, affected) is expected


@pytest.mark.parametrize(("version", "expected"), [("1.5", True), ("2.5", True), ("3.0", False)])
def test_several_limits_any_one_above_the_version_admits_it(version: str, expected: bool) -> None:
    affected = _range({"introduced": "1.0"}, {"limit": "2.0"}, {"limit": "3.0"})
    assert version_affected(version, affected) is expected


def test_evaluation_separates_unevaluable_from_not_affected() -> None:
    advisory = {
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "pkg"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "not a version!"}]}],
            }
        ]
    }
    unevaluable = evaluate_advisory(advisory, "pkg", "1.0")
    assert unevaluable.affected is False
    assert unevaluable.evaluated is False
    assert any("not a version!" in reason for reason in unevaluable.reasons)

    advisory["affected"][0]["ranges"][0]["events"] = [{"introduced": "2.0"}]
    outside = evaluate_advisory(advisory, "pkg", "1.0")
    assert outside.affected is False
    assert outside.evaluated is True
    assert outside.reasons == ()


def test_an_unparseable_pinned_version_cannot_be_evaluated() -> None:
    advisory = {
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "pkg"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
            }
        ]
    }
    result = evaluate_advisory(advisory, "pkg", "not-pep-440")
    assert result.affected is False
    assert result.evaluated is False


def test_an_affected_range_wins_over_an_unevaluable_one() -> None:
    advisory = {
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "pkg"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "bogus!"}]},
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0"}]},
                ],
            }
        ]
    }
    result = evaluate_advisory(advisory, "pkg", "1.0")
    assert result.affected is True
    assert result.evaluated is True

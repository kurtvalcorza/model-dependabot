"""Severity and its origin (T026, research R3)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from model_dependabot.matching.severity import (
    cvss3_base_score,
    cvss4_base_score,
    cvss_band,
    severity_of,
)

OSV = Path(__file__).resolve().parent.parent / "fixtures" / "osv"


def _recorded(advisory_id: str) -> dict[str, Any]:
    return json.loads((OSV / f"vuln-{advisory_id}.json").read_text(encoding="utf-8"))


def test_database_specific_severity_comes_first() -> None:
    assert severity_of(_recorded("GHSA-cp9v-662q-vvx9")) == ("HIGH", "database_specific")
    assert severity_of(_recorded("GHSA-24rc-8hj2-v98c")) == ("MODERATE", "database_specific")


def test_medium_is_read_as_moderate() -> None:
    advisory = {"database_specific": {"severity": "medium"}}
    assert severity_of(advisory) == ("MODERATE", "database_specific")


def test_a_cvss_v3_vector_gives_the_band() -> None:
    advisory = _recorded("GHSA-24rc-8hj2-v98c")
    del advisory["database_specific"]
    assert severity_of(advisory) == ("MODERATE", "cvss_v3")


def test_an_unrecognised_qualitative_value_falls_back_to_cvss() -> None:
    advisory = {
        "database_specific": {"severity": "SEVERE"},
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
    }
    assert severity_of(advisory) == ("CRITICAL", "cvss_v3")


def test_a_numeric_cvss_v4_score_gives_the_band() -> None:
    advisory = {"severity": [{"type": "CVSS_V4", "score": "8.7"}]}
    assert severity_of(advisory) == ("HIGH", "cvss_v4")


def test_a_cvss_v4_vector_gives_the_band() -> None:
    # The recorded vector scores 8.7, matching the advisory's own database_specific HIGH.
    advisory = _recorded("GHSA-cp9v-662q-vvx9")
    del advisory["database_specific"]
    assert severity_of(advisory) == ("HIGH", "cvss_v4")


@pytest.mark.parametrize(
    ("vector", "score"),
    [
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.3),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N", 8.7),
    ],
)
def test_cvss4_base_score(vector: str, score: float) -> None:
    assert cvss4_base_score(vector) == score


def test_an_invalid_cvss_vector_gives_unknown() -> None:
    advisory = {"severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N"}]}
    assert severity_of(advisory) == ("UNKNOWN", "unknown")


def test_no_severity_is_unknown() -> None:
    assert severity_of(_recorded("PYSEC-2019-64")) == ("UNKNOWN", "unknown")


@pytest.mark.parametrize(
    ("vector", "score"),
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H", 6.5),
        ("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5),
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", 3.7),
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ],
)
def test_cvss3_base_score(vector: str, score: float) -> None:
    assert cvss3_base_score(vector) == score


def test_an_invalid_cvss3_vector_is_rejected() -> None:
    with pytest.raises(ValueError):
        cvss3_base_score("CVSS:3.1/AV:N/AC:L")


@pytest.mark.parametrize(
    ("score", "band"),
    [
        (0.1, "LOW"),
        (3.9, "LOW"),
        (4.0, "MODERATE"),
        (6.9, "MODERATE"),
        (7.0, "HIGH"),
        (8.9, "HIGH"),
        (9.0, "CRITICAL"),
        (10.0, "CRITICAL"),
    ],
)
def test_cvss_bands(score: float, band: str) -> None:
    assert cvss_band(score) == band


# --- The highest scoreable entry (review F6, amended 2026-10-31) ---------------------------------

V3_CRITICAL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"  # 9.8
V4_MODERATE = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"


def test_the_highest_scoreable_entry_wins_not_the_first() -> None:
    assert cvss_band(cvss4_base_score(V4_MODERATE)) == "MODERATE"
    advisory = {
        "severity": [
            {"type": "CVSS_V4", "score": V4_MODERATE},
            {"type": "CVSS_V3", "score": V3_CRITICAL},
        ]
    }
    assert severity_of(advisory) == ("CRITICAL", "cvss_v3")


def test_a_tie_keeps_the_first_entry_origin() -> None:
    advisory = {
        "severity": [{"type": "CVSS_V4", "score": "9.8"}, {"type": "CVSS_V3", "score": V3_CRITICAL}]
    }
    assert severity_of(advisory) == ("CRITICAL", "cvss_v4")


@pytest.mark.parametrize("score", ["inf", "-inf", "nan", "NaN", "10.1", "-0.1", "1e3"])
def test_a_score_that_is_not_finite_or_outside_0_to_10_is_unscoreable(score: str) -> None:
    assert severity_of({"severity": [{"type": "CVSS_V3", "score": score}]}) == (
        "UNKNOWN",
        "unknown",
    )
    advisory = {
        "severity": [{"type": "CVSS_V3", "score": score}, {"type": "CVSS_V4", "score": "5.0"}]
    }
    assert severity_of(advisory) == ("MODERATE", "cvss_v4")


@pytest.mark.parametrize("score", ["0", "0.0", "10", "10.0"])
def test_the_ends_of_the_range_are_scoreable(score: str) -> None:
    assert severity_of({"severity": [{"type": "CVSS_V3", "score": score}]})[1] == "cvss_v3"


def test_database_specific_still_comes_before_a_higher_cvss_score() -> None:
    advisory = {
        "database_specific": {"severity": "LOW"},
        "severity": [{"type": "CVSS_V3", "score": V3_CRITICAL}],
    }
    assert severity_of(advisory) == ("LOW", "database_specific")

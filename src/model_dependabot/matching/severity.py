"""Advisory severity and its origin (research R3).

In order: the advisory's ``database_specific.severity`` (``LOW``, ``MODERATE``, ``HIGH``,
``CRITICAL``); else the band of a CVSS score in ``severity[]``; else ``UNKNOWN``. The origin is
returned with the value so the alert can show where it came from: ``database_specific``,
``cvss_v3``, ``cvss_v4`` or ``unknown``.

CVSS v3.x and v4.0 vectors are scored with the ``cvss`` package (pinned in ``pyproject.toml``),
which implements the specifications' base-score formulas, including FIRST's v4 macro-vector table.
A record that gives the number itself is used as given.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from cvss import CVSS3, CVSS4, CVSSError

SEVERITIES = ("CRITICAL", "HIGH", "MODERATE", "LOW", "UNKNOWN")
_QUALITATIVE = {
    "LOW": "LOW",
    "MODERATE": "MODERATE",
    "MEDIUM": "MODERATE",
    "HIGH": "HIGH",
    "CRITICAL": "CRITICAL",
}


def severity_rank(severity: str) -> int:
    """Sort position, most severe first."""
    return SEVERITIES.index(severity) if severity in SEVERITIES else len(SEVERITIES)


def cvss_band(score: float) -> str:
    """The qualitative band of a CVSS score, named as GitHub's advisories name them."""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MODERATE"
    return "LOW"


def cvss3_base_score(vector: str) -> float:
    """The base score of a CVSS v3.0 or v3.1 vector."""
    if not vector.startswith("CVSS:3."):
        raise ValueError(f"not a CVSS v3 vector: {vector!r}")
    try:
        return float(CVSS3(vector).base_score)
    except CVSSError as error:
        raise ValueError(f"invalid CVSS v3 vector {vector!r}: {error}") from None


def cvss4_base_score(vector: str) -> float:
    """The base score of a CVSS v4.0 vector."""
    if not vector.startswith("CVSS:4.0/"):
        raise ValueError(f"not a CVSS v4 vector: {vector!r}")
    try:
        return float(CVSS4(vector).base_score)
    except CVSSError as error:
        raise ValueError(f"invalid CVSS v4 vector {vector!r}: {error}") from None


_SCORERS = {"CVSS_V3": ("cvss_v3", cvss3_base_score), "CVSS_V4": ("cvss_v4", cvss4_base_score)}


def _score(entry: Mapping[str, Any]) -> tuple[float, str] | None:
    scorer = _SCORERS.get(str(entry.get("type")))
    if scorer is None:
        return None
    origin, score_vector = scorer
    text = str(entry.get("score", ""))
    try:
        return float(text), origin
    except ValueError:
        pass
    try:
        return score_vector(text), origin
    except ValueError:
        return None


def severity_of(advisory: Mapping[str, Any]) -> tuple[str, str]:
    """The advisory's severity and where it came from (research R3)."""
    qualitative = (advisory.get("database_specific") or {}).get("severity")
    if isinstance(qualitative, str) and qualitative.upper() in _QUALITATIVE:
        return _QUALITATIVE[qualitative.upper()], "database_specific"
    for entry in advisory.get("severity") or []:
        scored = _score(entry)
        if scored is not None:
            return cvss_band(scored[0]), scored[1]
    return "UNKNOWN", "unknown"

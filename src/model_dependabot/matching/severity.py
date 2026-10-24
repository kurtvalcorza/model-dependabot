"""Advisory severity and its origin (research R3).

In order: the advisory's ``database_specific.severity`` (``LOW``, ``MODERATE``, ``HIGH``,
``CRITICAL``); else the band of a CVSS score in ``severity[]``; else ``UNKNOWN``. The origin is
returned with the value so the alert can show where it came from: ``database_specific``,
``cvss_v3``, ``cvss_v4`` or ``unknown``.

CVSS v3.x vectors are scored here with the specification's base-score formula. A CVSS v4 vector is
scored only when the record gives the number itself: scoring a v4 vector needs FIRST's macro-vector
lookup table, which this module does not carry, so a v4 vector alone gives ``UNKNOWN``.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from typing import Any

SEVERITIES = ("CRITICAL", "HIGH", "MODERATE", "LOW", "UNKNOWN")
_QUALITATIVE = {
    "LOW": "LOW",
    "MODERATE": "MODERATE",
    "MEDIUM": "MODERATE",
    "HIGH": "HIGH",
    "CRITICAL": "CRITICAL",
}

_WEIGHTS: dict[str, dict[str, float]] = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_PRIVILEGES = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}


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


def _round_up(value: float) -> float:
    """CVSS v3.1 Roundup: the smallest one-decimal number not below ``value``."""
    whole = round(value * 100_000)
    if whole % 10_000 == 0:
        return whole / 100_000
    return (math.floor(whole / 10_000) + 1) / 10.0


def cvss3_base_score(vector: str) -> float:
    """The base score of a CVSS v3.0 or v3.1 vector."""
    parts = vector.split("/")
    if not parts[0].startswith("CVSS:3."):
        raise ValueError(f"not a CVSS v3 vector: {vector!r}")
    metrics = dict(part.split(":", 1) for part in parts[1:] if ":" in part)
    try:
        scope = metrics["S"]
        privileges = _PRIVILEGES[scope][metrics["PR"]]
        weights = {key: _WEIGHTS[key][metrics[key]] for key in _WEIGHTS}
    except KeyError as missing:
        raise ValueError(f"incomplete CVSS v3 vector {vector!r}: {missing}") from None
    impact_base = 1 - (1 - weights["C"]) * (1 - weights["I"]) * (1 - weights["A"])
    if scope == "U":
        impact = 6.42 * impact_base
    else:
        impact = 7.52 * (impact_base - 0.029) - 3.25 * (impact_base - 0.02) ** 15
    exploitability = 8.22 * weights["AV"] * weights["AC"] * privileges * weights["UI"]
    if impact <= 0:
        return 0.0
    total = impact + exploitability if scope == "U" else 1.08 * (impact + exploitability)
    return _round_up(min(total, 10.0))


def _score(entry: Mapping[str, Any]) -> tuple[float, str] | None:
    kind = entry.get("type")
    text = str(entry.get("score", ""))
    origin = {"CVSS_V3": "cvss_v3", "CVSS_V4": "cvss_v4"}.get(str(kind))
    if origin is None:
        return None
    try:
        return float(text), origin
    except ValueError:
        pass
    if kind == "CVSS_V3":
        try:
            return cvss3_base_score(text), origin
        except ValueError:
            return None
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

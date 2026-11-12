"""Per-kind tally of discovery against labelled held-out projects (feature 003; FR-026, SC-008).

Usage::

    python -I research/heldout/discover_eval.py LABELS.json [--json]

``LABELS.json`` names each held-out project folder and the dependencies a person labelled in it,
written before discovery is run on it::

    {"projects": [{"path": "projects/a", "expected": [
        {"kind": "package", "key": "torch==2.5.1"},
        {"kind": "weight_file", "key": "runs/best.safetensors"},
        {"kind": "base_model", "key": "org/base"}]}]}

A relative ``path`` is read from the labels file's folder. Each candidate discovery proposes is
reduced to the same key (``KEYS`` below) and compared per kind. The result is, for every kind,
how many labelled dependencies were found, how many were missed and how many candidates were
proposed that no label names. There is deliberately no pooled accuracy figure: the kinds differ
in how they are found and in how many there are, so a pooled number would hide the weak kinds.

Discovery runs offline here (no ``--upstream``), exactly as ``model-dependabot discover`` does,
and nothing is written. The report this produces is kept apart from the test suite.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from model_dependabot.discover.candidate import KINDS
from model_dependabot.discover.project import discover


def _package(identity: Mapping[str, Any]) -> str:
    name = str(identity.get("name") or identity.get("requirement") or "")
    version = identity.get("version")
    return f"{name}=={version}" if version else name


KEYS: dict[str, Callable[[Mapping[str, Any]], str]] = {
    "package": _package,
    "weight_file": lambda identity: str(identity.get("path")),
    "base_model": lambda identity: str(identity.get("hub_repo")).lower(),
    "dataset": lambda identity: str(identity.get("hub_repo") or identity.get("doi")).lower(),
    "licence": lambda identity: str(identity.get("spdx") or identity.get("licence")),
    "environment": lambda identity: str(identity.get("lock")),
}


def _normalise(kind: str, key: str) -> str:
    return key.lower() if kind in ("base_model", "dataset") else key


def tally_project(root: Path, expected: list[Mapping[str, str]]) -> dict[str, Counter[str]]:
    """Found, missed and wrongly proposed counts per kind for one project."""
    result = discover(root)
    proposed: dict[str, set[str]] = {kind: set() for kind in KINDS}
    for item in result["candidates"]:
        proposed[item["kind"]].add(KEYS[item["kind"]](item["identity"]))
    labelled: dict[str, set[str]] = {kind: set() for kind in KINDS}
    for label in expected:
        if label["kind"] not in KINDS:
            raise ValueError(f"unknown kind {label['kind']!r} in the labels of {root}")
        labelled[label["kind"]].add(_normalise(label["kind"], label["key"]))
    counts: dict[str, Counter[str]] = {}
    for kind in KINDS:
        counts[kind] = Counter(
            found=len(labelled[kind] & proposed[kind]),
            missed=len(labelled[kind] - proposed[kind]),
            wrongly_proposed=len(proposed[kind] - labelled[kind]),
        )
    return counts


def tally(labels_path: Path) -> dict[str, Any]:
    labels = json.loads(labels_path.read_text(encoding="utf-8"))
    totals: dict[str, Counter[str]] = {kind: Counter() for kind in KINDS}
    for project in labels["projects"]:
        root = Path(project["path"])
        if not root.is_absolute():
            root = labels_path.parent / root
        for kind, counts in tally_project(root, project["expected"]).items():
            totals[kind].update(counts)
    return {
        "projects": len(labels["projects"]),
        "per_kind": {
            kind: {name: totals[kind][name] for name in ("found", "missed", "wrongly_proposed")}
            for kind in KINDS
        },
    }


def table(report: Mapping[str, Any]) -> str:
    lines = [
        f"Discovery on {report['projects']} held-out projects (per kind; never pooled)",
        "",
        "| Kind | Found | Missed | Wrongly proposed |",
        "| :-- | --: | --: | --: |",
    ]
    for kind, counts in report["per_kind"].items():
        lines.append(
            f"| {kind} | {counts['found']} | {counts['missed']} | {counts['wrongly_proposed']} |"
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("labels", type=Path, metavar="LABELS.json")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args(argv)
    report = tally(args.labels)
    print(json.dumps(report, indent=2) if args.json else table(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())

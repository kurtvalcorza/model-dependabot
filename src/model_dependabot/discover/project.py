"""One discovery run over a project folder (data-model.md, Discovery result; FR-015 to FR-023)."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from model_dependabot.discover import propose
from model_dependabot.discover.candidate import STATEMENT, utc_text
from model_dependabot.discover.compare import compare, mark_version_conflicts
from model_dependabot.discover.model_card import discover_card
from model_dependabot.discover.python_deps import discover_python
from model_dependabot.discover.upstream import look_up
from model_dependabot.discover.walk import LIMITS, Limits, walk
from model_dependabot.discover.weights import discover_weights
from model_dependabot.manifest import Manifest
from model_dependabot.sources.fetcher import Fetcher

KIND_ORDER = ("weight_file", "environment", "package", "base_model", "dataset", "licence")


def discover(
    root: Path,
    *,
    manifest: Manifest | None = None,
    fetcher: Fetcher | None = None,
    now: Callable[[], datetime] | None = None,
    limits: Limits = LIMITS,
) -> dict[str, Any]:
    """The discovery result for ``root``; the hub is read only when ``fetcher`` is given."""
    root = root.resolve()
    observed_at = utc_text((now or (lambda: datetime.now(UTC)))())
    found = walk(root, limits)
    candidates: list[dict[str, Any]] = []
    skipped = list(found.skipped)
    for read in (discover_weights, discover_python, discover_card):
        more, missed = read(found, observed_at, limits)
        candidates += more
        skipped += missed
    candidates.sort(key=lambda item: KIND_ORDER.index(item["kind"]))
    mark_version_conflicts(candidates)
    if fetcher is not None:
        look_up(candidates, fetcher)
    declared_not_seen = [] if manifest is None else compare(candidates, manifest, root)
    return {
        "project": str(root),
        "observed_at": observed_at,
        "upstream": fetcher is not None,
        "statement": STATEMENT,
        "candidates": candidates,
        "declared_not_seen": declared_not_seen,
        "skipped": skipped,
        "limits": limits.as_dict(),
        "output": None,
    }


def write_proposal(
    result: dict[str, Any], output: Path, *, model_id: str, force: bool
) -> dict[str, Any]:
    """Write the proposed manifest for ``result`` to ``output`` and record it in the result."""
    root = Path(result["project"])
    text = propose.render(result, model_id, root, output.absolute())
    propose.write(text, output, force=force)
    result["output"] = {"path": str(output), "written": True}
    return result

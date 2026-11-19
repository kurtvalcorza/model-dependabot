"""The affected entry and its relationship in the view (T016, US1 scenarios 1 to 5, Edge Cases)."""

from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from model_dependabot.cli import main, make_handlers
from model_dependabot.lifecycle import dismiss_alert
from model_dependabot.sources.fetcher import RecordedFetcher
from model_dependabot.store import Store

NOW = datetime(2026, 11, 20, 9, 0, tzinfo=UTC)


def show(db: Path, alert_id: int, *, json_out: bool = True) -> Any:
    out = io.StringIO()
    handlers = make_handlers(fetcher=RecordedFetcher(db.parent / "none"), now=lambda: NOW)
    argv = ["alert", "show", str(alert_id), "--advice", "--db", str(db)]
    with redirect_stdout(out):
        assert main([*argv, "--json"] if json_out else argv, handlers=handlers) == 0
    return json.loads(out.getvalue()) if json_out else out.getvalue()


EXPECTED = {
    "weight_file_scan": ("weight_file", "[[weights]]", "weight file of this model", 1),
    "hub_scan": ("weight_file", "[[weights]]", "weight file of this model", 1),
    "format_policy": ("weight_file", "[[weights]]", "weight file of this model", 1),
    "globals_policy": ("weight_file", "[[weights]]", "weight file of this model", 1),
    "package_advisory": (
        "package",
        "[environment] lock",
        "package pinned in this model's environment lock",
        1,
    ),
    "dataset_retracted": ("dataset", "[[datasets]]", "declared dataset", 1),
    "paper_retracted": ("dataset", "[[datasets]]", "paper cited by a declared dataset", 2),
    "dataset_removed": ("dataset", "[[datasets]]", "declared dataset", 1),
    "dataset_not_findable": ("dataset", "[[datasets]]", "declared dataset", 1),
    "licence_changed": ("base_model", "[base_model]", "declared base model", 1),
    "licence_changed_dataset": ("dataset", "[[datasets]]", "declared dataset", 1),
    "base_model_disabled": ("base_model", "[base_model]", "declared base model", 1),
    "base_model_unavailable": ("base_model", "[base_model]", "declared base model", 1),
}


def test_one_alert_per_family_names_its_entry_and_relationship(
    advice_db: tuple[Path, dict[str, int]],
) -> None:
    db, ids = advice_db
    for name, (kind, section, value, steps) in EXPECTED.items():
        advice = show(db, ids[name])["advice"]
        entry, related = advice["entry"], advice["relationship"]
        assert (entry["status"], entry["kind"]) == ("resolved", kind), name
        assert entry["places"][0]["section"] == section, name
        assert entry["in_current_version"] is True, name
        assert (related["value"], related["steps_from_model"]) == (value, steps), name
        assert related["basis"]["declared_by"] == "owner", name
        assert advice["runtime_use"]["state"] == "unknown", name


def test_a_repository_keyed_alert_resolves_by_repository(
    advice_db: tuple[Path, dict[str, int]],
) -> None:
    db, ids = advice_db
    entry = show(db, ids["dataset_removed"])["advice"]["entry"]
    assert entry["matched_by"] == "repository"
    assert [place["version"] for place in entry["places"]] == [2, 1]
    assert entry["places"][0]["revision"] != entry["places"][1]["revision"]


def test_a_fixed_alert_names_the_last_holding_and_the_fixing_version(
    advice_db: tuple[Path, dict[str, int]],
) -> None:
    db, ids = advice_db
    entry = show(db, ids["fixed"])["advice"]["entry"]
    assert entry["in_current_version"] is False
    assert (entry["last_held_in_version"], entry["closed_by_version"]) == (1, 2)
    text = show(db, ids["fixed"], json_out=False)
    assert "not in the current version; opened in v1; last held in v1, fixed by v2" in text


def test_several_places_are_listed_in_a_fixed_order(advice_db: tuple[Path, dict[str, int]]) -> None:
    db, ids = advice_db
    places = show(db, ids["package_advisory"])["advice"]["entry"]["places"]
    assert [place["version"] for place in places] == [2, 1]


def test_a_dismissal_not_used_at_runtime_shows_the_declaration(
    advice_db: tuple[Path, dict[str, int]],
) -> None:
    db, ids = advice_db
    with Store(db, now=lambda: NOW) as store:
        dismiss_alert(
            store, ids["package_advisory"], reason="not_used_at_runtime", by="Owner", note="unused"
        )
    use = show(db, ids["package_advisory"])["advice"]["runtime_use"]
    assert use["state"] == "declared" and use["polarity"] == "not_used"
    assert use["basis"] == {
        "by": "Owner",
        "at": "2026-11-20T09:00:00Z",
        "note": "unused",
        "alert_id": ids["package_advisory"],
    }
    text = show(db, ids["package_advisory"], json_out=False)
    assert "Runtime use: declared not_used by Owner at 2026-11-20T09:00:00Z: unused" in text


def test_an_imported_version_is_never_shown_as_the_owners_own(
    advice_db: tuple[Path, dict[str, int]],
) -> None:
    db, ids = advice_db
    advice = show(db, ids["imported_package"])["advice"]
    assert advice["relationship"]["basis"] == {
        "declared_by": "imported",
        "origin": "import",
        "section": None,
        "version": 1,
    }
    text = show(db, ids["imported_package"], json_out=False)
    assert "(imported declaration, v1)" in text
    assert "v1 import, no manifest section, 12.3.0" in text

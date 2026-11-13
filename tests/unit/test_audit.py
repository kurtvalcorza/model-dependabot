"""The inventory audit's rules (T027; FR-008 to FR-012, research A12, data-model.md Audit report).

Each test builds the stored state it needs with the store, then audits it. The audit only reads.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from model_dependabot.assurance.audit import (
    STATEMENT,
    entry_status,
    relevant_sources,
)
from model_dependabot.assurance.audit import (
    audit_report as audit,
)
from model_dependabot.store import Store

START = datetime(2026, 11, 10, 0, 0, tzinfo=UTC)
SHA = "sha256:" + "a" * 64
PICKLE_SHA = "sha256:" + "b" * 64
COMMIT = "c" * 40


class Clock:
    def __init__(self) -> None:
        self.now = START

    def __call__(self) -> datetime:
        return self.now


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def store(tmp_path: Path, clock: Clock) -> Store:
    with Store(tmp_path / "md.db", now=clock) as opened:
        yield opened


def weight(**fields: Any) -> dict[str, Any]:
    entry = {
        "kind": "weight_file",
        "identifier": SHA,
        "pinned": True,
        "location": "weights/model.safetensors",
        "format": "safetensors",
        "can_run_code": False,
        "format_origin": "bytes",
    }
    return entry | fields


def package(**fields: Any) -> dict[str, Any]:
    entry = {
        "kind": "package",
        "identifier": "pkg:pypi/torch@2.5.1",
        "pinned": True,
        "name": "torch",
        "version": "2.5.1",
        "hashes": ["sha256:" + "d" * 64],
    }
    return entry | fields


def base_model() -> dict[str, Any]:
    return {
        "kind": "base_model",
        "identifier": f"pkg:huggingface/o/base@{COMMIT}",
        "pinned": True,
        "name": "o/base",
        "version": COMMIT,
    }


def hub_dataset() -> dict[str, Any]:
    return {
        "kind": "dataset",
        "identifier": f"hf-dataset:o/data@{COMMIT}",
        "pinned": True,
        "hub_repo": "o/data",
        "hub_revision": COMMIT,
    }


def doi_dataset(doi: str = "10.5555/example") -> dict[str, Any]:
    return {"kind": "dataset", "identifier": doi, "pinned": True}


def gap(kind: str, reason: str) -> dict[str, Any]:
    return {"kind": kind, "identifier": None, "pinned": False, "gap_reason": reason}


def register(
    store: Store, entries: list[dict[str, Any]], origin: str | None = "manifest", model: str = "m"
) -> int:
    if store.get_model(model) is None:
        store.add_model(model)
    return store.add_version(model, {}, "e" * 64, entries, origin=origin)


def run(store: Store, clock: Clock, sources: dict[str, str], scope: str = "m", hours: float = 1):
    clock.now += timedelta(hours=hours)
    run_id = store.start_check_run(scope=scope)
    store.finish_check_run(run_id, sources)
    return run_id


# --- entry status (research A12) ------------------------------------------------------------------


def _claim(verification: str) -> dict[str, Any]:
    return {"claim": "format", "verification": verification}


@pytest.mark.parametrize(
    ("entry", "claims", "latest", "expected"),
    [
        (weight(), [_claim("measured"), _claim("owner")], None, "verified"),
        (weight(), [_claim("confirmed")], None, "verified"),
        (weight(), [_claim("unverified"), _claim("owner")], None, "declared-but-unverified"),
        (weight(), [_claim("contradicted"), _claim("unverified")], None, "conflicting"),
        (gap("package", "no exact version"), [], None, "unavailable"),
        (weight(), [_claim("unverified")], {"outcome": "unreadable"}, "unavailable"),
    ],
)
def test_entry_status(
    entry: dict[str, Any], claims: list[dict[str, Any]], latest: Any, expected: str
) -> None:
    assert entry_status(entry, claims, latest) == expected


# --- relevant sources -----------------------------------------------------------------------------


def test_relevant_sources_by_entry_kind(store: Store) -> None:
    store.set_routing("10.5555/crossref", agency="Crossref")
    store.set_routing("10.5555/datacite", agency="DataCite", repository="zenodo")
    cases = {
        "package": (package(), "manifest", {"osv"}),
        "local pickle": (
            weight(identifier=PICKLE_SHA, format="pickle", can_run_code=True),
            "manifest",
            {"picklescan"},
        ),
        "hub weight": (
            weight(
                location=None,
                hub_repo="o/n",
                hub_revision=COMMIT,
                hub_file="model.safetensors",
                format_origin="name",
            ),
            "manifest",
            {"hf-scan"},
        ),
        "imported code-free": (weight(format_origin="import"), "import", {"format-check"}),
        "base model": (base_model(), "manifest", {"hf-hub"}),
        "hub dataset": (hub_dataset(), "manifest", {"hf-hub", "hf-takedowns"}),
        "crossref DOI": (doi_dataset("10.5555/crossref"), "manifest", {"crossref"}),
        "datacite DOI": (doi_dataset("10.5555/datacite"), "manifest", {"datacite", "zenodo"}),
        "local code-free": (weight(), "manifest", set()),
        "gap": (gap("weight_file", "no revision"), "manifest", set()),
    }
    for name, (entry, origin, expected) in cases.items():
        assert set(relevant_sources(store, entry, origin)) == expected, name


# --- the report -----------------------------------------------------------------------------------


def test_a_never_checked_model_says_so_and_lists_every_source_as_not_checked(
    store: Store,
) -> None:
    register(store, [weight(), package(), gap("package", "no exact version")])
    report = audit(store, "m")
    assert report["findings"]["state"] == "not_yet_checked"
    assert report["summary"]["checked"] is False
    assert report["statement"] == STATEMENT
    [osv] = report["coverage"]["sources"]
    assert (osv["source"], osv["status"], osv["last_run_id"]) == ("osv", "not checked", None)
    assert osv["relevant_entries"] == ["pkg:pypi/torch@2.5.1"]
    assert report["summary"]["sources_not_checked"] == 1


def test_claims_and_statuses_are_reported_per_entry(store: Store) -> None:
    register(store, [weight(format_origin="import"), package()], origin="import")
    report = audit(store, "m")
    entries = {e["kind"]: e for e in report["assurance"]["entries"]}
    assert entries["weight_file"]["status"] == "declared-but-unverified"
    assert {c["claim"] for c in entries["weight_file"]["claims"]} == {
        "format",
        "can_run_code",
        "sha256",
    }
    assert entries["package"]["claims"][0]["reason"] == "no check confirms this claim"
    assert report["summary"]["declared_but_unverified"] == 2


def test_the_latest_run_after_registration_that_asked_the_source_counts(
    store: Store, clock: Clock
) -> None:
    store.add_model("m")
    before = run(store, clock, {"osv": "ok"})  # before the version: does not count
    clock.now += timedelta(minutes=1)
    register(store, [package()])
    other = run(store, clock, {"osv": "ok"}, scope="someone-else")  # another model
    asked = run(store, clock, {"osv": "failed: HTTP 503 after 4 attempts"}, scope="all")
    not_asked = run(store, clock, {"picklescan": "ok"})  # did not ask osv
    report = audit(store, "m")
    [osv] = report["coverage"]["sources"]
    assert osv["last_run_id"] == asked
    assert osv["status"] == "failed: HTTP 503 after 4 attempts"
    assert osv["last_ok_at"] is None
    assert report["summary"]["sources_failed"] == 1
    # The only relevant source failed, so the version is not checked (review F6).
    assert report["summary"]["checked"] is False
    assert {before, other, not_asked}.isdisjoint({osv["last_run_id"]})


def test_a_source_older_than_the_threshold_is_stale(store: Store, clock: Clock) -> None:
    register(store, [package()])
    run(store, clock, {"osv": "ok"})
    clock.now += timedelta(hours=30)
    [osv] = audit(store, "m")["coverage"]["sources"]
    assert osv["stale"] is True and osv["age_hours"] == pytest.approx(30.0)
    [fresh] = audit(store, "m", stale_after_hours=48)["coverage"]["sources"]
    assert fresh["stale"] is False


def test_uncheckable_entries_are_listed_with_their_reasons(store: Store) -> None:
    register(
        store,
        [
            gap("dataset", "no DOI"),
            weight(
                identifier="sha256:" + "f" * 64,
                location="model.h5",
                format="unknown",
                can_run_code=None,
            ),
            doi_dataset("10.5555/unrouted"),
        ],
    )
    uncheckable = audit(store, "m")["coverage"]["uncheckable"]
    reasons = {(item["kind"], item["reason"]) for item in uncheckable}
    assert ("dataset", "no DOI") in reasons
    assert ("weight_file", "the file's format is unknown") in reasons
    assert any(kind == "dataset" and "agency" in reason for kind, reason in reasons)


def test_undeclared_kinds(store: Store) -> None:
    register(store, [weight()])
    kinds = audit(store, "m")["assurance"]["undeclared_kinds"]
    assert kinds == ["environment", "base_model", "datasets"]
    register(store, [package(), base_model(), hub_dataset()], model="other")
    assert audit(store, "other")["assurance"]["undeclared_kinds"] == ["weights"]


def test_an_older_version_can_be_audited(store: Store) -> None:
    register(store, [weight()])
    register(store, [package()])
    assert audit(store, "m", version=1)["version"] == 1
    assert audit(store, "m")["version"] == 2


def test_unknown_models_and_versions_are_refused(store: Store) -> None:
    register(store, [weight()])
    with pytest.raises(LookupError):
        audit(store, "nobody")
    with pytest.raises(LookupError):
        audit(store, "m", version=7)


# --- PR #15 round 1 (reviews F1, F3, F6, F7) ------------------------------------------------------


def test_an_older_version_is_not_credited_with_runs_that_checked_a_later_one(
    store: Store, clock: Clock
) -> None:
    """Review F1: a check examines the latest version only."""
    register(store, [package(identifier="pkg:pypi/oldvuln@1.0", name="oldvuln", version="1.0")])
    clock.now += timedelta(hours=1)
    register(store, [package()])
    run(store, clock, {"osv": "ok"})
    old = audit(store, "m", version=1)
    assert old["findings"]["state"] == "not_yet_checked"
    [osv] = old["coverage"]["sources"]
    assert (osv["status"], osv["last_run_id"]) == ("not checked", None)
    assert audit(store, "m")["findings"]["state"] == "checked"


def test_a_run_that_asked_no_relevant_source_has_not_checked_the_version(
    store: Store, clock: Clock
) -> None:
    """Review F6: findings say checked only once a relevant source succeeded."""
    register(store, [package()])
    run(store, clock, {"hf-hub": "failed: HTTP 503 after 4 attempts"})
    report = audit(store, "m")
    assert report["findings"]["state"] == "not_yet_checked"
    assert report["summary"]["checked"] is False
    run(store, clock, {"osv": "ok"})
    assert audit(store, "m")["summary"]["checked"] is True


def test_a_contradicted_code_free_claim_is_audited_as_the_pickle_it_is(store: Store) -> None:
    """Review F3: picklescan is relevant to the file the bytes showed, not to the claim."""
    register(store, [weight(format_origin="import")], origin="import")
    evidence = store.add_evidence(
        source="format-check", url="", retrieved_at=START, matched_identifier=SHA, body=b"{}"
    )
    store.add_claim_check(
        model_id="m",
        version=1,
        entry_identifier=SHA,
        claim="code_free",
        run_id=None,
        outcome="contradicted",
        measured_format="pickle",
        measured_can_run_code=True,
        reason="the bytes show pickle",
        evidence_id=evidence,
    )
    sources = {item["source"]: item for item in audit(store, "m")["coverage"]["sources"]}
    assert sources["picklescan"]["relevant_entries"] == [SHA]


@pytest.mark.parametrize(
    ("entry", "reason"),
    [
        (
            weight(
                location=None,
                hub_repo="o/n",
                hub_revision="main",
                hub_file="model.safetensors",
                format_origin="import",
            ),
            "not pinned to a commit",
        ),
        (weight(location=None, format_origin="import"), "no location"),
    ],
)
def test_a_claim_format_check_can_never_read_is_uncheckable(
    store: Store, entry: dict[str, Any], reason: str
) -> None:
    """Review F7: format-check skips these, so it is not listed as covering them."""
    register(store, [entry], origin="import")
    report = audit(store, "m")
    assert "format-check" not in {item["source"] for item in report["coverage"]["sources"]}
    [item] = report["coverage"]["uncheckable"]
    assert reason in item["reason"]


# --- PR #15 round 2 (G1, G5, S2) ------------------------------------------------------------------


def test_a_run_counts_for_the_version_it_checked_even_within_one_second(
    store: Store, clock: Clock
) -> None:
    """G1: a run started in the same second as the next registration checked the older version."""
    register(store, [package()])
    clock.now += timedelta(hours=1)
    run_id = store.start_check_run(scope="m")
    store.add_check_run_target(run_id, "m", 1)  # as run_check records it
    store.finish_check_run(run_id, {"osv": "ok"})
    register(store, [package(identifier="pkg:pypi/newvuln@9.9", name="newvuln", version="9.9")])
    assert store.registered_at("m", 2) == store.get_check_run(run_id)["started_at"]
    assert audit(store, "m", version=1)["findings"]["state"] == "checked"
    newer = audit(store, "m")
    assert newer["findings"]["state"] == "not_yet_checked"
    [osv] = newer["coverage"]["sources"]
    assert osv["last_run_id"] is None


def test_run_check_records_the_version_it_checked(store: Store) -> None:
    from model_dependabot.lifecycle import run_check

    register(store, [weight()])
    outcome = run_check(store, object(), ["m"], ["picklescan"])  # nothing here asks a source
    [checked] = store.check_runs_for("m", since="2000-01-01T00:00:00Z")
    assert (checked["run_id"], checked["version"]) == (outcome.run_id, 1)


def test_findings_are_partly_checked_until_every_relevant_source_succeeded(
    store: Store, clock: Clock
) -> None:
    """G5: one source succeeding does not make 0 alerts read as checked."""
    register(store, [package(), weight(identifier=PICKLE_SHA, format="pickle", can_run_code=True)])
    run(store, clock, {"osv": "ok"})
    report = audit(store, "m")
    assert report["findings"]["state"] == "partly_checked"
    assert report["summary"]["checked"] is False
    run(store, clock, {"picklescan": "ok"})
    report = audit(store, "m")
    assert report["findings"]["state"] == "checked"
    assert report["summary"]["checked"] is True


def test_a_hub_dataset_paper_at_crossref_makes_crossref_relevant(store: Store) -> None:
    """S2: the upstream check asks Crossref about the dataset's papers."""
    store.set_routing("10.5555/paper", agency="Crossref")
    entry = hub_dataset() | {"paper_dois": ["10.5555/paper"]}
    assert set(relevant_sources(store, entry, "manifest")) == {"hf-hub", "hf-takedowns", "crossref"}
    unrouted = hub_dataset() | {"paper_dois": ["10.5555/unknown"]}
    assert "crossref" not in relevant_sources(store, unrouted, "manifest")

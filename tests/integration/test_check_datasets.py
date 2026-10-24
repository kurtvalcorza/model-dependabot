"""Retraction and removal end to end, offline (T027; quickstart.md section 2, SC-001, SC-005,
SC-006).

The sources answer from the recordings under ``tests/fixtures`` or from states derived from them
by ``derive_upstream``; registering looks up each DOI's agency and repository from the same
recordings.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from conftest import fixture_json
from model_dependabot.cli import EXIT_OK, EXIT_SOURCE_FAILED, main, make_handlers
from model_dependabot.sources.datacite import doi_url
from model_dependabot.sources.doi_ra import doi_ra_url
from model_dependabot.sources.fetcher import RecordedFetcher
from model_dependabot.sources.hf import dataset_info_url
from model_dependabot.sources.hf_takedowns import INDEX_URL, NOTICE_LABEL

RETRACTED = "10.1177/1758835919874651"
ZENODO_FINDABLE = "10.5281/zenodo.3242074"
ZENODO_DELETED = "10.5281/zenodo.12584226"
DATACITE_MISSING = "10.5281/model-dependabot-fixture-does-not-exist"
MUXUE_SHA = "9408684b4d7410bf12651eff99ad6da74d746811"
LOG = "date,reported_content\n2026-09-04,yavon/muxue\n2023-03-06, Multiple\n"
UPSTREAM = ("hf-hub", "hf-takedowns", "crossref", "datacite", "zenodo", "figshare")


def _agency(doi: str, agency: str) -> dict[str, Any]:
    return {"url": doi_ra_url(doi), "status": 200, "body": [{"DOI": doi, "RA": agency}]}


def _datacite(doi: str, url: str) -> dict[str, Any]:
    body = fixture_json("datacite/findable")
    body["data"]["attributes"] |= {"doi": doi, "url": url}
    return {"url": doi_url(doi), "status": 200, "body": body}


EXTRA = {
    "ra-deleted": _agency(ZENODO_DELETED, "DataCite"),
    "ra-missing": _agency(DATACITE_MISSING, "DataCite"),
    "dc-deleted": _datacite(ZENODO_DELETED, "https://zenodo.org/records/12584226"),
}


def _no_retraction(body: dict) -> dict:
    body["message"].pop("updated-by")
    return body


@pytest.fixture
def cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> Callable[..., tuple[int, Any]]:
    db = tmp_path / "db" / "md.db"

    def invoke(*argv: str, fetcher: RecordedFetcher) -> tuple[int, Any]:
        code = main([*argv, "--db", str(db), "--json"], handlers=make_handlers(fetcher=fetcher))
        out = capsys.readouterr().out
        return code, json.loads(out) if out.strip() else None

    return invoke


def _manifest(directory: Path, model_id: str, datasets: list[str]) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    lines = ["[model]", f'id = "{model_id}"', 'name = "Dataset test model"', 'owner = "Owner"']
    for item in datasets:
        lines += ["", "[[datasets]]", item]
    path = directory / "model.toml"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


DATASETS = [
    f'doi = "{ZENODO_FINDABLE}"\npaper_doi = ["{RETRACTED}"]',
    f'doi = "{ZENODO_DELETED}"',
    f'hub = "hf:datasets/yavon/muxue"\nrevision = "{MUXUE_SHA}"',
    f'doi = "{DATACITE_MISSING}"',
]


def test_each_retracted_or_removed_dataset_gives_one_alert_and_a_clean_one_none(
    cli: Callable[..., tuple[int, Any]], tmp_path: Path, derive_upstream: Callable[..., Path]
) -> None:
    root = derive_upstream(changes={"hf_takedowns/index": lambda _: LOG}, extra=EXTRA)
    fetcher = RecordedFetcher(root)
    assert (
        cli("register", str(_manifest(tmp_path / "a", "watched", DATASETS)), fetcher=fetcher)[0]
        == 0
    )
    clean = [f'doi = "{ZENODO_FINDABLE}"']
    assert cli("register", str(_manifest(tmp_path / "b", "clean", clean)), fetcher=fetcher)[0] == 0

    code, checked = cli("check", "--all", "--source", ",".join(UPSTREAM), fetcher=fetcher)
    assert code == EXIT_OK
    assert checked["sources"] == dict.fromkeys(UPSTREAM, "ok")

    code, listed = cli("alerts", "watched", fetcher=fetcher)
    assert code == EXIT_OK
    found = {(a["kind"], a["cause"]["dataset"]): a for a in listed["alerts"]}
    hub_id = f"hf-dataset:yavon/muxue@{MUXUE_SHA}"
    assert set(found) == {
        ("paper_retracted", ZENODO_FINDABLE),
        ("dataset_removed", ZENODO_DELETED),
        ("dataset_removed", hub_id),
        ("dataset_not_findable", DATACITE_MISSING),
    }
    for alert in listed["alerts"]:
        assert (alert["severity"], alert["severity_origin"]) == ("HIGH", "policy")
    paper = found[("paper_retracted", ZENODO_FINDABLE)]
    assert paper["cause"]["paper_doi"] == RETRACTED
    assert {n["source"] for n in paper["cause"]["notices"]} == {"publisher", "retraction-watch"}
    zenodo = found[("dataset_removed", ZENODO_DELETED)]["cause"]
    assert (zenodo["removal_date"][:10], zenodo["reason"]) == ("2024-08-26", "duplicate")
    hub = found[("dataset_removed", hub_id)]["cause"]
    assert (hub["notice_date"], hub["notice_label"]) == ("2026-09-04", NOTICE_LABEL)

    for alert in listed["alerts"]:
        code, shown = cli("alert", "show", str(alert["alert_id"]), fetcher=fetcher)
        assert code == EXIT_OK and shown["evidence"]
        for evidence in shown["evidence"]:
            assert (
                evidence["source"] and evidence["retrieved_at"] and evidence["matched_identifier"]
            )
    code, listed = cli("alerts", "clean", fetcher=fetcher)
    assert listed["alerts"] == []


def test_a_retraction_opens_at_the_scheduled_run_after_it_appears(
    cli: Callable[..., tuple[int, Any]], tmp_path: Path, derive_upstream: Callable[..., Path]
) -> None:
    before = RecordedFetcher(
        derive_upstream(changes={"crossref/retracted": _no_retraction}, extra=EXTRA)
    )
    after = RecordedFetcher(derive_upstream(extra=EXTRA))
    manifest = _manifest(tmp_path / "a", "late", [DATASETS[0], DATASETS[2]])
    assert cli("register", str(manifest), fetcher=before)[0] == EXIT_OK
    wanted = {
        f"https://api.crossref.org/works/{RETRACTED}",
        doi_url(ZENODO_FINDABLE),
        "https://zenodo.org/api/records/3242074",
        dataset_info_url("yavon/muxue"),
        INDEX_URL,
    }
    for fetcher, expected in ((before, set()), (after, {"paper_retracted"})):
        fetcher.requests.clear()
        code, checked = cli("check", "--all", "--scheduled", fetcher=fetcher)
        assert code == EXIT_OK, checked
        assert checked["trigger"] == "scheduled"
        assert {name: checked["sources"][name] for name in UPSTREAM} == dict.fromkeys(
            UPSTREAM, "ok"
        )
        assert wanted <= {url for _, url, _ in fetcher.requests}
        _, listed = cli("alerts", "late", fetcher=fetcher)
        retractions = {a["kind"] for a in listed["alerts"] if a["kind"].endswith("retracted")}
        assert retractions == expected


def test_a_failed_source_exits_2_and_changes_no_alert(
    cli: Callable[..., tuple[int, Any]], tmp_path: Path, derive_upstream: Callable[..., Path]
) -> None:
    fetcher = RecordedFetcher(derive_upstream(extra=EXTRA))
    manifest = _manifest(tmp_path / "a", "m", [DATASETS[1]])
    assert cli("register", str(manifest), fetcher=fetcher)[0] == EXIT_OK
    failing = RecordedFetcher(derive_upstream(errors={"zenodo/deleted": "timeout"}, extra=EXTRA))
    code, checked = cli("check", "m", "--source", "datacite,zenodo", fetcher=failing)
    assert code == EXIT_SOURCE_FAILED
    assert checked["sources"]["zenodo"].startswith("failed")
    _, listed = cli("alerts", "m", fetcher=failing)
    assert listed["alerts"] == []

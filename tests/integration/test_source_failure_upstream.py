"""A failed upstream source changes no alert (T056; quickstart.md section 6, SC-005, FR-018).

The worked example has a base model (``openai-community/gpt2``), a Zenodo dataset DOI tied to the
retracted paper of ``crossref/retracted``, a Figshare dataset DOI and the disabled hub dataset
``yavon/muxue``, so every new source is asked. Each source is made to fail in turn by replaying its
recording as a timeout (``derive_upstream(errors=...)``); the Figshare DOI's doi.org and DataCite
answers are the derived ones of ``tests/unit/test_register_licences.py``.
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
from model_dependabot.store import Store

GPT2_SHA = "607a30d783dfa663caf39e06633721c8d4cfcd7e"
ZENODO = "10.5281/zenodo.3242074"
RETRACTED = "10.1177/1758835919874651"
FIGSHARE = "10.6084/m9.figshare.34763127.v1"
FIGSHARE_PAGE = "https://figshare.com/articles/dataset/Data_Analysis/34763127"
MUXUE_SHA = "9408684b4d7410bf12651eff99ad6da74d746811"
LOG = "date,reported_content\n2026-09-04,yavon/muxue\n"
UPSTREAM = ("hf-hub", "hf-takedowns", "crossref", "datacite", "zenodo", "figshare")
# The recording each source answers from in the worked example.
FAILING = {
    "hf-hub": "hf_upstream/model-normal",
    "hf-takedowns": "hf_takedowns/index",
    "crossref": "crossref/retracted",
    "datacite": "datacite/findable",
    "zenodo": "zenodo/record-3242074",
    "figshare": "figshare/cc-by-4.0",
}


def figshare_extra() -> dict[str, dict[str, Any]]:
    body = fixture_json("datacite/previous-version")
    body["data"]["attributes"]["doi"] = FIGSHARE
    body["data"]["attributes"]["url"] = FIGSHARE_PAGE
    return {
        "figshare-ra": {
            "url": doi_ra_url(FIGSHARE),
            "status": 200,
            "body": [{"DOI": FIGSHARE, "RA": "DataCite"}],
        },
        "figshare-datacite": {"url": doi_url(FIGSHARE), "status": 200, "body": body},
    }


def manifest(directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    text = f"""[model]
id = "m"
name = "Upstream worked example"
owner = "Owner"

[base_model]
hub = "hf:openai-community/gpt2"
revision = "{GPT2_SHA}"

[[datasets]]
doi = "{ZENODO}"
paper_doi = ["{RETRACTED}"]

[[datasets]]
doi = "{FIGSHARE}"

[[datasets]]
hub = "hf:datasets/yavon/muxue"
revision = "{MUXUE_SHA}"
"""
    path = directory / "model.toml"
    path.write_text(text, encoding="utf-8")
    return path


@pytest.fixture
def example(
    tmp_path: Path, derive_upstream: Callable[..., Path], capsys: pytest.CaptureFixture[str]
) -> Callable[..., tuple[int, Any]]:
    def invoke(db: Path, *argv: str, errors: dict[str, str] | None = None) -> tuple[int, Any]:
        root = derive_upstream(
            changes={"hf_takedowns/index": lambda _: LOG}, errors=errors, extra=figshare_extra()
        )
        handlers = make_handlers(fetcher=RecordedFetcher(root))
        code = main([*argv, "--db", str(db), "--json"], handlers=handlers)
        out = capsys.readouterr().out
        return code, json.loads(out) if out.strip() else None

    return invoke


def snapshot(db: Path) -> list[tuple[Any, ...]]:
    with Store(db) as store:
        return [
            (
                a["alert_id"],
                a["kind"],
                a["state"],
                json.dumps(a["cause"], sort_keys=True),
                tuple(e["evidence_id"] for e in store.alert_evidence(a["alert_id"])),
            )
            for a in store.alerts_for("m", None)
        ]


def test_every_source_answers_in_the_worked_example(
    example: Callable[..., tuple[int, Any]], tmp_path: Path
) -> None:
    db = tmp_path / "db" / "md.db"
    assert example(db, "register", str(manifest(tmp_path / "a")))[0] == EXIT_OK
    code, checked = example(db, "check", "--all", "--scheduled")
    assert code == EXIT_OK, checked
    assert {name: checked["sources"][name] for name in UPSTREAM} == dict.fromkeys(UPSTREAM, "ok")
    kinds = {kind for _, kind, *_ in snapshot(db)}
    assert {"paper_retracted", "dataset_removed"} <= kinds


@pytest.mark.parametrize("source", UPSTREAM)
def test_a_failed_source_exits_2_and_opens_changes_or_closes_nothing(
    source: str, example: Callable[..., tuple[int, Any]], tmp_path: Path
) -> None:
    db = tmp_path / "db" / "md.db"
    assert example(db, "register", str(manifest(tmp_path / "a")))[0] == EXIT_OK
    assert example(db, "check", "--all", "--scheduled")[0] == EXIT_OK
    before = snapshot(db)
    errors = {FAILING[source]: "timed out"}
    code, checked = example(db, "check", "--all", "--scheduled", errors=errors)
    assert code == EXIT_SOURCE_FAILED
    assert checked["sources"][source].startswith("failed")
    assert snapshot(db) == before
    with Store(db) as store:
        run = store.latest_check_run()
        assert run is not None and run["sources"][source].startswith("failed")
        rows = store.conn.execute(
            "SELECT count(*) FROM upstream_observations WHERE run_id = ? AND source = ?",
            (run["run_id"], source),
        ).fetchone()[0]
    assert rows == 0, f"a failed {source} wrote no observation (FR-018)"


@pytest.mark.parametrize("source", UPSTREAM)
def test_a_source_failing_at_the_first_check_opens_no_alert_of_its_own(
    source: str, example: Callable[..., tuple[int, Any]], tmp_path: Path
) -> None:
    db = tmp_path / "db" / "md.db"
    assert example(db, "register", str(manifest(tmp_path / "a")))[0] == EXIT_OK
    errors = {FAILING[source]: "timed out"}
    code, _ = example(db, "check", "--all", "--scheduled", errors=errors)
    assert code == EXIT_SOURCE_FAILED
    with Store(db) as store:
        for alert in store.alerts_for("m", None):
            sources = {e["source"] for e in store.alert_evidence(alert["alert_id"])}
            assert source not in sources, (alert["kind"], sources)

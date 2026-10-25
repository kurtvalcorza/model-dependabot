"""Watch events only, end to end, offline (T051; quickstart.md section 5, FR-007, FR-013).

One model is registered with gpt2 as its base model and four datasets, each answering from a
recording under ``tests/fixtures`` or a state derived from one: Zenodo record 8176941, whose
``links.latest`` leads to a newer record; DataCite ``10.1594/pangaea.958394`` (``IsObsoletedBy``)
with a tied paper DOI Crossref answers 404 for; a DOI routed to the Figshare article the recorded
404 is for; and a hub dataset the hub redirects to ``defunct-datasets/`` (the recorded 307 of
``the_pile_books3`` at an ``owner/name`` path). A second state of gpt2's answer then carries a
newer ``sha``, a ``new_version`` pointer, ``gated: "manual"`` and a changed card. Each change
gives one watch event and none gives an alert.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from conftest import fixture_json
from model_dependabot.cli import EXIT_OK, main, make_handlers
from model_dependabot.sources.datacite import doi_url
from model_dependabot.sources.doi_ra import doi_ra_url
from model_dependabot.sources.fetcher import RecordedFetcher
from model_dependabot.sources.hf import dataset_info_url

GPT2 = "openai-community/gpt2"
GPT2_SHA = "607a30d783dfa663caf39e06633721c8d4cfcd7e"
OLDER = "10.5281/zenodo.8176941"
OBSOLETED = "10.1594/pangaea.958394"
PAPER_MISSING = "10.1177/model-dependabot-fixture-does-not-exist"
FIGSHARE_GONE = "10.6084/m9.figshare.1"
BOOKS3_SHA = "9408684b4d7410bf12651eff99ad6da74d746811"
UPSTREAM = "hf-hub,hf-takedowns,crossref,datacite,zenodo,figshare"
DATASET_KINDS = {
    "dataset_new_version",
    "dataset_replaced",
    "dataset_unreachable",
    "paper_not_found",
    "dataset_moved",
}
BASE_KINDS = {
    "base_model_new_revision",
    "base_model_new_version_pointer",
    "gating_changed",
    "card_changed",
}


def _agency(doi: str, agency: str) -> dict[str, Any]:
    return {"url": doi_ra_url(doi), "status": 200, "body": [{"DOI": doi, "RA": agency}]}


def _datacite_at(doi: str, url: str) -> dict[str, Any]:
    body = fixture_json("datacite/findable")
    body["data"]["id"] = doi
    # Without the findable record's licence: the routed record declares its own (FR-008).
    body["data"]["attributes"] |= {"doi": doi, "url": url, "rightsList": []}
    return {"url": doi_url(doi), "status": 200, "body": body}


EXTRA = {
    "ra-older": _agency(OLDER, "DataCite"),
    "ra-obsoleted": _agency(OBSOLETED, "DataCite"),
    "ra-paper": _agency(PAPER_MISSING, "Crossref"),
    "ra-figshare": _agency(FIGSHARE_GONE, "DataCite"),
    "dc-older": _datacite_at(OLDER, "https://zenodo.org/records/8176941"),
    "dc-figshare": _datacite_at(FIGSHARE_GONE, "https://figshare.com/articles/dataset/gone/1"),
    # The recorded 307 of ``the_pile_books3`` (``hf_upstream/dataset-moved``) at an owner/name.
    "moved": {
        "url": dataset_info_url("owner/books3"),
        "status": 307,
        "body": "Temporary Redirect.",
        "redirected_to": dataset_info_url("defunct-datasets/books3"),
    },
    "moved-target": {
        "url": dataset_info_url("defunct-datasets/books3"),
        "status": 200,
        "body": fixture_json("hf_upstream/dataset-moved-target"),
    },
}


def _changed_model(body: dict[str, Any]) -> dict[str, Any]:
    body = body | {"sha": "0" * 40, "gated": "manual"}
    body["cardData"] |= {"new_version": "openai-community/gpt2-large", "language": "de"}
    return body


@pytest.fixture
def cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> Callable[..., tuple[int, Any]]:
    db = tmp_path / "db" / "md.db"

    def invoke(*argv: str, fetcher: RecordedFetcher) -> tuple[int, Any]:
        code = main([*argv, "--db", str(db), "--json"], handlers=make_handlers(fetcher=fetcher))
        out = capsys.readouterr().out
        return code, json.loads(out) if out.strip() else None

    return invoke


def _manifest(directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    lines = ["[model]", 'id = "watched"', 'name = "Watched"', 'owner = "Owner"', ""]
    lines += ["[base_model]", f'hub = "hf:{GPT2}"', f'revision = "{GPT2_SHA}"']
    for item in (
        f'doi = "{OLDER}"',
        f'doi = "{OBSOLETED}"\npaper_doi = ["{PAPER_MISSING}"]',
        f'doi = "{FIGSHARE_GONE}"',
        f'hub = "hf:datasets/owner/books3"\nrevision = "{BOOKS3_SHA}"',
    ):
        lines += ["", "[[datasets]]", item]
    path = directory / "model.toml"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def test_each_upstream_change_gives_one_watch_event_and_no_alert(
    cli: Callable[..., tuple[int, Any]], tmp_path: Path, derive_upstream: Callable[..., Path]
) -> None:
    recorded = RecordedFetcher(derive_upstream(extra=EXTRA))
    changes = {"hf_upstream/model-normal": _changed_model}
    changed = RecordedFetcher(derive_upstream(changes=changes, extra=EXTRA))
    code, registered = cli("register", str(_manifest(tmp_path / "m")), fetcher=recorded)
    assert code == EXIT_OK, registered

    def scheduled(fetcher: RecordedFetcher) -> tuple[Counter[str], list[dict[str, Any]]]:
        argv = ("check", "--all", "--scheduled", "--source", UPSTREAM)
        code, checked = cli(*argv, fetcher=fetcher)
        assert code == EXIT_OK, checked
        assert set(checked["sources"].values()) == {"ok"}
        _, listed = cli("alerts", "watched", fetcher=fetcher)
        return Counter(e["kind"] for e in listed["watch_events"]), listed["alerts"]

    events, alerts = scheduled(recorded)
    assert alerts == []
    assert {kind: events[kind] for kind in DATASET_KINDS} == dict.fromkeys(DATASET_KINDS, 1)
    assert not BASE_KINDS & set(events)

    for _ in range(2):
        events, alerts = scheduled(changed)
        assert alerts == []
        assert {kind: events[kind] for kind in BASE_KINDS} == dict.fromkeys(BASE_KINDS, 1)
        assert {kind: events[kind] for kind in DATASET_KINDS} == dict.fromkeys(DATASET_KINDS, 1)

    _, listed = cli("alerts", "watched", fetcher=changed)
    by_kind = {e["kind"]: e for e in listed["watch_events"]}
    revision = by_kind["base_model_new_revision"]["detail"]
    assert (revision["pinned"], revision["newest"]) == (GPT2_SHA, "0" * 40)
    assert by_kind["dataset_new_version"]["detail"]["newer"] == "18180184"
    assert by_kind["dataset_replaced"]["detail"]["replaced_by"] == "10.1594/pangaea.997226"

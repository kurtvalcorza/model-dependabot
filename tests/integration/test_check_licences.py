"""Licences end to end, offline (T038; quickstart.md section 3, SC-002).

``register`` records the declared licence, ``check`` compares each later declaration with it and
``alerts`` and ``history`` show the result. Every declared licence is a state derived in the test
from a recording under ``tests/fixtures``: the hub answer for ``openai-community/gpt2``
(``hf_upstream/model-normal``) with its ``cardData.license`` replaced, and the Figshare article
``figshare/cc-by-4.0`` (``license.name: "CC BY 4.0"``) reached through the recorded DataCite
``previous-version`` body (``rightsIdentifier: "cc-by-4.0"``) moved to the article's DOI.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from conftest import fixture_json
from model_dependabot.cli import EXIT_OK, main, make_handlers
from model_dependabot.sources.datacite import doi_url
from model_dependabot.sources.doi_ra import doi_ra_url
from model_dependabot.sources.fetcher import RecordedFetcher

GPT2 = "openai-community/gpt2"
GPT2_SHA = "607a30d783dfa663caf39e06633721c8d4cfcd7e"
PURL = f"pkg:huggingface/openai-community/gpt2@{GPT2_SHA}"
FIGSHARE = "10.6084/m9.figshare.34763127.v1"
FIGSHARE_PAGE = "https://figshare.com/articles/dataset/Data_Analysis/34763127"


@pytest.fixture
def cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> Callable[..., tuple[int, Any]]:
    db = tmp_path / "db" / "md.db"

    def invoke(*argv: str, fetcher: RecordedFetcher) -> tuple[int, Any]:
        code = main([*argv, "--db", str(db), "--json"], handlers=make_handlers(fetcher=fetcher))
        out = capsys.readouterr().out
        return code, json.loads(out) if out.strip() else None

    return invoke


def _card(licence: str | None) -> Callable[[dict[str, Any]], dict[str, Any]]:
    def change(body: dict[str, Any]) -> dict[str, Any]:
        if licence is None:
            body["cardData"].pop("license", None)
        else:
            body["cardData"]["license"] = licence
        return body

    return change


def _manifest(directory: Path, lines: list[str]) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    head = ["[model]", 'id = "licensed"', 'name = "Licence model"', 'owner = "Owner"', ""]
    path = directory / "model.toml"
    path.write_text("\n".join(head + lines) + "\n", encoding="utf-8")
    return path


BASE = ["[base_model]", f'hub = "hf:{GPT2}"', f'revision = "{GPT2_SHA}"']

# (licence at registration, licences declared at later checks, alerts expected open,
#  alerts expected cleared, licence watch events expected)
PAIRS = {
    "case only": ("apache-2.0", ["Apache-2.0"], 0, 0, set()),
    "real change": ("apache-2.0", ["cc-by-nc-4.0"], 1, 0, set()),
    "unrecognised": ("mit", ["llama3.1"], 0, 0, {"licence_unrecognised"}),
    "no longer declared": ("mit", [None], 0, 0, {"licence_missing"}),
    "a then b then c": ("apache-2.0", ["cc-by-nc-4.0", "mit"], 1, 0, set()),
    "a then b then a": ("apache-2.0", ["cc-by-nc-4.0", "Apache-2.0"], 0, 1, set()),
}


@pytest.mark.parametrize("name", list(PAIRS))
def test_recorded_licence_pairs(
    name: str,
    cli: Callable[..., tuple[int, Any]],
    tmp_path: Path,
    derive_upstream: Callable[..., Path],
) -> None:
    registered, declared, open_count, cleared_count, events = PAIRS[name]
    fetcher = RecordedFetcher(
        derive_upstream(changes={"hf_upstream/model-normal": _card(registered)})
    )
    code, _ = cli("register", str(_manifest(tmp_path / "m", BASE)), fetcher=fetcher)
    assert code == EXIT_OK
    for licence in declared:
        root = derive_upstream(changes={"hf_upstream/model-normal": _card(licence)})
        code, checked = cli(
            "check", "licensed", "--source", "hf-hub", fetcher=RecordedFetcher(root)
        )
        assert (code, checked["sources"]) == (EXIT_OK, {"hf-hub": "ok"})
    _, listed = cli("alerts", "licensed", fetcher=fetcher)
    _, history = cli("history", "licensed", fetcher=fetcher)
    opened = [a for a in listed["alerts"] if a["kind"] == "licence_changed"]
    cleared = [a for a in history["history"] if a["outcome"] == "cleared"]
    assert (len(opened), len(cleared)) == (open_count, cleared_count)
    assert {e["kind"] for e in listed["watch_events"]} == events
    for alert in opened:
        assert (alert["severity"], alert["severity_origin"]) == ("HIGH", "policy")
        cause = alert["cause"]
        assert (cause["identifier"], cause["recorded_licence"]) == (PURL, "Apache-2.0")
        assert cause["declared_licence"] == declared[-1]
        assert [e["source"] for e in alert["evidence"]] == ["hf-hub"] * len(declared)
    for alert in cleared:
        assert alert["kind"] == "licence_changed"
        assert len(alert["evidence"]) == 2


def test_a_figshare_alias_against_a_recorded_identifier_raises_nothing(
    cli: Callable[..., tuple[int, Any]], tmp_path: Path, derive_upstream: Callable[..., Path]
) -> None:
    record = fixture_json("datacite/previous-version")
    record["data"]["attributes"] |= {"doi": FIGSHARE, "url": FIGSHARE_PAGE}
    extra = {
        "ra": {
            "url": doi_ra_url(FIGSHARE),
            "status": 200,
            "body": [{"DOI": FIGSHARE, "RA": "DataCite"}],
        },
        "datacite": {"url": doi_url(FIGSHARE), "status": 200, "body": record},
    }
    fetcher = RecordedFetcher(derive_upstream(extra=extra))
    manifest = _manifest(tmp_path / "m", ["[[datasets]]", f'doi = "{FIGSHARE}"'])
    code, registered = cli("register", str(manifest), fetcher=fetcher)
    assert code == EXIT_OK
    [entry] = [e for e in registered["entries"] if e["kind"] == "dataset"]
    assert (entry["recorded_licence"], entry["licence_form"]) == ("CC-BY-4.0", "spdx")
    code, checked = cli("check", "licensed", "--source", "datacite,figshare", fetcher=fetcher)
    assert (code, checked["sources"]) == (EXIT_OK, {"datacite": "ok", "figshare": "ok"})
    _, listed = cli("alerts", "licensed", fetcher=fetcher)
    assert listed["alerts"] == []
    assert [e for e in listed["watch_events"] if e["kind"].startswith("licence_")] == []

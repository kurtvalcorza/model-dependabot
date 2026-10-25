"""Licences recorded at registration (T036; FR-008, research U8 and U11).

``register`` reads the declared licence of the base model (hub ``cardData.license``) and of each
dataset (DataCite ``rightsList``, Zenodo ``metadata.license.id``, Figshare ``license.name``, hub
``cardData.license``) with the US1 adapters and writes it, normalised, into the inventory's
CycloneDX ``licenses``. The answers come from the recordings under ``tests/fixtures``; the Figshare
article is reached through a derived DataCite record (the recorded ``previous-version`` body moved
to the article's own DOI and landing page), written out below.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from conftest import fixture_json
from model_dependabot.cli import main, make_handlers
from model_dependabot.sources.datacite import doi_url
from model_dependabot.sources.doi_ra import doi_ra_url
from model_dependabot.sources.fetcher import RecordedFetcher
from model_dependabot.store import Store
from model_dependabot.upstream.changes import licence_reference

GPT2 = "openai-community/gpt2"
GPT2_SHA = "607a30d783dfa663caf39e06633721c8d4cfcd7e"
GPT2_PURL = f"pkg:huggingface/openai-community/gpt2@{GPT2_SHA}"
ZENODO = "10.5281/zenodo.3242074"
FIGSHARE = "10.6084/m9.figshare.34763127.v1"
FIGSHARE_PAGE = "https://figshare.com/articles/dataset/Data_Analysis/34763127"
MUXUE = "yavon/muxue"
MUXUE_SHA = "9408684b4d7410bf12651eff99ad6da74d746811"
MUXUE_ID = f"hf-dataset:{MUXUE}@{MUXUE_SHA}"


def _figshare_datacite(rights: bool = True) -> dict[str, Any]:
    body = fixture_json("datacite/previous-version")
    attributes = body["data"]["attributes"]
    attributes["doi"], attributes["url"] = FIGSHARE, FIGSHARE_PAGE
    if not rights:
        attributes["rightsList"] = []
    return body


def _extra(rights: bool = True) -> dict[str, dict[str, Any]]:
    return {
        "figshare-ra": {
            "url": doi_ra_url(FIGSHARE),
            "status": 200,
            "body": [{"DOI": FIGSHARE, "RA": "DataCite"}],
        },
        "figshare-datacite": {
            "url": doi_url(FIGSHARE),
            "status": 200,
            "body": _figshare_datacite(rights),
        },
    }


def _no_rights(body: dict[str, Any]) -> dict[str, Any]:
    body["data"]["attributes"]["rightsList"] = []
    return body


def _manifest(directory: Path, datasets: list[str], base: bool = True) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    lines = ["[model]", 'id = "licensed"', 'name = "Licence test model"', 'owner = "Owner"']
    if base:
        lines += ["", "[base_model]", f'hub = "hf:{GPT2}"', f'revision = "{GPT2_SHA}"']
    for item in datasets:
        lines += ["", "[[datasets]]", item]
    path = directory / "model.toml"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


DATASETS = [
    f'doi = "{ZENODO}"',
    f'doi = "{FIGSHARE}"',
    f'hub = "hf:datasets/{MUXUE}"\nrevision = "{MUXUE_SHA}"',
]


@pytest.fixture
def cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> Callable[..., Any]:
    db = tmp_path / "db" / "md.db"

    def invoke(*argv: str, fetcher: RecordedFetcher) -> tuple[int, Any]:
        code = main([*argv, "--db", str(db), "--json"], handlers=make_handlers(fetcher=fetcher))
        out = capsys.readouterr().out
        return code, json.loads(out) if out.strip() else None

    invoke.db = db  # type: ignore[attr-defined]
    return invoke


def _recorded(db: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    with Store(db) as store:
        entries = {e["identifier"]: e for e in store.entries("licensed", 1)}
        document = store.get_version("licensed", 1)["inventory"]
    licences = {e: (v["recorded_licence"], v["licence_form"]) for e, v in entries.items()}
    components: dict[str, Any] = {}

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            ref = node.get("bom-ref")
            if isinstance(ref, str) and node.get("type") in ("machine-learning-model", "data"):
                components[GPT2_PURL if ref.startswith("base-model:") else ref] = node.get(
                    "licenses"
                )
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(document)
    return licences, components


def test_register_records_each_declared_licence_normalised(
    cli: Callable[..., Any], tmp_path: Path, derive_upstream: Callable[..., Path]
) -> None:
    fetcher = RecordedFetcher(derive_upstream(extra=_extra()))
    assert cli("register", str(_manifest(tmp_path / "m", DATASETS)), fetcher=fetcher)[0] == 0
    licences, components = _recorded(cli.db)  # type: ignore[attr-defined]
    assert licences[GPT2_PURL] == ("MIT", "spdx")  # hub cardData.license "mit"
    # DataCite rightsList: 'BSD 3-Clause "New" or "Revised" License', an SPDX full name.
    assert licences[ZENODO] == ("BSD-3-Clause", "spdx")
    assert licences[FIGSHARE] == ("CC-BY-4.0", "spdx")  # DataCite rightsIdentifier cc-by-4.0
    assert licences[MUXUE_ID] == ("Apache-2.0", "spdx")  # hub cardData.license "apache-2.0"
    assert components[GPT2_PURL] == [{"license": {"id": "MIT"}}]
    assert components[f"doi:{ZENODO}"] == [{"license": {"id": "BSD-3-Clause"}}]
    assert components[MUXUE_ID] == [{"license": {"id": "Apache-2.0"}}]


def test_a_record_without_rights_falls_to_the_repository_record(
    cli: Callable[..., Any], tmp_path: Path, derive_upstream: Callable[..., Path]
) -> None:
    root = derive_upstream(changes={"datacite/findable": _no_rights}, extra=_extra(rights=False))
    fetcher = RecordedFetcher(root)
    manifest = _manifest(tmp_path / "m", DATASETS[:2], base=False)
    assert cli("register", str(manifest), fetcher=fetcher)[0] == 0
    licences, _ = _recorded(cli.db)  # type: ignore[attr-defined]
    assert licences[ZENODO] == ("BSD-3-Clause", "spdx")  # Zenodo metadata.license.id
    assert licences[FIGSHARE] == ("CC-BY-4.0", "spdx")  # Figshare license.name "CC BY 4.0"


def test_a_source_failing_at_registration_leaves_the_licence_empty_and_raises_nothing(
    cli: Callable[..., Any], tmp_path: Path, derive_upstream: Callable[..., Path]
) -> None:
    failing = RecordedFetcher(derive_upstream(errors={"hf_upstream/model-normal": "timed out"}))
    assert cli("register", str(_manifest(tmp_path / "m", [])), fetcher=failing)[0] == 0
    licences, components = _recorded(cli.db)  # type: ignore[attr-defined]
    assert licences[GPT2_PURL] == (None, None)
    assert components[GPT2_PURL] is None

    working = RecordedFetcher(derive_upstream())
    code, checked = cli("check", "licensed", "--source", "hf-hub", fetcher=working)
    assert code == 0
    [model] = checked["models"]
    assert (model["opened"], model["watch_events"]) == ([], [])
    with Store(cli.db) as store:  # type: ignore[attr-defined]
        [entry] = [e for e in store.entries("licensed", 1) if e["kind"] == "base_model"]
        reference = licence_reference(store, entry)
        [observation] = store.observations(GPT2_PURL, "hf-hub")
    # The first successful observation is the baseline, labelled as such; the inventory stays.
    assert reference is not None
    assert (reference.origin, reference.observation_id) == (
        "baseline",
        observation["observation_id"],
    )
    assert (reference.licence.normalised, reference.licence.form) == ("MIT", "spdx")
    assert entry["recorded_licence"] is None

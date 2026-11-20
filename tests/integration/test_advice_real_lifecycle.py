"""The advisory view over alerts the real lifecycle raised (review round 1, M10-R4; issue #32).

The fixture store of ``tests/fixtures/advice/build.py`` writes alerts through the ``Store`` API.
Here real checks raise each upstream kind on recorded answers, or states derived from them by
``derive_upstream`` and ``derive_hf`` (``tests/conftest.py``); nothing is fetched:

- ``base_model_disabled`` (MDB501) and ``licence_changed`` (MDB401): an ``hf-hub`` check on the
  recorded answer for ``openai-community/gpt2`` (``hf_upstream/model-normal``) changed to
  ``disabled: true`` with another licence, as ``tests/integration/test_upstream_fixed.py`` does.
- ``hub_scan`` (MDB102): ``register`` and an ``hf-scan`` check of
  ``mcpotato/42-eicar-street/pytorch_model.bin`` on ``hf/eicar-security`` with that file flagged
  unsafe, as ``tests/integration/test_check_weights.py`` does. No weight file is downloaded,
  loaded or scanned.
- ``dataset_retracted`` (MDB301), ``paper_retracted`` (MDB302), ``dataset_removed`` (MDB303) and
  ``dataset_not_findable`` (MDB304): ``register`` of a ``[[datasets]]`` manifest, which routes each
  DOI from doi.org's answer, then a ``check`` of the dataset sources, as
  ``tests/integration/test_check_datasets.py`` does. MDB301 and MDB302 run on the recorded
  ``doi_ra/crossref`` and ``doi_ra/datacite``, ``crossref/retracted``, ``datacite/findable`` and
  ``zenodo/record-3242074``. MDB303 runs twice, on recordings only: the disabled hub dataset
  ``yavon/muxue`` on ``hf_upstream/dataset-disabled`` and ``hf_takedowns/index``; and the deleted
  Zenodo DOI, which doi.org reports does not exist (``doi_ra/not-registered-zenodo``), so
  ``register`` records agency ``none``, DataCite answers 404 (``datacite/zenodo-deleted``) and
  Zenodo, asked by the record id, 410 (``zenodo/deleted``). MDB304 needs one derived answer:
  doi.org naming DataCite as the agency of the made-up DOI (recorded: does not exist), so
  DataCite's recorded 404 (``datacite/not-found``) means not findable.

If the lifecycle ever renames a cause key the resolver reads, these views stop resolving, or
resolve by another key, and these tests fail.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from conftest import EICAR_COMMIT, EICAR_REPO, flag_bin
from model_dependabot.assurance.advice import advice_view
from model_dependabot.cli import EXIT_OK, main, make_handlers
from model_dependabot.lifecycle import run_check
from model_dependabot.sources.doi_ra import doi_ra_url
from model_dependabot.sources.fetcher import RecordedFetcher
from model_dependabot.store import Store

MOMENT = datetime(2026, 10, 24, 6, 0, tzinfo=UTC)
GPT2 = "openai-community/gpt2"
GPT2_SHA = "607a30d783dfa663caf39e06633721c8d4cfcd7e"
BASE = {
    "kind": "base_model",
    "identifier": f"pkg:huggingface/{GPT2}@{GPT2_SHA}",
    "pinned": True,
    "name": GPT2,
    "version": GPT2_SHA,
    "recorded_licence": "MIT",
    "licence_form": "spdx",
}


def assert_resolves(
    store: Store, alert: Mapping[str, Any], entry_kind: str, value: str, matched_by: str
) -> None:
    """The view of a real alert names its entry, the cause key that matched it, the relationship,
    and only its own evidence."""
    kind = alert["kind"]
    view = advice_view(store, alert)
    entry = view["entry"]
    assert (entry["status"], entry["kind"]) == ("resolved", entry_kind), kind
    assert entry["matched_by"] == matched_by, kind
    assert view["relationship"]["value"] == value, kind
    assert entry["in_current_version"] is True, kind
    evidence = {e["evidence_id"] for e in store.alert_evidence(alert["alert_id"])}
    assert view["established"], kind
    for statement in view["established"]:
        assert set(statement["evidence_ids"]) <= evidence, kind
    assert "not recorded" not in " ".join(s["text"] for s in view["review_steps"]), kind


def _disabled(body: dict[str, Any]) -> dict[str, Any]:
    body["cardData"]["license"] = "cc-by-nc-4.0"
    return body | {"disabled": True}


def test_real_base_model_alerts_resolve_to_the_declared_base_model(
    tmp_path: Path, derive_upstream: Callable[..., Path]
) -> None:
    root = derive_upstream(changes={"hf_upstream/model-normal": _disabled})
    with Store(tmp_path / "md.db", now=lambda: MOMENT) as store:
        store.add_model("m")
        store.add_version("m", {}, "0" * 64, [BASE], origin="manifest")
        run_check(store, RecordedFetcher(root), ["m"], ("hf-hub",))
        raised = {a["kind"]: a for a in store.alerts_for("m", ["open"])}
        assert {"base_model_disabled", "licence_changed"} <= set(raised)
        for kind, matched_by in (
            ("base_model_disabled", "repository"),
            ("licence_changed", "repository"),
        ):
            assert_resolves(store, raised[kind], "base_model", "declared base model", matched_by)


HUB_MANIFEST = f"""[model]
id = "m"
name = "Hub weight model"
owner = "Owner"

[[weights]]
hub = "hf:{EICAR_REPO}"
revision = "{EICAR_COMMIT}"
file = "pytorch_model.bin"
"""


def test_a_real_hub_scan_alert_resolves_to_the_weight_file(
    tmp_path: Path, derive_hf: Callable[..., Path]
) -> None:
    db = tmp_path / "md.db"
    manifest = tmp_path / "model.toml"
    manifest.write_text(HUB_MANIFEST, encoding="utf-8")
    handlers = make_handlers(fetcher=RecordedFetcher(derive_hf(security=flag_bin)))
    assert main(["register", str(manifest), "--db", str(db)], handlers=handlers) == EXIT_OK
    check = ["check", "m", "--source", "hf-scan", "--db", str(db)]
    assert main(check, handlers=handlers) == EXIT_OK
    with Store(db) as store:
        (alert,) = store.alerts_for("m", ["open"])
        assert alert["kind"] == "hub_scan"
        assert_resolves(store, alert, "weight_file", "weight file of this model", "identifier")


RETRACTED = "10.1177/1758835919874651"
ZENODO_FINDABLE = "10.5281/zenodo.3242074"
ZENODO_DELETED = "10.5281/zenodo.12584226"
MADE_UP = "10.5281/model-dependabot-fixture-does-not-exist"
MUXUE_SHA = "9408684b4d7410bf12651eff99ad6da74d746811"
DATASET_SOURCES = ("hf-hub", "hf-takedowns", "crossref", "datacite", "zenodo", "figshare")
DECLARED = "declared dataset"


def _dataset_manifest(path: Path, datasets: str) -> Path:
    head = '[model]\nid = "m"\nname = "Dataset test model"\nowner = "Owner"\n\n[[datasets]]\n'
    path.write_text(head + datasets + "\n", encoding="utf-8")
    return path


# The made-up DOI as if DataCite had registered it, the one derived answer (FR-006): doi.org's
# recorded answer for it is "DOI does not exist", on which the check writes a
# ``dataset_unreachable`` watch event, not an alert (tests/integration/test_check_datasets.py).
MADE_UP_AT_DATACITE = {
    "ra-missing": {
        "url": doi_ra_url(MADE_UP),
        "status": 200,
        "body": [{"DOI": MADE_UP, "RA": "DataCite"}],
    }
}

# Each case: the kind the check raises, the ``[[datasets]]`` entry registered, the agency
# ``register`` records for each DOI from doi.org's answer (recorded under ``doi_ra``, except the
# derived one for MDB304), the extra recordings, the relationship value, and the cause key
# (``matched_by``) that resolves the entry.
DATASET_CASES = [
    pytest.param(
        "dataset_retracted",
        f'doi = "{RETRACTED}"',
        {RETRACTED: "Crossref"},
        None,
        DECLARED,
        "identifier",
        id="MDB301-crossref-retraction",
    ),
    pytest.param(
        "paper_retracted",
        f'doi = "{ZENODO_FINDABLE}"\npaper_doi = ["{RETRACTED}"]',
        {ZENODO_FINDABLE: "DataCite", RETRACTED: "Crossref"},
        None,
        "paper cited by a declared dataset",
        "identifier",
        id="MDB302-cited-paper-retracted",
    ),
    pytest.param(
        "dataset_removed",
        f'hub = "hf:datasets/yavon/muxue"\nrevision = "{MUXUE_SHA}"',
        {},
        None,
        DECLARED,
        "repository",
        id="MDB303-hub-dataset-disabled",
    ),
    pytest.param(
        "dataset_removed",
        f'doi = "{ZENODO_DELETED}"',
        {ZENODO_DELETED: "none"},
        None,
        DECLARED,
        "identifier",
        id="MDB303-zenodo-410",
    ),
    pytest.param(
        "dataset_not_findable",
        f'doi = "{MADE_UP}"',
        {MADE_UP: "DataCite"},
        MADE_UP_AT_DATACITE,
        DECLARED,
        "identifier",
        id="MDB304-datacite-404",
    ),
]


@pytest.mark.parametrize(
    ("kind", "datasets", "agencies", "extra", "value", "matched_by"), DATASET_CASES
)
def test_a_real_dataset_alert_resolves_to_the_declared_dataset(
    tmp_path: Path,
    derive_upstream: Callable[..., Path],
    capsys: pytest.CaptureFixture[str],
    kind: str,
    datasets: str,
    agencies: dict[str, str],
    extra: dict[str, dict[str, Any]] | None,
    value: str,
    matched_by: str,
) -> None:
    db = tmp_path / "md.db"
    manifest = _dataset_manifest(tmp_path / "model.toml", datasets)
    handlers = make_handlers(fetcher=RecordedFetcher(derive_upstream(extra=extra)))
    assert main(["register", str(manifest), "--db", str(db)], handlers=handlers) == EXIT_OK
    capsys.readouterr()
    check = ["check", "m", "--source", ",".join(DATASET_SOURCES), "--db", str(db), "--json"]
    assert main(check, handlers=handlers) == EXIT_OK
    assert json.loads(capsys.readouterr().out)["sources"] == dict.fromkeys(DATASET_SOURCES, "ok")
    with Store(db) as store:
        for doi, agency in agencies.items():
            assert (store.get_routing(doi) or {}).get("agency") == agency, doi
        (alert,) = store.alerts_for("m", ["open"])
        assert alert["kind"] == kind
        assert_resolves(store, alert, "dataset", value, matched_by)

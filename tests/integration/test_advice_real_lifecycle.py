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
- ``dataset_retracted`` (MDB301), ``paper_retracted`` (MDB302), ``dataset_removed`` (MDB303, a
  disabled hub dataset and a Zenodo 410) and ``dataset_not_findable`` (MDB304): dataset checks on
  ``crossref/retracted``, ``datacite/*``, ``zenodo/deleted``, the hub answer for ``yavon/muxue``
  and ``hf_takedowns/index``, set up as ``tests/unit/test_lifecycle_datasets.py`` does.

If the lifecycle ever renames a cause key the resolver reads, these views stop resolving and these
tests fail.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from conftest import EICAR_COMMIT, EICAR_REPO, fixture_json
from model_dependabot.assurance.advice import advice_view
from model_dependabot.cli import EXIT_OK, main, make_handlers
from model_dependabot.lifecycle import run_check
from model_dependabot.sources.datacite import doi_url
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


def assert_resolves(store: Store, alert: Mapping[str, Any], entry_kind: str, value: str) -> None:
    """The view of a real alert names its entry, the relationship, and only its own evidence."""
    kind = alert["kind"]
    view = advice_view(store, alert)
    entry = view["entry"]
    assert (entry["status"], entry["kind"]) == ("resolved", entry_kind), kind
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
        for kind in ("base_model_disabled", "licence_changed"):
            assert_resolves(store, raised[kind], "base_model", "declared base model")


def _flag_bin(info: Any) -> Any:
    issues = info["securityRepoStatus"]["filesWithIssues"]
    issues.append({"path": "pytorch_model.bin", "level": "unsafe"})
    return info


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
    handlers = make_handlers(fetcher=RecordedFetcher(derive_hf(security=_flag_bin)))
    assert main(["register", str(manifest), "--db", str(db)], handlers=handlers) == EXIT_OK
    check = ["check", "m", "--source", "hf-scan", "--db", str(db)]
    assert main(check, handlers=handlers) == EXIT_OK
    with Store(db) as store:
        (alert,) = store.alerts_for("m", ["open"])
        assert alert["kind"] == "hub_scan"
        assert_resolves(store, alert, "weight_file", "weight file of this model")


RETRACTED = "10.1177/1758835919874651"
ZENODO_FINDABLE = "10.5281/zenodo.3242074"
ZENODO_DELETED = "10.5281/zenodo.12584226"
DATACITE_MISSING = "10.5281/model-dependabot-fixture-does-not-exist"
MUXUE_SHA = "9408684b4d7410bf12651eff99ad6da74d746811"
DATASET_SOURCES = ("hf-hub", "hf-takedowns", "crossref", "datacite", "zenodo", "figshare")
DECLARED = "declared dataset"
MUXUE = {
    "kind": "dataset",
    "identifier": f"hf-dataset:yavon/muxue@{MUXUE_SHA}",
    "pinned": True,
    "hub_repo": "yavon/muxue",
    "hub_revision": MUXUE_SHA,
}


def _doi(doi: str, papers: list[str] | None = None) -> dict[str, Any]:
    return {"kind": "dataset", "identifier": doi, "pinned": True, "paper_dois": papers}


def _zenodo_deleted() -> dict[str, Any]:
    """DataCite's answer for the deleted Zenodo DOI, derived from ``datacite/findable``, so the
    check routes it to Zenodo, whose recorded answer is the 410 (``zenodo/deleted``)."""
    body = fixture_json("datacite/findable")
    body["data"]["id"] = body["data"]["attributes"]["doi"] = ZENODO_DELETED
    body["data"]["attributes"]["url"] = "https://zenodo.org/records/12584226"
    return {"dc-deleted": {"url": doi_url(ZENODO_DELETED), "status": 200, "body": body}}


# Each case: the kind the check raises, the declared entry, the agency routing registering would
# record as (doi, agency, repository, repository id), extra recordings, the relationship value.
DATASET_CASES = [
    pytest.param(
        "dataset_retracted",
        _doi(RETRACTED),
        [(RETRACTED, "Crossref", None, None)],
        None,
        DECLARED,
        id="MDB301-crossref-retraction",
    ),
    pytest.param(
        "paper_retracted",
        _doi(ZENODO_FINDABLE, [RETRACTED]),
        [(ZENODO_FINDABLE, "DataCite", "zenodo", "3242074"), (RETRACTED, "Crossref", None, None)],
        None,
        "paper cited by a declared dataset",
        id="MDB302-cited-paper-retracted",
    ),
    pytest.param("dataset_removed", MUXUE, [], None, DECLARED, id="MDB303-hub-dataset-disabled"),
    pytest.param(
        "dataset_removed",
        _doi(ZENODO_DELETED),
        [(ZENODO_DELETED, "DataCite", None, None)],
        _zenodo_deleted,
        DECLARED,
        id="MDB303-zenodo-410",
    ),
    pytest.param(
        "dataset_not_findable",
        _doi(DATACITE_MISSING),
        [(DATACITE_MISSING, "DataCite", None, None)],
        None,
        DECLARED,
        id="MDB304-datacite-404",
    ),
]


@pytest.mark.parametrize(("kind", "entry", "routing", "extra", "value"), DATASET_CASES)
def test_a_real_dataset_alert_resolves_to_the_declared_dataset(
    tmp_path: Path,
    derive_upstream: Callable[..., Path],
    kind: str,
    entry: dict[str, Any],
    routing: list[tuple[str, str, str | None, str | None]],
    extra: Callable[[], dict[str, Any]] | None,
    value: str,
) -> None:
    root = derive_upstream(extra=extra() if extra else None)
    with Store(tmp_path / "md.db", now=lambda: MOMENT) as store:
        store.add_model("m")
        store.add_version("m", {}, "0" * 64, [dict(entry)], origin="manifest")
        for doi, agency, repository, rid in routing:
            store.set_routing(doi, agency=agency, repository=repository, repository_id=rid)
        outcome = run_check(store, RecordedFetcher(root), ["m"], DATASET_SOURCES)
        assert set(outcome.sources.values()) == {"ok"}
        (alert,) = store.alerts_for("m", ["open"])
        assert alert["kind"] == kind
        assert_resolves(store, alert, "dataset", value)

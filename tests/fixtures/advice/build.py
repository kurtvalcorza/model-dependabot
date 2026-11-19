"""The advisory-view fixture store of feature 010 (T004, tests/fixtures/advice/NOTES.md).

``build(path)`` writes one store at the current schema holding one alert of every rule ID, plus the
states and edge cases the advisory view must handle: a fixed alert, a cleared alert, an excepted
alert, a version registered from a record whose bytes are absent and an imported version. The
alerts carry the cause shapes the checks write (``lifecycle.py``) and evidence rows whose bodies are
the recorded answers under ``tests/fixtures`` (``osv``, ``hf``, ``crossref``, ``datacite``,
``hf_upstream``), copied, never fetched. Nothing is a weight file: no file is scanned or loaded.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from model_dependabot.store import Store

FIXTURES = Path(__file__).resolve().parent.parent
NOW = datetime(2026, 11, 19, 9, 0, tzinfo=UTC)
MODEL = "advice-model"
UNAVAILABLE_MODEL = "unavailable-model"
RECORD_MODEL = "record-model"
IMPORT_MODEL = "import-model"

PICKLE = "sha256:" + "a1" * 32
OTHER_PICKLE = "sha256:" + "b2" * 32
HUB_BIN = "sha256:f9343d7d7ec5c3d8bcced056c438fc9f1d3819e9ca3d42418a40857050e10e20"
EICAR_REPO = "mcpotato/42-eicar-street"
EICAR_COMMIT = "8fb61c4d511e9aaff0ea55396a124aa292830efc"
PILLOW = "pkg:pypi/pillow@12.3.0"
VALIDATORS = "pkg:pypi/validators@0.12.2"
GPT2 = "openai-community/gpt2"
GPT2_SHA = "607a30d783dfa663caf39e06633721c8d4cfcd7e"
GPT2_PURL = f"pkg:huggingface/openai-community/gpt2@{GPT2_SHA}"
LLAMA = "meta-llama/Llama-3.1-8B"
LLAMA_SHA = "d04e592bb4f6aa9cfee91e2e20afa771667e1d4b"
LLAMA_PURL = f"pkg:huggingface/meta-llama/Llama-3.1-8B@{LLAMA_SHA}"
DOI = "10.5281/zenodo.3242074"
DOI_LOST = "10.5281/model-dependabot-fixture-does-not-exist"
PAPER = "10.1177/1758835919874651"
PAPER_CLEARED = "10.1016/j.example.2020.01.001"
HUB_DATASET_REPO = "yavon/muxue"
HUB_DATASET_REVISION = "0123456789abcdef0123456789abcdef01234567"
HUB_DATASET = f"hf-dataset:{HUB_DATASET_REPO}@{HUB_DATASET_REVISION}"

LOCAL_PICKLE = {
    "kind": "weight_file",
    "identifier": PICKLE,
    "pinned": True,
    "location": "weights/model.pkl",
    "size": 120,
    "format": "pickle",
    "can_run_code": True,
}
HUB_WEIGHT = {
    "kind": "weight_file",
    "identifier": HUB_BIN,
    "pinned": True,
    "hub_repo": EICAR_REPO,
    "hub_revision": EICAR_COMMIT,
    "hub_file": "pytorch_model.bin",
    "format": "pytorch",
    "can_run_code": True,
}
PILLOW_ENTRY = {
    "kind": "package",
    "identifier": PILLOW,
    "pinned": True,
    "name": "pillow",
    "version": "12.3.0",
    "hashes": ["sha256:3b8182a766685eaa002637e28b4ec8d6b18819a0c71f579bf0dbaa5830297cce"],
}
VALIDATORS_ENTRY = {
    "kind": "package",
    "identifier": VALIDATORS,
    "pinned": True,
    "name": "validators",
    "version": "0.12.2",
    "hashes": ["sha256:172ac45f7d1944ce4beca3c5c53ca7c83e9759e39fd3fedc1cf28e2130268706"],
}
BASE = {
    "kind": "base_model",
    "identifier": GPT2_PURL,
    "pinned": True,
    "name": GPT2,
    "version": GPT2_SHA,
    "recorded_licence": "MIT",
    "licence_form": "spdx",
}
LLAMA_BASE = {
    "kind": "base_model",
    "identifier": LLAMA_PURL,
    "pinned": True,
    "name": LLAMA,
    "version": LLAMA_SHA,
}
DOI_DATASET = {
    "kind": "dataset",
    "identifier": DOI,
    "pinned": True,
    "paper_dois": [PAPER, PAPER_CLEARED],
    "recorded_licence": "CC-BY-4.0",
    "licence_form": "spdx",
}
LOST_DATASET = {"kind": "dataset", "identifier": DOI_LOST, "pinned": True}
HUB_DATASET_ENTRY = {
    "kind": "dataset",
    "identifier": HUB_DATASET,
    "pinned": True,
    "hub_repo": HUB_DATASET_REPO,
    "hub_revision": HUB_DATASET_REVISION,
}
V1 = [
    LOCAL_PICKLE,
    HUB_WEIGHT,
    PILLOW_ENTRY,
    VALIDATORS_ENTRY,
    BASE,
    DOI_DATASET,
    LOST_DATASET,
    HUB_DATASET_ENTRY,
]
# Version 2 drops validators (its alert is fixed) and pins the hub dataset at another revision
# (its repository-keyed alert still resolves, US1 scenario 4).
HUB_DATASET_V2 = HUB_DATASET_ENTRY | {
    "identifier": f"hf-dataset:{HUB_DATASET_REPO}@{'f' * 40}",
    "hub_revision": "f" * 40,
}
V2 = [LOCAL_PICKLE, HUB_WEIGHT, PILLOW_ENTRY, BASE, DOI_DATASET, LOST_DATASET, HUB_DATASET_V2]


def _recorded(store: Store, name: str, matched: str, **fields: Any) -> int:
    """An evidence row whose body is the recorded answer ``name`` (``crossref/retracted``)."""
    meta = json.loads((FIXTURES / f"{name}.meta.json").read_text("utf-8"))
    body = (FIXTURES / name).parent.joinpath(meta["body_file"]).read_bytes()
    retrieved = datetime.fromisoformat(meta["retrieved_at"].replace("Z", "+00:00"))
    return store.add_evidence(
        source=fields.pop("source"),
        url=meta["url"],
        retrieved_at=retrieved,
        matched_identifier=matched,
        body=body,
        **fields,
    )


def _local(store: Store, source: str, url: str, matched: str, detail: dict[str, Any]) -> int:
    """An evidence row this tool wrote itself (a scan report, a policy, the inventory)."""
    body = json.dumps(detail, sort_keys=True).encode("utf-8")
    return store.add_evidence(
        source=source,
        url=url,
        retrieved_at=NOW,
        matched_identifier=matched,
        body=body,
        detail=detail,
    )


def _alert(
    store: Store,
    model: str,
    kind: str,
    key: str,
    cause: dict[str, Any],
    evidence: list[int],
    severity: str = "HIGH",
    origin: str = "policy",
) -> int:
    return store.insert_alert(
        model_id=model,
        kind=kind,
        cause_key=key,
        cause=cause,
        severity=severity,
        severity_origin=origin,
        opened_in_version=1,
        evidence_ids=evidence,
    )


def _carry(store: Store, alert_id: int, version: int) -> None:
    store.conn.execute(
        "UPDATE alerts SET current_version = ? WHERE alert_id = ?", (version, alert_id)
    )
    store.conn.commit()


def build(path: Path) -> dict[str, int]:
    """Write the fixture store at ``path``; returns the alert ids by name (NOTES.md)."""
    ids: dict[str, int] = {}
    with Store(path, now=lambda: NOW) as store:
        store.add_model(MODEL)
        store.add_version(MODEL, {}, "1" * 64, V1, origin="manifest")
        scan = {"scanner": "picklescan", "dangerous": ["os.system"], "suspicious": []}
        scan_ev = _local(store, "picklescan", "weights/model.pkl", PICKLE, scan)
        ids["weight_file_scan"] = _alert(
            store,
            MODEL,
            "weight_file_scan",
            f"weight_file_scan:{PICKLE[7:]}",
            {"identifier": PICKLE, "location": "weights/model.pkl", **scan, "complete": True},
            [scan_ev],
        )
        hub_ev = _recorded(store, "hf/eicar-security", HUB_BIN, source="hf-scan")
        ids["hub_scan"] = _alert(
            store,
            MODEL,
            "hub_scan",
            f"hub_scan:{HUB_BIN[7:]}",
            {
                "identifier": HUB_BIN,
                "location": f"hf:{EICAR_REPO}/pytorch_model.bin",
                "hub_repo": EICAR_REPO,
                "revision": EICAR_COMMIT,
                "verdict": "unsafe",
            },
            [hub_ev],
        )
        policy = {"format": "pickle", "policy": "strict", "set_by": "Owner", "set_at": "2026-11-18"}
        policy_ev = _local(store, "format-policy", "", PICKLE, policy)
        ids["format_policy"] = _alert(
            store,
            MODEL,
            "format_policy",
            f"format_policy:{PICKLE[7:]}",
            {"identifier": PICKLE, "location": "weights/model.pkl", **policy},
            [policy_ev],
        )
        globals_ev = _local(
            store, "globals-policy", "", PICKLE, {"unlisted": ["os.system"], "policy": "strict"}
        )
        ids["globals_policy"] = _alert(
            store,
            MODEL,
            "globals_policy",
            f"globals_policy:{PICKLE[7:]}",
            {
                "identifier": PICKLE,
                "location": "weights/model.pkl",
                "format": "pickle",
                "unlisted": ["os.system"],
                "excepted": [],
                "policy": "strict",
            },
            [globals_ev],
        )
        osv_a = _recorded(store, "osv/vuln-GHSA-cp9v-662q-vvx9", PILLOW, source="osv.dev")
        osv_b = _recorded(store, "osv/vuln-GHSA-24rc-8hj2-v98c", PILLOW, source="osv.dev")
        ids["package_advisory"] = _alert(
            store,
            MODEL,
            "package_advisory",
            "package_advisory:GHSA-cp9v-662q-vvx9:pillow",
            {
                "advisory_id": "GHSA-cp9v-662q-vvx9",
                "advisory_ids": ["GHSA-cp9v-662q-vvx9", "GHSA-24rc-8hj2-v98c"],
                "aliases": ["CVE-2026-112405"],
                "source": "osv.dev",
                "package": "pillow",
                "version": "12.3.0",
                "identifier": PILLOW,
                "affected": [],
                "fixed": ["13.0.0"],
            },
            [osv_a, osv_b],
            origin="database_specific",
        )
        osv_c = _recorded(store, "osv/vuln-PYSEC-2019-64", VALIDATORS, source="osv.dev")
        ids["fixed"] = _alert(
            store,
            MODEL,
            "package_advisory",
            "package_advisory:PYSEC-2019-64:validators",
            {
                "advisory_id": "PYSEC-2019-64",
                "advisory_ids": ["PYSEC-2019-64"],
                "aliases": [],
                "source": "osv.dev",
                "package": "validators",
                "version": "0.12.2",
                "identifier": VALIDATORS,
                "affected": [],
                "fixed": ["0.12.6"],
            },
            [osv_c],
            severity="MODERATE",
            origin="cvss_v3",
        )
        retracted = _recorded(
            store, "crossref/retracted", DOI, source="crossref", redacted_fields=["author"]
        )
        ids["dataset_retracted"] = _alert(
            store,
            MODEL,
            "dataset_retracted",
            f"dataset_retracted:{DOI}",
            {"identifier": DOI, "dataset": DOI, "doi": DOI, "notices": []},
            [retracted],
        )
        paper = _recorded(store, "crossref/retracted", PAPER, source="crossref")
        ids["paper_retracted"] = _alert(
            store,
            MODEL,
            "paper_retracted",
            f"paper_retracted:{DOI}:{PAPER}",
            {"identifier": DOI, "dataset": DOI, "paper_doi": PAPER, "notices": []},
            [paper],
        )
        cleared_paper = _recorded(store, "crossref/retracted", PAPER_CLEARED, source="crossref")
        ids["cleared"] = _alert(
            store,
            MODEL,
            "paper_retracted",
            f"paper_retracted:{DOI}:{PAPER_CLEARED}",
            {"identifier": DOI, "dataset": DOI, "paper_doi": PAPER_CLEARED, "notices": []},
            [cleared_paper],
        )
        removed = _recorded(store, "hf_upstream/dataset-disabled", HUB_DATASET, source="hf-hub")
        ids["dataset_removed"] = _alert(
            store,
            MODEL,
            "dataset_removed",
            f"dataset_removed:hf-dataset:{HUB_DATASET_REPO}",
            {
                "identifier": HUB_DATASET,
                "dataset": HUB_DATASET,
                "repo": HUB_DATASET_REPO,
                "host": "huggingface",
                "disabled": True,
            },
            [removed],
        )
        lost = _recorded(store, "datacite/not-found", DOI_LOST, source="datacite")
        ids["dataset_not_findable"] = _alert(
            store,
            MODEL,
            "dataset_not_findable",
            f"dataset_not_findable:{DOI_LOST}",
            {"identifier": DOI_LOST, "dataset": DOI_LOST},
            [lost],
            severity="MODERATE",
        )
        licence = _recorded(store, "hf_upstream/model-normal", GPT2_PURL, source="hf-hub")
        ids["licence_changed"] = _alert(
            store,
            MODEL,
            "licence_changed",
            "licence_changed:pkg:huggingface/openai-community/gpt2",
            {
                "identifier": GPT2_PURL,
                "item": GPT2_PURL,
                "recorded_licence": "MIT",
                "declared_licence": "cc-by-nc-4.0",
                "declared_normalised": "CC-BY-NC-4.0",
                "source": "hf-hub",
                "sources": ["hf-hub"],
            },
            [licence],
            severity="MODERATE",
        )
        dataset_licence = _recorded(store, "datacite/findable", DOI, source="datacite")
        ids["licence_changed_dataset"] = _alert(
            store,
            MODEL,
            "licence_changed",
            f"licence_changed:{DOI}",
            {
                "identifier": DOI,
                "item": DOI,
                "recorded_licence": "CC-BY-4.0",
                "declared_licence": "CC-BY-NC-4.0",
                "source": "datacite",
                "sources": ["datacite"],
            },
            [dataset_licence],
            severity="MODERATE",
        )
        disabled = _recorded(store, "hf_upstream/model-disabled", GPT2_PURL, source="hf-hub")
        ids["base_model_disabled"] = _alert(
            store,
            MODEL,
            "base_model_disabled",
            "base_model_disabled:pkg:huggingface/openai-community/gpt2",
            {
                "identifier": GPT2_PURL,
                "base_model": GPT2_PURL,
                "repo": GPT2,
                "disabled": True,
                "source": "hf-hub",
            },
            [disabled],
        )
        store.add_version(MODEL, {}, "2" * 64, V2, origin="manifest")
        for name, alert_id in ids.items():
            if name not in ("fixed", "cleared"):
                _carry(store, alert_id, 2)
        inventory = _local(store, "inventory", "", VALIDATORS, {"version": 2, "found": None})
        store.link_alert_evidence(ids["fixed"], inventory)
        store.close_alert(ids["fixed"], state="fixed", closed_by_version=2)
        clearing = _local(store, "crossref", "", PAPER_CLEARED, {"retraction": None})
        store.link_alert_evidence(ids["cleared"], clearing)
        store.close_alert(ids["cleared"], state="cleared")

        store.add_model(UNAVAILABLE_MODEL)
        store.add_version(UNAVAILABLE_MODEL, {}, "3" * 64, [LLAMA_BASE], origin="manifest")
        gated = _recorded(store, "hf_upstream/model-gated", LLAMA_PURL, source="hf-hub")
        ids["base_model_unavailable"] = _alert(
            store,
            UNAVAILABLE_MODEL,
            "base_model_unavailable",
            "base_model_unavailable:pkg:huggingface/meta-llama/Llama-3.1-8B",
            {"identifier": LLAMA_PURL, "base_model": LLAMA_PURL, "repo": LLAMA, "source": "hf-hub"},
            [gated],
            severity="LOW",
        )

        record_pickle = LOCAL_PICKLE | {"identifier": OTHER_PICKLE, "location": "weights/other.pkl"}
        store.add_model(RECORD_MODEL)
        store.add_version(
            RECORD_MODEL,
            {},
            "4" * 64,
            [record_pickle],
            registration_record_sha256="5" * 64,
            origin="record",
        )
        absent = _local(store, "registration-record", "", OTHER_PICKLE, {"absent": True})
        store.record_watch_event(
            model_id=RECORD_MODEL,
            version=1,
            entry_identifier=OTHER_PICKLE,
            kind="weight_file_absent",
            detail={"location": "weights/other.pkl"},
            evidence_ids=[absent],
        )
        record_scan = _local(store, "picklescan", "weights/other.pkl", OTHER_PICKLE, scan)
        ids["record_weight"] = _alert(
            store,
            RECORD_MODEL,
            "weight_file_scan",
            f"weight_file_scan:{OTHER_PICKLE[7:]}",
            {"identifier": OTHER_PICKLE, "location": "weights/other.pkl", **scan},
            [record_scan],
        )

        store.add_model(IMPORT_MODEL)
        store.add_version(IMPORT_MODEL, {}, "6" * 64, [PILLOW_ENTRY], origin="import")
        imported = _recorded(store, "osv/vuln-GHSA-cp9v-662q-vvx9", PILLOW, source="osv.dev")
        ids["imported_package"] = _alert(
            store,
            IMPORT_MODEL,
            "package_advisory",
            "package_advisory:GHSA-cp9v-662q-vvx9:pillow",
            {
                "advisory_id": "GHSA-cp9v-662q-vvx9",
                "advisory_ids": ["GHSA-cp9v-662q-vvx9"],
                "source": "osv.dev",
                "package": "pillow",
                "version": "12.3.0",
                "identifier": PILLOW,
                "fixed": ["13.0.0"],
            },
            [imported],
        )
    return ids


def except_weight_alert(store: Store, alert_id: int) -> dict[str, Any]:
    """Record an exception for the weight alert's global and mark the alert excepted."""
    record = store.add_exception(
        module="os", name="system", sha256=PICKLE[7:], reason="reviewed", accepted_by="Owner"
    )
    alert = store.get_alert(alert_id)
    assert alert is not None
    item = {
        "global": "os.system",
        "exception_id": record["exception_id"],
        "accepted_by": record["accepted_by"],
        "recorded_at": record["recorded_at"],
        "expires_on": record["expires_on"],
    }
    store.link_alert_evidence(alert_id, store.exception_evidence(record["exception_id"])[0])
    store.set_alert_exception(
        alert_id, excepted_at=record["recorded_at"], cause={**alert["cause"], "excepted": [item]}
    )
    return record

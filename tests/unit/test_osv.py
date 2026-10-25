"""The OSV.dev adapter against recorded responses (T027, research R2, FR-003)."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from model_dependabot.sources.fetcher import RecordedFetcher, SourceFailedError
from model_dependabot.sources.osv import (
    SOURCE,
    OsvClient,
    aliases,
    pinned_packages,
    withdrawn,
)

OSV = Path(__file__).resolve().parent.parent / "fixtures" / "osv"
PILLOW = "pkg:pypi/pillow@12.3.0"
VALIDATORS = "pkg:pypi/validators@0.12.2"


def _package(name: str, version: str | None) -> dict[str, Any]:
    if version is None:
        return {
            "kind": "package",
            "identifier": None,
            "pinned": False,
            "name": name,
            "gap_reason": "no exact version",
        }
    return {
        "kind": "package",
        "identifier": f"pkg:pypi/{name}@{version}",
        "pinned": True,
        "name": name,
        "version": version,
        "hashes": ["sha256:" + "0" * 64],
    }


ENTRIES = [
    {"kind": "weight_file", "identifier": "sha256:" + "1" * 64, "pinned": True},
    _package("validators", "0.12.2"),
    _package("numpy", None),
    _package("pillow", "12.3.0"),
]


def test_only_pinned_packages_are_queried() -> None:
    assert [entry["name"] for entry in pinned_packages(ENTRIES)] == ["validators", "pillow"]


def test_batch_query_sends_one_query_per_pinned_package() -> None:
    fetcher = RecordedFetcher(OSV)
    answer = OsvClient(fetcher).query(ENTRIES)
    assert len(fetcher.requests) == 1
    method, url, body = fetcher.requests[0]
    assert (method, url) == ("POST", "https://api.osv.dev/v1/querybatch")
    assert body is not None
    assert json.loads(body)["queries"] == [
        {"package": {"name": "pillow", "ecosystem": "PyPI"}, "version": "12.3.0"},
        {"package": {"name": "validators", "ecosystem": "PyPI"}, "version": "0.12.2"},
    ]
    assert answer.matches == {
        PILLOW: ["GHSA-24rc-8hj2-v98c", "GHSA-cp9v-662q-vvx9"],
        VALIDATORS: [],
    }
    assert answer.response is not None
    assert answer.response.retrieved_at.isoformat().startswith("2026-10-24")


def test_an_unaffected_version_has_no_match() -> None:
    answer = OsvClient(RecordedFetcher(OSV)).query([_package("pillow", "13.0.0")])
    assert answer.matches == {"pkg:pypi/pillow@13.0.0": []}


def test_no_pinned_package_sends_no_request() -> None:
    fetcher = RecordedFetcher(OSV)
    answer = OsvClient(fetcher).query([_package("numpy", None)])
    assert answer.matches == {}
    assert answer.response is None
    assert fetcher.requests == []


def test_detail_fetch_gives_aliases_fixed_and_evidence() -> None:
    record = OsvClient(RecordedFetcher(OSV)).vuln("GHSA-cp9v-662q-vvx9")
    assert record.advisory["id"] == "GHSA-cp9v-662q-vvx9"
    assert aliases(record.advisory) == ["CVE-2026-112405"]
    assert withdrawn(record.advisory) is None
    assert record.response.url == "https://api.osv.dev/v1/vulns/GHSA-cp9v-662q-vvx9"
    assert record.response.body == (OSV / "vuln-GHSA-cp9v-662q-vvx9.json").read_bytes()


def test_the_withdrawn_field_is_read() -> None:
    record = OsvClient(RecordedFetcher(OSV)).vuln("PYSEC-2019-64")
    assert withdrawn(record.advisory) == "2023-03-14T07:01:09.371407Z"
    assert aliases(record.advisory) == []


def test_a_failed_batch_query_is_a_source_failure(derive_osv: Callable[..., Path]) -> None:
    root = derive_osv(errors={"querybatch-vulnerable": "timed out"})
    with pytest.raises(SourceFailedError):
        OsvClient(RecordedFetcher(root)).query(ENTRIES)


def test_an_error_status_is_a_source_failure(tmp_path: Path) -> None:
    meta = {
        "method": "GET",
        "url": "https://api.osv.dev/v1/vulns/GHSA-none",
        "status": 500,
        "retrieved_at": "2026-10-24T00:00:00Z",
        "body_file": "e.json",
    }
    (tmp_path / "e.json").write_text("{}", encoding="utf-8")
    (tmp_path / "e.meta.json").write_text(json.dumps(meta), encoding="utf-8")
    with pytest.raises(SourceFailedError) as caught:
        OsvClient(RecordedFetcher(tmp_path)).vuln("GHSA-none")
    assert caught.value.source == SOURCE

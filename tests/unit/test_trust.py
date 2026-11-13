"""The trust rules for imported claims (T013; FR-001, FR-002, FR-004; research A12)."""

from __future__ import annotations

from typing import Any

import pytest

from model_dependabot.assurance.trust import (
    NO_CHECK_CONFIRMS,
    claim_verification,
    counts_as_code_free,
    needs_confirmation,
)

SHA = "sha256:" + "a" * 64


def weight(format_origin: str | None, **fields: Any) -> dict[str, Any]:
    entry = {
        "kind": "weight_file",
        "identifier": SHA,
        "pinned": True,
        "location": "model.safetensors",
        "format": "safetensors",
        "can_run_code": False,
        "hub_repo": None,
        "hub_revision": None,
        "format_origin": format_origin,
    }
    return entry | fields


def check(outcome: str, claim: str = "code_free") -> dict[str, Any]:
    return {"claim": claim, "outcome": outcome, "entry_identifier": SHA, "reason": None}


@pytest.mark.parametrize(
    ("format_origin", "version_origin", "expected"),
    [
        ("import", "import", True),
        ("import", None, True),
        (None, None, True),  # legacy: the database cannot tell an import from a manifest
        (None, "import", True),
        ("bytes", "import", False),  # an imported local file classified from its bytes
        ("bytes", "manifest", False),
        ("name", "manifest", False),
        ("record", "record", False),
        (None, "record", False),  # back-filled from a registration record
        (None, "manifest", False),
    ],
)
def test_needs_confirmation(
    format_origin: str | None, version_origin: str | None, expected: bool
) -> None:
    assert needs_confirmation(weight(format_origin), version_origin) is expected


def test_only_weight_files_carry_a_format_claim() -> None:
    package = {"kind": "package", "format_origin": None, "pinned": True}
    assert needs_confirmation(package, None) is False


@pytest.mark.parametrize("format_origin", ["bytes", "name", "record"])
def test_an_owner_trusted_code_free_file_counts(format_origin: str) -> None:
    assert counts_as_code_free(weight(format_origin), "manifest", None) is True


@pytest.mark.parametrize(
    ("latest", "expected"),
    [
        (None, False),
        (check("unreadable"), False),
        (check("contradicted"), False),
        (check("confirmed"), True),
    ],
)
def test_an_imported_code_free_claim_counts_only_once_confirmed(
    latest: dict[str, Any] | None, expected: bool
) -> None:
    assert counts_as_code_free(weight("import"), "import", latest) is expected
    assert counts_as_code_free(weight(None), None, latest) is expected


@pytest.mark.parametrize(
    "entry",
    [
        weight("bytes", pinned=False, gap_reason="no revision"),
        weight("bytes", can_run_code=True, format="pickle"),
        weight("bytes", can_run_code=None, format="unknown"),
        {"kind": "package", "pinned": True, "can_run_code": False, "format_origin": "bytes"},
    ],
)
def test_only_a_pinned_code_free_weight_file_can_count(entry: dict[str, Any]) -> None:
    assert counts_as_code_free(entry, "manifest", check("confirmed")) is False


def _claims(entry: dict[str, Any], origin: str | None, checks: list[dict[str, Any]]) -> dict:
    return {item["claim"]: item for item in claim_verification(entry, origin, checks)}


def test_owner_and_measured_claims() -> None:
    local = _claims(weight("bytes"), "manifest", [])
    assert {name: item["verification"] for name, item in local.items()} == {
        "format": "measured",
        "can_run_code": "measured",
        "sha256": "measured",
    }
    hub = weight("name", location=None, hub_repo="o/n", hub_revision="b" * 40)
    claims = _claims(hub, "manifest", [])
    assert {name: item["verification"] for name, item in claims.items()} == {
        "format": "owner",
        "can_run_code": "owner",
        "sha256": "owner",
        "revision": "owner",
    }
    assert claims["format"]["origin"] == "name"
    assert claims["revision"]["value"] == "b" * 40


def test_imported_claims_are_unverified_until_checked() -> None:
    claims = _claims(weight("import"), "import", [])
    assert {item["verification"] for item in claims.values()} == {"unverified"}
    assert {item["origin"] for item in claims.values()} == {"import"}


def test_a_confirmation_and_a_contradiction_are_shown() -> None:
    confirmed = _claims(
        weight("import"), "import", [check("confirmed"), check("confirmed", "identity")]
    )
    assert confirmed["format"]["verification"] == "confirmed"
    assert confirmed["can_run_code"]["verification"] == "confirmed"
    assert confirmed["sha256"]["verification"] == "confirmed"
    contradicted = _claims(weight("import"), "import", [check("contradicted")])
    assert contradicted["can_run_code"]["verification"] == "contradicted"
    assert contradicted["sha256"]["verification"] == "unverified"
    # The latest check decides: a later confirmation follows an unreadable read.
    later = _claims(weight("import"), "import", [check("unreadable"), check("confirmed")])
    assert later["can_run_code"]["verification"] == "confirmed"


def test_legacy_claims_say_where_they_came_from() -> None:
    claims = _claims(weight(None), None, [])
    assert {item["origin"] for item in claims.values()} == {"legacy"}
    assert {item["verification"] for item in claims.values()} == {"unverified"}


def test_imported_package_hashes_and_revisions_say_no_check_confirms_them() -> None:
    package = {
        "kind": "package",
        "identifier": "pkg:pypi/torch@2.5.1",
        "pinned": True,
        "hashes": ["sha256:" + "c" * 64],
        "format_origin": None,
    }
    [claim] = claim_verification(package, "import", [])
    assert claim == {
        "claim": "sha256",
        "value": ["sha256:" + "c" * 64],
        "origin": "import",
        "verification": "unverified",
        "reason": NO_CHECK_CONFIRMS,
    }
    base = {
        "kind": "base_model",
        "identifier": "pkg:huggingface/o/n@" + "d" * 40,
        "pinned": True,
        "version": "d" * 40,
        "format_origin": None,
    }
    [revision] = claim_verification(base, "import", [])
    assert (revision["claim"], revision["verification"], revision["reason"]) == (
        "revision",
        "unverified",
        "no check confirms this claim",
    )
    dataset = {
        "kind": "dataset",
        "identifier": "hf-dataset:o/d@" + "e" * 40,
        "pinned": True,
        "hub_repo": "o/d",
        "hub_revision": "e" * 40,
        "format_origin": None,
    }
    assert [c["verification"] for c in claim_verification(dataset, "manifest", [])] == ["owner"]
    assert [c["verification"] for c in claim_verification(dataset, "import", [])] == ["unverified"]


def test_a_gap_makes_no_claims() -> None:
    gap = weight("bytes", pinned=False, identifier=None, gap_reason="no revision")
    assert claim_verification(gap, "manifest", []) == []

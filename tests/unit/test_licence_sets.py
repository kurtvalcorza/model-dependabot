"""Licence sets and SPDX exceptions (owner decisions of 2026-10-24; research U8, FR-008 to FR-010).

A source can declare more than one licence entry. Every recognised entry is recorded, and two
licences are compared as the normalised set of their entries, order ignored. ``<licence> WITH
<exception>`` is normalised against the vendored SPDX exceptions list; an unknown exception stays
unrecognised. Hub answers are derived from the recorded ``hf_upstream/model-normal`` answer for
``openai-community/gpt2``; the DataCite ``rightsList`` is built in the test.
"""

from __future__ import annotations

import shutil
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from model_dependabot.inventory import cyclonedx
from model_dependabot.inventory.build import record_licences
from model_dependabot.lifecycle import run_check
from model_dependabot.sources.datacite import declared_licence
from model_dependabot.sources.fetcher import RecordedFetcher
from model_dependabot.sources.hf import read_model
from model_dependabot.store import Store
from model_dependabot.upstream.licences import (
    LICENCE_DIR,
    LicenceListError,
    load_licence_list,
    normalise,
    same_licence,
)

MOMENT = datetime(2026, 10, 24, 6, 0, tzinfo=UTC)
GPT2 = "openai-community/gpt2"
GPT2_SHA = "607a30d783dfa663caf39e06633721c8d4cfcd7e"
PURL = f"pkg:huggingface/openai-community/gpt2@{GPT2_SHA}"


# --- SPDX exceptions -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("declared", "expected"),
    [
        (
            "GPL-2.0-or-later WITH Classpath-exception-2.0",
            "GPL-2.0-or-later WITH Classpath-exception-2.0",
        ),
        (
            "gpl-2.0-or-later with classpath-exception-2.0",
            "GPL-2.0-or-later WITH Classpath-exception-2.0",
        ),
        ("Apache-2.0 WITH llvm-exception", "Apache-2.0 WITH LLVM-exception"),
        (
            "MIT OR (gpl-3.0-only with gcc-exception-3.1)",
            "MIT OR (GPL-3.0-only WITH GCC-exception-3.1)",
        ),
    ],
)
def test_a_with_expression_normalises_its_exception_ignoring_case(
    declared: str, expected: str
) -> None:
    licence = normalise(declared)
    assert (licence.normalised, licence.form) == (expected, "expression")
    assert licence.recognised


@pytest.mark.parametrize(
    "declared",
    [
        "GPL-2.0-only WITH Made-up-exception",  # an exception the list does not have
        "MIT WITH Apache-2.0",  # a licence where an exception belongs
        "Classpath-exception-2.0 OR MIT",  # an exception where a licence belongs
        "Classpath-exception-2.0",
    ],
)
def test_an_unknown_or_misplaced_exception_stays_unrecognised(declared: str) -> None:
    licence = normalise(declared)
    assert (licence.normalised, licence.form) == (declared, "unrecognised")


def test_a_changed_exception_is_a_real_difference() -> None:
    a = normalise("GPL-2.0-or-later WITH Classpath-exception-2.0")
    assert same_licence(a, normalise("gpl-2.0-or-later with CLASSPATH-EXCEPTION-2.0"))
    assert not same_licence(a, normalise("GPL-2.0-or-later WITH GCC-exception-3.1"))


def test_the_exceptions_list_is_checked_against_sha256sums(tmp_path: Path) -> None:
    directory = tmp_path / "licences"
    shutil.copytree(LICENCE_DIR, directory)
    listed = load_licence_list(directory)
    assert listed.exception("classpath-exception-2.0") == "Classpath-exception-2.0"
    path = directory / "spdx-exceptions-3.29.0.json"
    path.write_bytes(path.read_bytes().replace(b"Classpath", b"Klasspath", 1))
    with pytest.raises(LicenceListError, match="SHA256SUMS"):
        load_licence_list(directory)


# --- Licence sets ----------------------------------------------------------------------------


def test_several_entries_normalise_to_a_sorted_set() -> None:
    licence = normalise("mit\nCC BY 4.0")
    assert (licence.normalised, licence.form) == ("CC-BY-4.0\nMIT", "spdx")
    assert [entry.normalised for entry in licence.entries] == ["MIT", "CC-BY-4.0"]
    assert normalise("MIT\nMIT OR Apache-2.0").form == "expression"
    assert normalise("MIT\nllama3.1").form == "unrecognised"


def test_order_and_repeated_entries_leave_the_set_equal() -> None:
    a = normalise("MIT\nCC-BY-4.0")
    assert same_licence(a, normalise("CC BY 4.0\nmit"))
    assert same_licence(a, normalise("mit\nCC-BY-4.0\nMIT"))
    assert not same_licence(a, normalise("MIT"))
    assert not same_licence(a, normalise("MIT\nCC-BY-4.0\nApache-2.0"))


def test_datacite_records_every_licence_entry_and_skips_access_rights() -> None:
    attributes = {
        "rightsList": [
            {"rights": "Open Access", "rightsUri": "info:eu-repo/semantics/openAccess"},
            {
                "rights": "Creative Commons Attribution 4.0 International",
                "rightsIdentifier": "cc-by-4.0",
            },
            {"rights": "MIT License"},
        ]
    }
    assert declared_licence(attributes) == "cc-by-4.0\nMIT License"
    assert (
        declared_licence({"rightsList": [{"rightsUri": "info:eu-repo/semantics/closedAccess"}]})
        is None
    )


def card(licence: object) -> Callable[[dict[str, Any]], dict[str, Any]]:
    def change(body: dict[str, Any]) -> dict[str, Any]:
        body["cardData"]["license"] = licence
        return body

    return change


def test_the_hub_records_every_entry_of_a_licence_list(
    derive_upstream: Callable[..., Path],
) -> None:
    root = derive_upstream(changes={"hf_upstream/model-normal": card(["mit", "apache-2.0"])})
    assert read_model(RecordedFetcher(root), GPT2).licence == "mit\napache-2.0"


def test_register_records_the_full_set_and_cyclonedx_holds_every_entry(
    derive_upstream: Callable[..., Path],
) -> None:
    root = derive_upstream(changes={"hf_upstream/model-normal": card(["mit", "apache-2.0"])})
    entries = [{"kind": "base_model", "identifier": PURL, "pinned": True, "name": GPT2}]
    record_licences(entries, RecordedFetcher(root), lambda doi: None)
    assert (entries[0]["recorded_licence"], entries[0]["licence_form"]) == (
        "Apache-2.0\nMIT",
        "spdx",
    )
    assert cyclonedx._licenses(entries[0]) == [
        {"license": {"id": "Apache-2.0"}},
        {"license": {"id": "MIT"}},
    ]


def test_a_mixed_set_round_trips_through_cyclonedx() -> None:
    entry = {
        "recorded_licence": "GPL-2.0-or-later WITH Classpath-exception-2.0\nMIT\nllama3.1",
        "licence_form": "unrecognised",
    }
    licenses = cyclonedx._licenses(entry)
    assert licenses == [
        {"expression": "GPL-2.0-or-later WITH Classpath-exception-2.0"},
        {"license": {"id": "MIT"}},
        {"license": {"name": "llama3.1"}},
    ]
    assert cyclonedx._read_licence({"licenses": licenses}) == (
        entry["recorded_licence"],
        "unrecognised",
    )


@pytest.fixture
def store(tmp_path: Path) -> Store:
    with Store(tmp_path / "md.db", now=lambda: MOMENT) as opened:
        yield opened


def register(store: Store, recorded: str | None, form: str | None) -> None:
    store.add_model("m")
    entry = {
        "kind": "base_model",
        "identifier": PURL,
        "pinned": True,
        "name": GPT2,
        "version": GPT2_SHA,
        "recorded_licence": recorded,
        "licence_form": form,
    }
    store.add_version("m", {}, "0" * 64, [entry])


def check(store: Store, derive: Callable[..., Path], licence: object) -> None:
    root = derive(changes={"hf_upstream/model-normal": card(licence)})
    run_check(store, RecordedFetcher(root), ["m"], ("hf-hub",))


def alerts(store: Store) -> list[dict[str, Any]]:
    found = store.alerts_for("m", ["open", "cleared"])
    return [a for a in found if a["kind"] == "licence_changed"]


def events(store: Store) -> list[str]:
    return [e["kind"] for e in store.watch_events("m") if e["kind"].startswith("licence_")]


def test_reordering_or_repeating_an_entry_raises_nothing(
    store: Store, derive_upstream: Callable[..., Path]
) -> None:
    register(store, "Apache-2.0\nMIT", "spdx")
    check(store, derive_upstream, ["mit", "apache-2.0"])
    check(store, derive_upstream, ["Apache-2.0", "mit", "MIT"])
    assert alerts(store) == []
    assert events(store) == []


def test_a_baseline_set_reordered_raises_nothing(
    store: Store, derive_upstream: Callable[..., Path]
) -> None:
    register(store, None, None)
    check(store, derive_upstream, ["mit", "apache-2.0"])
    check(store, derive_upstream, ["apache-2.0", "mit"])
    assert alerts(store) == []
    assert events(store) == []


def test_a_changed_set_opens_the_alert_and_its_return_clears_it(
    store: Store, derive_upstream: Callable[..., Path]
) -> None:
    register(store, "Apache-2.0\nMIT", "spdx")
    check(store, derive_upstream, ["mit"])
    (alert,) = alerts(store)
    assert alert["state"] == "open"
    assert alert["cause"]["recorded_licence"] == "Apache-2.0\nMIT"
    assert alert["cause"]["declared_normalised"] == "MIT"
    check(store, derive_upstream, ["mit", "apache-2.0"])
    (alert,) = alerts(store)
    assert alert["state"] == "cleared"

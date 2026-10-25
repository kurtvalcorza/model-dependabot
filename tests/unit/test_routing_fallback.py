"""A DOI routed to Zenodo without a record id is still asked at Zenodo (T061, no silent skip).

Found in the T061 walkthrough: DataCite gives Zenodo DOIs the landing URL
``https://zenodo.org/doi/10.5281/zenodo.<id>``, which the router once read as "Zenodo, no id", so
Zenodo was never asked. ``datacite.route`` now reads that form; ``lifecycle._routed`` also falls
back to the DOI's own record id for a routing row stored without one.
"""

from __future__ import annotations

from pathlib import Path

from model_dependabot.lifecycle import _routed
from model_dependabot.store import Store


def test_a_zenodo_routing_without_an_id_falls_back_to_the_dois_record_id(tmp_path: Path) -> None:
    with Store(tmp_path / "md.db") as store:
        store.set_routing("10.5281/zenodo.20066074", agency="DataCite", repository="zenodo")
        assert _routed(store, ["10.5281/zenodo.20066074"], "zenodo") == {
            "10.5281/zenodo.20066074": "20066074"
        }


def test_a_figshare_routing_without_an_id_is_not_guessed(tmp_path: Path) -> None:
    with Store(tmp_path / "md.db") as store:
        store.set_routing("10.6084/m9.figshare.1", agency="DataCite", repository="figshare")
        assert _routed(store, ["10.6084/m9.figshare.1"], "figshare") == {}


def test_a_routed_id_is_used_as_stored(tmp_path: Path) -> None:
    with Store(tmp_path / "md.db") as store:
        store.set_routing(
            "10.5281/zenodo.3242074",
            agency="DataCite",
            repository="zenodo",
            repository_id="3242074",
        )
        assert _routed(store, ["10.5281/zenodo.3242074"], "zenodo") == {
            "10.5281/zenodo.3242074": "3242074"
        }

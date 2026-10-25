"""Manifest additions: tied paper DOIs and hub datasets (contracts/manifest.md, tasks T012)."""

from __future__ import annotations

from pathlib import Path

import pytest

from model_dependabot.inventory.build import NO_REVISION, NOT_A_COMMIT, build_entries
from model_dependabot.manifest import ManifestError, load_manifest

COMMIT = "0123abcd" * 5


def _write(tmp_path: Path, datasets: str) -> Path:
    path = tmp_path / "model.toml"
    path.write_text('[model]\nid = "m"\n' + datasets, encoding="utf-8")
    return path


def test_paper_doi_is_a_list_of_dois(tmp_path: Path) -> None:
    manifest = load_manifest(
        _write(
            tmp_path,
            '[[datasets]]\ndoi = "10.5281/zenodo.20066074"\n'
            'paper_doi = ["10.1177/1758835919874651", "https://doi.org/10.5555/ABC"]\n',
        )
    )
    assert manifest.datasets[0].paper_dois == ("10.1177/1758835919874651", "10.5555/abc")
    entry = build_entries(manifest)[0]
    assert entry["identifier"] == "10.5281/zenodo.20066074"
    assert entry["paper_dois"] == ["10.1177/1758835919874651", "10.5555/abc"]


@pytest.mark.parametrize("value", ['"10.1/x"', "[1]", '["not-a-doi"]', '[""]'])
def test_paper_doi_must_be_a_list_of_dois(tmp_path: Path, value: str) -> None:
    with pytest.raises(ManifestError, match="paper_doi"):
        load_manifest(_write(tmp_path, f'[[datasets]]\ndoi = "10.1/x"\npaper_doi = {value}\n'))


def test_a_dataset_without_paper_doi_has_none(tmp_path: Path) -> None:
    manifest = load_manifest(_write(tmp_path, '[[datasets]]\ndoi = "10.1/x"\n'))
    assert manifest.datasets[0].paper_dois == ()
    assert build_entries(manifest)[0]["paper_dois"] is None


def test_a_hub_dataset_is_pinned_by_commit(tmp_path: Path) -> None:
    manifest = load_manifest(
        _write(tmp_path, f'[[datasets]]\nhub = "hf:datasets/owner/name"\nrevision = "{COMMIT}"\n')
    )
    spec = manifest.datasets[0]
    assert (spec.hub, spec.revision, spec.doi) == ("owner/name", COMMIT, None)
    entry = build_entries(manifest)[0]
    assert entry["kind"] == "dataset"
    assert entry["identifier"] == f"hf-dataset:owner/name@{COMMIT}"
    assert entry["pinned"] is True
    assert (entry["hub_repo"], entry["hub_revision"]) == ("owner/name", COMMIT)


def test_a_hub_dataset_without_revision_is_a_gap(tmp_path: Path) -> None:
    manifest = load_manifest(_write(tmp_path, '[[datasets]]\nhub = "hf:datasets/owner/name"\n'))
    entry = build_entries(manifest)[0]
    assert (entry["pinned"], entry["gap_reason"]) == (False, NO_REVISION)
    assert entry["hub_repo"] == "owner/name"


def test_a_hub_dataset_with_a_branch_is_a_gap(tmp_path: Path) -> None:
    manifest = load_manifest(
        _write(tmp_path, '[[datasets]]\nhub = "hf:datasets/owner/name"\nrevision = "main"\n')
    )
    assert build_entries(manifest)[0]["gap_reason"] == NOT_A_COMMIT


def test_both_doi_and_hub_is_an_error(tmp_path: Path) -> None:
    table = f'doi = "10.1/x"\nhub = "hf:datasets/owner/name"\nrevision = "{COMMIT}"\n'
    with pytest.raises(ManifestError, match="exactly one of 'doi' and 'hub', not both"):
        load_manifest(_write(tmp_path, "[[datasets]]\n" + table))


@pytest.mark.parametrize("table", ['sha256 = "' + "a" * 64 + '"\n', 'paper_doi = ["10.5555/p"]\n'])
def test_neither_doi_nor_hub_stays_001s_gap(tmp_path: Path, table: str) -> None:
    # contracts/manifest.md (owner ruling): neither is 001's gap "no DOI"; only both is an error.
    entry = build_entries(load_manifest(_write(tmp_path, "[[datasets]]\n" + table)))[0]
    assert (entry["pinned"], entry["gap_reason"]) == (False, "no DOI")


@pytest.mark.parametrize("hub", ["hf:owner/name", "datasets/owner/name", "hf:datasets/owner"])
def test_a_hub_dataset_reference_names_a_dataset(tmp_path: Path, hub: str) -> None:
    with pytest.raises(ManifestError, match="hub"):
        load_manifest(_write(tmp_path, f'[[datasets]]\nhub = "{hub}"\nrevision = "{COMMIT}"\n'))


def test_revision_is_for_hub_datasets_only(tmp_path: Path) -> None:
    with pytest.raises(ManifestError, match="revision"):
        load_manifest(_write(tmp_path, f'[[datasets]]\ndoi = "10.1/x"\nrevision = "{COMMIT}"\n'))


def test_001_rules_still_hold(tmp_path: Path) -> None:
    with pytest.raises(ManifestError, match="unknown key"):
        load_manifest(_write(tmp_path, '[[datasets]]\ndoi = "10.1/x"\nlicence = "mit"\n'))
    manifest = load_manifest(_write(tmp_path, '[[datasets]]\ndoi = "not-a-doi"\n'))
    assert build_entries(manifest)[0]["gap_reason"] == "not a DOI"

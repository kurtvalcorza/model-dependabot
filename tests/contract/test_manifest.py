"""The registration manifest (T013, contracts/manifest.md)."""

from __future__ import annotations

from pathlib import Path

import pytest

from model_dependabot.cli import EXIT_INVALID_INPUT, main
from model_dependabot.inventory.build import build_entries
from model_dependabot.manifest import ManifestError, load_manifest

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
EXAMPLE = FIXTURES / "manifests" / "example.toml"


def _write(tmp_path: Path, text: str, name: str = "model.toml") -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_the_example_manifest_loads() -> None:
    manifest = load_manifest(EXAMPLE)
    assert manifest.model_id == "example-detector"
    assert manifest.name == "Example detector, test fixture"
    assert manifest.owner == "Model owner"
    assert len(manifest.weights) == 5
    assert manifest.base_model is not None
    assert manifest.base_model.repo == "openai-community/gpt2"
    assert [dataset.doi for dataset in manifest.datasets] == ["10.5555/example-dataset-0001"]


def test_model_id_is_required(tmp_path: Path) -> None:
    path = _write(tmp_path, '[model]\nname = "no id"\n')
    with pytest.raises(ManifestError, match=r"model.id"):
        load_manifest(path)


def test_a_manifest_without_a_model_table_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(ManifestError, match=r"model.id"):
        load_manifest(_write(tmp_path, "[environment]\n"))


@pytest.mark.parametrize(
    "text",
    [
        '[model]\nid = "m"\nversion = "1"\n',
        '[model]\nid = "m"\n[[weights]]\npath = "w.pt"\nsha = "x"\n',
        '[model]\nid = "m"\n[environment]\nlocks = "x.txt"\n',
        '[model]\nid = "m"\n[base_model]\nhub = "hf:a/b"\nrev = "x"\n',
        '[model]\nid = "m"\n[[datasets]]\ndoi = "10.1/x"\nmd5 = "x"\n',
        '[model]\nid = "m"\n[[dataset]]\ndoi = "10.1/x"\n',
    ],
)
def test_unknown_keys_are_an_error(tmp_path: Path, text: str) -> None:
    (tmp_path / "w.pt").write_bytes(b"x")
    with pytest.raises(ManifestError, match="unknown key"):
        load_manifest(_write(tmp_path, text))


def test_unknown_keys_exit_1_from_register(tmp_path: Path) -> None:
    path = _write(tmp_path, '[model]\nid = "m"\nversoin = "1"\n')
    assert main(["register", str(path), "--db", str(tmp_path / "x.db")]) == EXIT_INVALID_INPUT


def test_invalid_toml_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(ManifestError):
        load_manifest(_write(tmp_path, "[model\nid = 1\n"))


def test_paths_resolve_relative_to_the_manifest(tmp_path: Path) -> None:
    sub = tmp_path / "deep" / "er"
    sub.mkdir(parents=True)
    (sub / "w.safetensors").write_bytes(b"weights")
    (tmp_path / "deep" / "lock.txt").write_text("a==1.0 --hash=sha256:" + "a" * 64 + "\n")
    path = _write(
        sub,
        '[model]\nid = "m"\n[[weights]]\npath = "w.safetensors"\n'
        '[environment]\nlock = "../lock.txt"\n',
    )
    manifest = load_manifest(path)
    assert manifest.weights[0].path == (sub / "w.safetensors").resolve()
    assert manifest.weights[0].relative == "w.safetensors"
    assert manifest.lock == (tmp_path / "deep" / "lock.txt").resolve()


def test_a_missing_local_file_is_an_error(tmp_path: Path) -> None:
    path = _write(tmp_path, '[model]\nid = "m"\n[[weights]]\npath = "absent.pt"\n')
    with pytest.raises(ManifestError, match=r"absent.pt"):
        load_manifest(path)


def test_a_weight_needs_exactly_one_of_path_and_hub(tmp_path: Path) -> None:
    (tmp_path / "w.pt").write_bytes(b"x")
    both = '[model]\nid = "m"\n[[weights]]\npath = "w.pt"\nhub = "hf:a/b"\nfile = "w.pt"\n'
    with pytest.raises(ManifestError):
        load_manifest(_write(tmp_path, both))
    with pytest.raises(ManifestError):
        load_manifest(_write(tmp_path, '[model]\nid = "m"\n[[weights]]\nfile = "w.pt"\n'))


def test_a_hub_reference_must_be_a_hugging_face_repository(tmp_path: Path) -> None:
    text = '[model]\nid = "m"\n[base_model]\nhub = "gh:a/b"\nrevision = "' + "0" * 40 + '"\n'
    with pytest.raises(ManifestError, match="hf:"):
        load_manifest(_write(tmp_path, text))


def test_a_hub_weight_file_without_revision_is_a_gap(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        '[model]\nid = "m"\n[[weights]]\nhub = "hf:openai-community/gpt2"\n'
        'file = "pytorch_model.bin"\n',
    )
    (entry,) = build_entries(load_manifest(path), fetcher=None)
    assert entry["kind"] == "weight_file"
    assert entry["pinned"] is False
    assert entry["gap_reason"] == "no revision"
    assert (entry["hub_repo"], entry["hub_file"]) == ("openai-community/gpt2", "pytorch_model.bin")


def test_registration_never_fails_because_of_a_gap(tmp_path: Path) -> None:
    (tmp_path / "lock.txt").write_text("numpy\nrequests==2.32.5\n")
    path = _write(
        tmp_path,
        '[model]\nid = "gappy"\n'
        '[[weights]]\nhub = "hf:openai-community/gpt2"\nfile = "pytorch_model.bin"\n'
        '[environment]\nlock = "lock.txt"\n'
        '[base_model]\nhub = "hf:openai-community/gpt2"\n'
        "[[datasets]]\n"
        'sha256 = "' + "a" * 64 + '"\n',
    )
    entries = build_entries(load_manifest(path), fetcher=None)
    assert entries, "a gap is an entry, not a failure"
    assert all(entry["pinned"] is False for entry in entries)
    assert all(entry["gap_reason"] for entry in entries)
    db = tmp_path / "x.db"
    assert main(["register", str(path), "--db", str(db)]) == 0


def test_a_manifest_with_only_a_model_id_registers(tmp_path: Path) -> None:
    path = _write(tmp_path, '[model]\nid = "bare"\n')
    manifest = load_manifest(path)
    assert (manifest.weights, manifest.lock, manifest.base_model, manifest.datasets) == (
        (),
        None,
        None,
        (),
    )

"""The ``inventory audit`` JSON contract and exit codes (T029, contracts/cli.md)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from model_dependabot.cli import EXIT_INVALID_INPUT, EXIT_OK, main, make_handlers
from model_dependabot.sources.fetcher import RecordedFetcher

NOW = datetime(2026, 11, 13, 9, 0, tzinfo=UTC)
SUMMARY = {
    "checked",
    "alerts_open",
    "alerts_excepted",
    "watch_events",
    "entries",
    "verified",
    "declared_but_unverified",
    "conflicting",
    "unavailable",
    "gaps",
    "uncheckable",
    "sources_failed",
    "sources_stale",
    "sources_not_checked",
}
TOP = {
    "model_id",
    "version",
    "produced_at",
    "stale_after_hours",
    "statement",
    "summary",
    "findings",
    "assurance",
    "coverage",
    "lineage",  # feature 011 (FR-030)
}


@pytest.fixture
def audit(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    db = tmp_path / "md.db"
    manifest = tmp_path / "model.toml"
    manifest.write_text('[model]\nid = "m"\n\n[base_model]\nhub = "hf:o/base"\n', "utf-8")
    handlers = make_handlers(fetcher=RecordedFetcher(tmp_path / "none"), now=lambda: NOW)
    assert main(["register", str(manifest), "--db", str(db)], handlers=handlers) == EXIT_OK
    capsys.readouterr()

    def invoke(*argv: str) -> tuple[int, Any]:
        code = main(["inventory", "audit", *argv, "--db", str(db), "--json"], handlers=handlers)
        out = capsys.readouterr().out
        return code, json.loads(out) if out.strip() else None

    return invoke


def test_the_json_has_every_field_of_the_contract(audit) -> None:
    code, report = audit("m")
    assert code == EXIT_OK
    assert set(report) == TOP
    assert set(report["summary"]) == SUMMARY
    assert set(report["findings"]) == {"state", "alerts", "excepted", "watch_events"}
    assert set(report["assurance"]) == {"entries", "undeclared_kinds"}
    assert set(report["coverage"]) == {"sources", "uncheckable"}
    assert set(report["lineage"]) == {"edges", "problems", "notes"}
    assert report["produced_at"] == "2026-11-13T09:00:00Z"
    assert report["stale_after_hours"] == 24
    [entry] = report["assurance"]["entries"]
    assert set(entry) == {"kind", "identifier", "location", "status", "gap_reason", "claims"}
    [uncheckable] = report["coverage"]["uncheckable"]
    assert set(uncheckable) == {"kind", "identifier", "location", "reason"}


def test_weak_assurance_still_exits_0(audit) -> None:
    code, report = audit("m")
    assert code == EXIT_OK
    assert report["summary"]["gaps"] == 1 and report["summary"]["checked"] is False


@pytest.mark.parametrize(
    "argv", [("nobody",), ("m", "--version", "2"), ("m", "--stale-after", "0")]
)
def test_bad_input_exits_1(audit, argv: tuple[str, ...]) -> None:
    assert audit(*argv)[0] == EXIT_INVALID_INPUT


def test_stale_after_changes_only_staleness(audit) -> None:
    _, default = audit("m")
    _, longer = audit("m", "--stale-after", "72")
    assert longer["stale_after_hours"] == 72

    def without_staleness(report: dict[str, Any]) -> dict[str, Any]:
        copy = json.loads(json.dumps(report))
        copy.pop("stale_after_hours")
        copy["summary"].pop("sources_stale")
        for source in copy["coverage"]["sources"]:
            source.pop("stale")
        return copy

    assert without_staleness(default) == without_staleness(longer)


def test_the_json_reports_partly_checked_after_a_check_of_some_sources(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """H3: through the command line, a check of one of two relevant sources is partly checked."""
    import shutil

    weights = Path(__file__).resolve().parent.parent / "fixtures" / "manifests" / "weights"
    shutil.copy(weights / "tiny.pt", tmp_path / "tiny.pt")
    manifest = tmp_path / "model.toml"
    manifest.write_text(
        '[model]\nid = "m"\n\n[[weights]]\npath = "tiny.pt"\n\n[base_model]\nhub = "hf:o/base"\n'
        f'revision = "{"c" * 40}"\n',
        "utf-8",
    )
    db = tmp_path / "md.db"
    handlers = make_handlers(fetcher=RecordedFetcher(tmp_path / "none"), now=lambda: NOW)
    assert main(["register", str(manifest), "--db", str(db)], handlers=handlers) == EXIT_OK
    main(["check", "m", "--source", "picklescan", "--db", str(db)], handlers=handlers)
    capsys.readouterr()
    code = main(["inventory", "audit", "m", "--db", str(db), "--json"], handlers=handlers)
    report = json.loads(capsys.readouterr().out)
    assert code == EXIT_OK
    assert report["findings"]["state"] == "partly_checked"
    assert report["summary"]["checked"] is False
    sources = {item["source"]: item["status"] for item in report["coverage"]["sources"]}
    assert sources == {"picklescan": "ok", "hf-hub": "not checked"}


def test_an_excepted_alert_is_counted_apart_from_the_open_ones(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], craft
) -> None:
    """Feature 004 (T020): ``alerts_open`` excludes excepted alerts; they are listed apart."""
    import hashlib

    db = tmp_path / "md.db"
    handlers = make_handlers(fetcher=RecordedFetcher(tmp_path / "none"), now=lambda: NOW)

    def cli(*argv: str) -> tuple[int, Any]:
        code = main([*argv, "--db", str(db), "--json"], handlers=handlers)
        out = capsys.readouterr().out
        return code, json.loads(out) if out.strip() else None

    model = tmp_path / "model"
    model.mkdir()
    reviewed = craft.protocol2_getattr()
    (model / "reviewed.pkl").write_bytes(reviewed)
    (model / "dangerous.pkl").write_bytes(craft.dangerous())
    manifest = model / "model.toml"
    manifest.write_text(
        '[model]\nid = "m"\n\n[[weights]]\npath = "reviewed.pkl"\n\n'
        '[[weights]]\npath = "dangerous.pkl"\n',
        "utf-8",
    )
    assert cli("register", str(manifest))[0] == EXIT_OK
    assert cli("check", "m", "--source", "picklescan")[0] == EXIT_OK
    sha = hashlib.sha256(reviewed).hexdigest()
    argv = ("--global", "__builtin__.getattr", "--sha256", sha, "--reason", "r", "--by", "O")
    assert cli("exception", "record", *argv)[0] == EXIT_OK
    assert cli("check", "m", "--source", "picklescan")[0] == EXIT_OK

    code, report = cli("inventory", "audit", "m")
    assert code == EXIT_OK
    assert (report["summary"]["alerts_open"], report["summary"]["alerts_excepted"]) == (1, 1)
    [open_alert] = report["findings"]["alerts"]
    assert open_alert["cause"]["location"] == "dangerous.pkl"
    [excepted] = report["findings"]["excepted"]
    assert (excepted["state"], excepted["cause"]["location"]) == ("excepted", "reviewed.pkl")


def test_coverage_items_carry_the_last_overview_state(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Feature 004 (T040): ``last_state`` is the source's overview state in its latest run."""
    db = tmp_path / "md.db"
    handlers = make_handlers(fetcher=RecordedFetcher(tmp_path / "none"), now=lambda: NOW)
    model = tmp_path / "model"
    model.mkdir()
    pickles = Path(__file__).resolve().parent.parent / "fixtures" / "pickles"
    (model / "i.pkl").write_bytes((pickles / "innocuous.pkl").read_bytes())
    manifest = '[model]\nid = "m"\n\n[[weights]]\npath = "i.pkl"\n'
    (model / "model.toml").write_text(manifest, "utf-8")

    def cli(*argv: str) -> Any:
        main([*argv, "--db", str(db), "--json"], handlers=handlers)
        out = capsys.readouterr().out
        return json.loads(out) if out.strip() else None

    cli("register", str(model / "model.toml"))
    before = cli("inventory", "audit", "m")
    assert [item["last_state"] for item in before["coverage"]["sources"]] == [None]
    cli("check", "m", "--source", "picklescan")
    after = cli("inventory", "audit", "m")
    [scan] = after["coverage"]["sources"]
    assert (scan["source"], scan["last_state"]) == ("picklescan", "passed")


# --- feature 011: the lineage section (T048, FR-030, SC-006) ------------------------------------

LINEAGE_FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "lineage"


def test_the_lineage_section_lists_edges_problems_and_notes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from lineage_support import Cli

    cli = Cli(tmp_path, capsys)
    base = tmp_path / "base.toml"
    base.write_text('[model]\nid = "example-adapter-base"\n', encoding="utf-8")
    cli.ok("register", str(base))
    cli.ok("register", str(LINEAGE_FIXTURES / "four-types.toml"))
    exported = tmp_path / "four.json"
    cli.ok("inventory", "export", "example-four", "-o", str(exported))
    cli.ok("import", str(exported), "--model-id", "example-imported")
    report = cli.ok("inventory", "audit", "example-imported")
    edges = report["lineage"]["edges"]
    assert [e["relationship"] for e in edges] == [
        "fine-tuned-from",
        "merged-from",
        "quantized-from",
        "adapter-for",
    ]
    assert {(e["origin"], e["claimed_origin"], e["state"]) for e in edges} == {
        ("import", "manifest", "unverified")
    }
    assert edges[3]["note"] == "resolved by id and version only"
    assert set(edges[3]) == {
        "edge_id",
        "relationship",
        "relationship_recorded",
        "parent",
        "origin",
        "claimed_origin",
        "state",
        "source",
        "recorded_at",
        "declared_count",
        "gap",
        "resolved",
        "note",
    }
    cli.ok("register", str(LINEAGE_FIXTURES / "merge-one-parent.toml"))
    merged = cli.ok("inventory", "audit", "example-merge-one")
    assert [note["kind"] for note in merged["lineage"]["notes"]] == ["merge_with_one_parent"]
    cli.ok("register", str(LINEAGE_FIXTURES / "duplicate.toml"))
    code, text = cli.run("inventory", "audit", "example-duplicate", as_json=False)
    assert code == EXIT_OK
    assert "Lineage (1 edge, 1 problem):" in text
    assert "  problem duplicate_parent: hf:example-org/base-a@" in text
    code, text = cli.run("inventory", "audit", "example-merge-one", as_json=False)
    assert "  note merge with one parent" in text


def test_no_output_shows_an_edge_as_verified(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """SC-006: the state of every edge in every output is owner or unverified."""
    from lineage_support import Cli

    cli = Cli(tmp_path, capsys)
    outputs = [cli.ok("register", str(LINEAGE_FIXTURES / "merge-two.toml"))]
    outputs.append(
        cli.ok("import", str(LINEAGE_FIXTURES / "claims-manifest.json"), "--model-id", "i")
    )
    outputs.append(cli.ok("inventory", "show", "example-merge"))
    outputs.append(cli.ok("inventory", "audit", "example-merge"))
    outputs.append(cli.ok("inventory", "audit", "i"))
    outputs.append(cli.ok("alerts", "example-merge"))
    outputs.append(cli.ok("check", "example-merge", "--source", "picklescan"))

    def states(value: Any) -> list[str]:
        if isinstance(value, dict):
            found = [value["state"]] if {"relationship", "state"} <= set(value) else []
            return found + [s for item in value.values() for s in states(item)]
        if isinstance(value, list):
            return [s for item in value for s in states(item)]
        return []

    seen = [state for output in outputs for state in states(output)]
    assert seen and set(seen) <= {"owner", "unverified"}
    for argv in (("inventory", "show", "example-merge"), ("inventory", "audit", "i")):
        code, text = cli.run(*argv, as_json=False)
        section = text[text.index("Lineage (") :]  # the lineage section is last
        assert code == EXIT_OK and "verified" not in section.replace("unverified", "")

"""No personal data reaches the database or the evidence store (T057; quickstart.md section 7,
FR-005, research U10).

The recorded fixtures were redacted when they were recorded, so the personal fields are put back
into derived states with made-up canary values: the takedown log's ``requesting_entity`` and
``file`` columns, the Zenodo tombstone's ``removed_by``, ``note`` and ``citation_text``, Zenodo
``metadata.creators``, ``metadata.contributors`` and ``owners``, Figshare ``authors`` and
``citation``, Crossref ``author`` and ``reference[].author`` / ``reference[].unstructured`` and
DataCite ``creators`` and ``contributors``. After ``register`` and a scheduled check of the worked
example, no canary is found in any file under the database directory, the takedown log keeps only
``date`` and ``reported_content``, and the evidence records list the removed fields.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from test_source_failure_upstream import figshare_extra, manifest

from model_dependabot.cli import EXIT_OK, main, make_handlers
from model_dependabot.sources.fetcher import RecordedFetcher
from model_dependabot.store import Store

CANARY = "canary-person-7f3a"
DELETED = "10.5281/zenodo.12584226"


def person(n: int) -> dict[str, Any]:
    return {"name": f"{CANARY}-{n}", "given": f"{CANARY}-{n}", "family": f"{CANARY}-{n}"}


def takedown_log(text: str) -> str:
    lines = text.splitlines()
    rows = ["date,requesting_entity,file,reported_content"]
    for n, line in enumerate(lines[1:]):
        date, _, content = line.partition(",")
        rows.append(f"{date},{CANARY}-entity-{n},{CANARY}-file-{n}.pdf,{content}")
    return "\n".join(rows) + "\n"


def zenodo_tombstone(body: dict[str, Any]) -> dict[str, Any]:
    tombstone = body.setdefault("tombstone", {})
    tombstone |= {
        "removed_by": {"user": f"{CANARY}-remover"},
        "note": f"{CANARY}-note",
        "citation_text": f"{CANARY}-citation",
    }
    return body


def zenodo_record(body: dict[str, Any]) -> dict[str, Any]:
    body.setdefault("metadata", {}).update(creators=[person(1)], contributors=[person(2)])
    body["owners"] = [{"id": f"{CANARY}-owner"}]
    return body


def figshare(body: dict[str, Any]) -> dict[str, Any]:
    return body | {"authors": [{"full_name": f"{CANARY}-author"}], "citation": f"{CANARY}-cite"}


def crossref(body: dict[str, Any]) -> dict[str, Any]:
    body["message"]["author"] = [person(3)]
    body["message"]["reference"] = [
        {"key": "r1", "author": f"{CANARY}-ref-author", "unstructured": f"{CANARY}-ref-text"}
    ]
    return body


def datacite(body: dict[str, Any]) -> dict[str, Any]:
    body["data"]["attributes"] |= {"creators": [person(4)], "contributors": [person(5)]}
    return body


CHANGES = {
    "hf_takedowns/index": takedown_log,
    "zenodo/deleted": zenodo_tombstone,
    "zenodo/record-3242074": zenodo_record,
    "figshare/cc-by-4.0": figshare,
    "crossref/retracted": crossref,
    "datacite/findable": datacite,
}


@pytest.fixture
def checked(
    tmp_path: Path, derive_upstream: Callable[..., Path], capsys: pytest.CaptureFixture[str]
) -> Path:
    for name in CHANGES:
        assert (Path(__file__).parent.parent / "fixtures" / f"{name}.meta.json").exists(), name
    root = derive_upstream(changes=CHANGES, extra=figshare_extra())
    handlers = make_handlers(fetcher=RecordedFetcher(root))
    db = tmp_path / "db" / "md.db"
    path = manifest(tmp_path / "model")
    path.write_text(path.read_text("utf-8") + f'\n[[datasets]]\ndoi = "{DELETED}"\n', "utf-8")
    for argv in (("register", str(path)), ("check", "--all", "--scheduled")):
        code = main([*argv, "--db", str(db), "--json"], handlers=handlers)
        out = capsys.readouterr().out
        assert code == EXIT_OK, out
    # The derived states did carry the canaries.
    assert CANARY in (root / "crossref" / "retracted.json").read_text("utf-8")
    return db


def test_no_canary_reaches_the_database_or_the_evidence_store(checked: Path) -> None:
    files = [path for path in checked.parent.rglob("*") if path.is_file()]
    assert len(files) > 1, "the evidence store holds the stored bodies"
    found = [str(path) for path in files if CANARY.encode() in path.read_bytes()]
    assert found == []


def test_the_evidence_lists_what_was_removed(checked: Path) -> None:
    with Store(checked) as store:
        rows = store.conn.execute("SELECT source, url, body_sha256, redacted_fields FROM evidence")
        removed: dict[str, set[str]] = {}
        log_bodies: list[bytes] = []
        for source, _url, digest, fields in rows.fetchall():
            removed.setdefault(source, set()).update(json.loads(fields))
            if source == "hf-takedowns":
                log_bodies.append(store.read_body(digest))
    assert removed["hf-takedowns"] == {"file", "requesting_entity"}
    assert {"removed_by", "note", "citation_text"} <= removed["zenodo"]
    assert {"metadata.creators", "metadata.contributors", "owners"} <= removed["zenodo"]
    assert {"authors", "citation"} <= removed["figshare"]
    assert {"author", "reference[].unstructured"} <= removed["crossref"]
    assert {"creators", "contributors"} <= removed["datacite"]
    assert log_bodies
    for body in log_bodies:
        assert body.decode("utf-8").splitlines()[0] == "date,reported_content"

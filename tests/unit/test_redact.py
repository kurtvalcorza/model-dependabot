"""Redaction of personal data before storage (research U10, tasks T004)."""

from __future__ import annotations

import csv
import hashlib
import io
import json
from pathlib import Path

import pytest

from model_dependabot.redact import RULES, redact, source_for_url


def _sha(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


TAKEDOWN_CSV = (
    b"date,requesting_entity,reported_content,file\n"
    b"2026-09-04,A Person,https://huggingface.co/datasets/owner/name,2026/2026-09-04-notice.md\n"
    b"2025-01-02,Some Firm,Multiple,2025/2025-01-02-notice.md\n"
)


def test_takedown_log_drops_the_requesting_entity_and_file_columns() -> None:
    # Owner ruling: ``file`` can name the requesting party too, so only date and content remain.
    result = redact("hf-takedowns", TAKEDOWN_CSV)
    rows = list(csv.DictReader(io.StringIO(result.body.decode("utf-8"))))
    assert list(rows[0]) == ["date", "reported_content"]
    assert rows[0]["reported_content"] == "https://huggingface.co/datasets/owner/name"
    assert rows[1] == {"date": "2025-01-02", "reported_content": "Multiple"}
    assert b"A Person" not in result.body and b"Some Firm" not in result.body
    assert b"notice.md" not in result.body
    assert result.redacted_fields == ("file", "requesting_entity")
    assert result.original_sha256 == _sha(TAKEDOWN_CSV)
    assert result.body_sha256 == _sha(result.body) != result.original_sha256


def test_takedown_log_already_without_requesting_entity_still_drops_file() -> None:
    body = b"date,reported_content,file\n2022-06-28,o/n,2022/2022-06-28-Name.md\n"
    result = redact("hf-takedowns", body)
    assert result.body == b"date,reported_content\n2022-06-28,o/n\n"
    assert result.redacted_fields == ("file",)


def test_zenodo_tombstone_drops_removed_by_note_and_citation_text() -> None:
    tombstone = {
        "removal_date": "2024-01-01",
        "removal_reason": {"id": "spam"},
        "removed_by": {"user": 12345},
        "note": "removed at the request of A Person",
        "citation_text": "Person, A. (2020). Title. Zenodo.",
        "is_visible": True,
    }
    body = json.dumps({"status": 410, "message": "Record deleted", "tombstone": tombstone}).encode()
    result = redact("zenodo", body)
    stored = json.loads(result.body)
    assert stored["tombstone"] == {
        "removal_date": "2024-01-01",
        "removal_reason": {"id": "spam"},
        "is_visible": True,
    }
    assert stored["status"] == 410
    assert result.redacted_fields == ("citation_text", "note", "removed_by")
    assert result.original_sha256 == _sha(body) != result.body_sha256


def test_zenodo_record_drops_creators_contributors_and_owners() -> None:
    record = {
        "id": 3242074,
        "metadata": {
            "title": "t",
            "creators": [{"name": "Person, A."}],
            "contributors": [{"name": "Person, B."}],
            "license": {"id": "cc-by-4.0"},
        },
        "owners": [{"id": 1}],
        "links": {"latest": "https://zenodo.org/api/records/3242074"},
    }
    body = json.dumps(record).encode()
    result = redact("zenodo", body)
    stored = json.loads(result.body)
    assert stored == {
        "id": 3242074,
        "metadata": {"title": "t", "license": {"id": "cc-by-4.0"}},
        "links": {"latest": "https://zenodo.org/api/records/3242074"},
    }
    assert result.redacted_fields == ("metadata.contributors", "metadata.creators", "owners")
    assert result.original_sha256 == _sha(body) != result.body_sha256


def test_zenodo_tombstone_and_record_fields_are_removed_together() -> None:
    body = json.dumps(
        {"metadata": {"creators": []}, "owners": [], "tombstone": {"note": "n", "is_visible": 1}}
    ).encode()
    result = redact("zenodo", body)
    assert json.loads(result.body) == {"metadata": {}, "tombstone": {"is_visible": 1}}
    assert result.redacted_fields == ("metadata.creators", "note", "owners")


def test_figshare_article_drops_authors_and_citation() -> None:
    article = {
        "id": 1,
        "title": "t",
        "authors": [{"id": 9, "full_name": "A Person"}],
        "citation": "Person, A. (2020). t. figshare.",
        "license": {"value": 1, "name": "CC BY 4.0"},
    }
    body = json.dumps(article).encode()
    result = redact("figshare", body)
    assert json.loads(result.body) == {
        "id": 1,
        "title": "t",
        "license": {"value": 1, "name": "CC BY 4.0"},
    }
    assert result.redacted_fields == ("authors", "citation")
    assert result.original_sha256 == _sha(body) != result.body_sha256


def test_crossref_references_drop_unstructured_text_and_keep_the_rest() -> None:
    record = {
        "message": {
            "DOI": "10.1/x",
            "reference": [
                {"key": "r1", "DOI": "10.1/y", "unstructured": "Person, A. Title. 2001."},
                {"key": "r2", "author": "Person", "year": "2002", "unstructured": "Person. 2002."},
                {"key": "r3", "journal-title": "J"},
            ],
        }
    }
    body = json.dumps(record).encode()
    result = redact("crossref", body)
    assert json.loads(result.body)["message"]["reference"] == [
        {"key": "r1", "DOI": "10.1/y"},
        {"key": "r2", "year": "2002"},
        {"key": "r3", "journal-title": "J"},
    ]
    assert result.redacted_fields == ("author", "reference[].unstructured")
    assert b"Person" not in result.body


def test_unstructured_outside_crossref_references_is_kept() -> None:
    body = json.dumps({"message": {"DOI": "10.1/x", "unstructured": "kept"}}).encode()
    assert redact("crossref", body).body == body


@pytest.mark.parametrize("source", ["crossref", "datacite"])
def test_scholarly_records_drop_author_creators_contributors_and_editor(source: str) -> None:
    record = {
        "message": {
            "DOI": "10.1/x",
            "author": [{"given": "A", "family": "Person"}],
            "editor": [{"given": "B", "family": "Editor"}],
            "updated-by": [{"type": "retraction", "DOI": "10.1/notice"}],
            "reference": [{"key": "r1", "author": "Person"}],
        },
        "data": {"attributes": {"creators": [{"name": "C"}], "contributors": [{"name": "D"}]}},
    }
    body = json.dumps(record).encode()
    result = redact(source, body)
    stored = json.loads(result.body)
    assert stored["message"] == {
        "DOI": "10.1/x",
        "updated-by": [{"type": "retraction", "DOI": "10.1/notice"}],
        "reference": [{"key": "r1"}],
    }
    assert stored["data"] == {"attributes": {}}
    assert result.redacted_fields == ("author", "contributors", "creators", "editor")
    assert result.original_sha256 == _sha(body)
    assert result.body_sha256 == _sha(result.body)


@pytest.mark.parametrize(
    ("source", "body"),
    [
        ("hf-hub", json.dumps({"id": "o/n", "author": "o", "disabled": True}).encode()),
        ("crossref", json.dumps({"message": {"DOI": "10.1/x"}}).encode()),
        ("zenodo", json.dumps({"id": 1, "metadata": {"title": "t"}}).encode()),
        ("osv", b'{"id": "GHSA-x"}'),
        (None, b"not json at all"),
    ],
)
def test_nothing_to_remove_keeps_the_body_and_equal_hashes(source: str | None, body: bytes) -> None:
    result = redact(source, body)
    assert result.body == body
    assert result.original_sha256 == result.body_sha256 == _sha(body)
    assert result.redacted_fields == ()


def test_hugging_face_info_has_no_rule() -> None:
    assert RULES["hf-hub"] == ()
    body = json.dumps({"author": "namespace", "cardData": {"license": "mit"}}).encode()
    assert redact("hf-hub", body).body == body


def test_a_redacted_body_is_stable_when_redacted_again() -> None:
    first = redact("hf-takedowns", TAKEDOWN_CSV)
    second = redact("hf-takedowns", first.body)
    assert second.body == first.body
    assert second.redacted_fields == ()


@pytest.mark.parametrize(
    ("url", "source"),
    [
        ("https://api.crossref.org/works/10.1/x", "crossref"),
        ("https://api.datacite.org/dois/10.5281/zenodo.1", "datacite"),
        ("https://zenodo.org/api/records/3242074", "zenodo"),
        ("https://api.figshare.com/v2/articles/1", "figshare"),
        ("https://doi.org/doiRA/10.1/x", "doi-ra"),
        (
            "https://huggingface.co/datasets/huggingface-legal/takedown-notices/resolve/main/index.csv",
            "hf-takedowns",
        ),
        (
            "https://huggingface.co/api/resolve-cache/datasets/huggingface-legal/takedown-notices/"
            "ab924c52c724af95331ee579af0cb12afacdebad/index.csv?etag=x",
            "hf-takedowns",
        ),
        ("https://huggingface.co/api/datasets/yavon/muxue?expand[]=disabled", "hf-hub"),
        ("https://api.osv.dev/v1/querybatch", None),
    ],
)
def test_source_for_url(url: str, source: str | None) -> None:
    assert source_for_url(url) == source


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
FIXTURE_SOURCES = {
    "crossref": "crossref",
    "datacite": "datacite",
    "zenodo": "zenodo",
    "figshare": "figshare",
    "doi_ra": "doi-ra",
    "hf_upstream": "hf-hub",
    "hf_takedowns": "hf-takedowns",
}


def _fixture_metas() -> list[Path]:
    return sorted(p for folder in FIXTURE_SOURCES for p in (FIXTURES / folder).glob("*.meta.json"))


@pytest.mark.parametrize("meta_path", _fixture_metas(), ids=lambda p: f"{p.parent.name}/{p.name}")
def test_every_upstream_fixture_is_already_redacted_by_the_runtime_rule(meta_path: Path) -> None:
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    body = (meta_path.parent / meta["body_file"]).read_bytes()
    again = redact(FIXTURE_SOURCES[meta_path.parent.name], body)
    assert again.body == body, f"the runtime rule would still remove {again.redacted_fields}"
    assert meta["body_sha256"] == _sha(body)
    assert "trimmed" not in meta
    if meta["redacted_fields"]:
        assert meta["original_sha256"] != meta["body_sha256"]


def test_the_takedown_fixture_keeps_only_date_and_reported_content() -> None:
    meta = json.loads((FIXTURES / "hf_takedowns" / "index.meta.json").read_text("utf-8"))
    body = (FIXTURES / "hf_takedowns" / "index.csv").read_bytes()
    header = next(csv.reader(io.StringIO(body.decode("utf-8"))))
    assert header == ["date", "reported_content"]
    assert meta["redacted_fields"] == ["file", "requesting_entity"]
    assert meta["original_sha256"] == (
        "d5f772c05c28cb53554d76276143889c500f7036b3b697f377e5f35274f52b83"
    )

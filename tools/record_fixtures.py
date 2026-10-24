"""Record live source responses into ``tests/fixtures`` (run by hand, never by the tests).

Usage::

    uv run python tools/record_fixtures.py hf
    uv run python tools/record_fixtures.py osv
    uv run python tools/record_fixtures.py hf-scan
    uv run python tools/record_fixtures.py upstream

Requests are anonymous and carry only the generic User-Agent of ``UrlFetcher``; no token is sent.
Each response is written in ``RecordedFetcher``'s format: ``NAME.meta.json`` beside the body file.
Large lists the tests do not need are trimmed, and each trim is recorded in the meta file
(``trimmed``) and in the directory's ``NOTES.md``.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import sys
import urllib.request
import zlib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from model_dependabot.redact import redact
from model_dependabot.sources.fetcher import DEFAULT_USER_AGENT, Response, UrlFetcher
from model_dependabot.store import utc_text

ROOT = Path(__file__).resolve().parent.parent
HF_API = "https://huggingface.co/api/models"
HF_REPO = "openai-community/gpt2"
HF_MISSING_REPO = "model-dependabot-fixture/does-not-exist"
KEPT_HEADERS = ("content-type", "x-repo-commit", "etag")
# The hub's security status (research R5): a public test repository whose files carry real
# ``unsafe`` verdicts, and gpt2 for a real clean answer.
HF_SCAN_UNSAFE_REPO = "mcpotato/42-eicar-street"

OSV_API = "https://api.osv.dev/v1"
# Each batch is one recording, matched by its request body. pillow 12.3.0 is affected and 13.0.0 is
# the fixed version (checked live on 2026-10-24); validators 0.12.2 is in the range of the withdrawn
# advisory PYSEC-2019-64, found by listing the ``withdrawn`` records in OSV's PyPI export.
# OSV leaves withdrawn records out of query answers, so PYSEC-2019-64 is recorded by id only.
OSV_BATCHES: dict[str, list[tuple[str, str]]] = {
    "querybatch-vulnerable": [("pillow", "12.3.0"), ("validators", "0.12.2")],
    "querybatch-pillow-13.0.0": [("pillow", "13.0.0")],
}
# pillow 12.3.0 has 41 advisories and validators 0.12.2 has 2; the batch answers keep only the
# records named here (two small pillow records with a qualitative severity and different CVSS
# versions), and the trim is recorded.
OSV_KEPT = ("GHSA-cp9v-662q-vvx9", "GHSA-24rc-8hj2-v98c", "PYSEC-2019-64")


def _write(
    out: Path,
    name: str,
    response: Response,
    body: bytes,
    trimmed: str | None,
    *,
    method: str = "GET",
    request_body: Any = None,
) -> None:
    out.mkdir(parents=True, exist_ok=True)
    body_file = f"{name}.json"
    (out / body_file).write_bytes(body)
    meta: dict[str, Any] = {"method": method, "url": response.url}
    if request_body is not None:
        meta["request_body"] = request_body
    meta |= {
        "status": response.status,
        "headers": {k: response.headers[k] for k in KEPT_HEADERS if k in response.headers},
        "retrieved_at": utc_text(response.retrieved_at),
        "body_file": body_file,
    }
    if trimmed:
        meta["trimmed"] = trimmed
    text = json.dumps(meta, indent=2) + "\n"
    (out / f"{name}.meta.json").write_bytes(text.encode("utf-8"))
    note = f" ({trimmed})" if trimmed else ""
    print(f"{name}: HTTP {response.status}, {len(body)} bytes{note}")


def _trim_model_info(body: bytes) -> tuple[bytes, str | None]:
    info = json.loads(body)
    notes = []
    for key in ("spaces", "widgetData", "cardData", "transformersInfo"):
        if key in info:
            notes.append(f"removed '{key}'")
            del info[key]
    text = json.dumps(info, indent=1, sort_keys=True) + "\n"
    return text.encode("utf-8"), "; ".join(notes) or None


def record_hf() -> None:
    out = ROOT / "tests" / "fixtures" / "hf"
    fetcher = UrlFetcher()
    head = fetcher.get(f"{HF_API}/{HF_REPO}")
    commit = json.loads(head.body)["sha"]
    print(f"{HF_REPO} is at {commit}")

    info = fetcher.get(f"{HF_API}/{HF_REPO}/revision/{commit}")
    body, trimmed = _trim_model_info(info.body)
    _write(out, "gpt2-model-info", info, body, trimmed)

    tree = fetcher.get(f"{HF_API}/{HF_REPO}/tree/{commit}")
    _write(out, "gpt2-tree", tree, tree.body, None)

    missing = fetcher.get(f"{HF_API}/{HF_MISSING_REPO}/tree/{commit}")
    _write(out, "missing-repo-tree", missing, missing.body, None)


def _trim_batch(body: bytes) -> tuple[bytes, str | None]:
    answer = json.loads(body)
    dropped = 0
    for result in answer.get("results", []):
        vulns = result.get("vulns")
        if vulns is None:
            continue
        kept = [vuln for vuln in vulns if vuln["id"] in OSV_KEPT]
        dropped += len(vulns) - len(kept)
        result["vulns"] = kept
    if not dropped:
        return body, None
    text = json.dumps(answer, separators=(",", ":")) + "\n"
    return text.encode("utf-8"), f"kept {', '.join(OSV_KEPT)}; removed {dropped} other vulns"


def record_osv() -> None:
    out = ROOT / "tests" / "fixtures" / "osv"
    fetcher = UrlFetcher()
    for name, packages in OSV_BATCHES.items():
        query = {
            "queries": [
                {"package": {"name": package, "ecosystem": "PyPI"}, "version": version}
                for package, version in packages
            ]
        }
        payload = json.dumps(query, separators=(",", ":")).encode("utf-8")
        response = fetcher.post(f"{OSV_API}/querybatch", payload)
        body, trimmed = _trim_batch(response.body)
        _write(out, name, response, body, trimmed, method="POST", request_body=query)
    for advisory_id in OSV_KEPT:
        response = fetcher.get(f"{OSV_API}/vulns/{advisory_id}")
        _write(out, f"vuln-{advisory_id}", response, response.body, None)


def record_hf_scan() -> None:
    out = ROOT / "tests" / "fixtures" / "hf"
    fetcher = UrlFetcher()
    for name, repo in (("eicar-security", HF_SCAN_UNSAFE_REPO), ("gpt2-security", HF_REPO)):
        status = fetcher.get(f"{HF_API}/{repo}?securityStatus=true")
        _write(out, name, status, status.body, None)
        if repo == HF_SCAN_UNSAFE_REPO:
            commit = json.loads(status.body)["sha"]
            tree = fetcher.get(f"{HF_API}/{repo}/tree/{commit}?expand=true")
            _write(out, "eicar-tree-expand", tree, tree.body, None)


# --- feature 002: upstream sources (tasks T019) ---------------------------------------------------
#
# Every response passes through ``UrlFetcher``, which applies the source's redaction rule (research
# U10) before the body is returned; the writer applies the rule again under the intended source name
# (idempotent), so a body reached through a redirect to another host is redacted too. Every field
# that can name a person is removed by a U10 rule, so nothing is trimmed by hand. Calls that must
# see a move (hub model and dataset info, the takedown log, Zenodo ``links.latest``) pass
# ``follow_redirects=False``; the others follow redirects as feature 001 does. Identifiers
# found by search at recording time are written to each folder's ``NOTES.md`` with the query that
# found them.

UPSTREAM_HEADERS = (
    "content-type",
    "etag",
    "location",
    "x-repo-commit",
    "x-rate-limit-limit",
    "x-rate-limit-interval",
    "x-concurrency-limit",
)
CROSSREF = "https://api.crossref.org"
DATACITE = "https://api.datacite.org"
ZENODO = "https://zenodo.org/api"
FIGSHARE = "https://api.figshare.com/v2"
HF = "https://huggingface.co"
MODEL_EXPAND = (
    "?expand[]=disabled&expand[]=gated&expand[]=private&expand[]=cardData&expand[]=sha"
    "&expand[]=lastModified"
)
DATASET_EXPAND = "?expand[]=disabled&expand[]=gated&expand[]=private&expand[]=cardData&expand[]=sha"
TAKEDOWN_INDEX = f"{HF}/datasets/huggingface-legal/takedown-notices/resolve/main/index.csv"
RETRACTED_DOI = "10.1177/1758835919874651"
ZENODO_DOI = "10.5281/zenodo.3242074"
UNRETRACTED_DOI = "10.1038/nature14539"
MISSING_SUFFIX = "model-dependabot-fixture-does-not-exist"
GATED_MODEL = "meta-llama/Llama-3.1-8B"
NORMAL_MODEL = "openai-community/gpt2"
MISSING_REPO = "model-dependabot-fixture/does-not-exist"
DISABLED_DATASET = "yavon/muxue"
MOVED_DATASET = "the_pile_books3"
NOTES: dict[str, list[str]] = {}


def _note(folder: str, line: str) -> None:
    NOTES.setdefault(folder, []).append(line)
    print(f"  note [{folder}]: {line}")


def _write_upstream(folder: str, name: str, response: Response, source: str) -> Response:
    out = ROOT / "tests" / "fixtures" / folder
    out.mkdir(parents=True, exist_ok=True)
    again = redact(source, response.body)
    body = again.body
    fields = sorted(set(response.redacted_fields) | set(again.redacted_fields))
    is_csv = "csv" in str(response.headers.get("content-type", "")) or urlsplit(
        response.url
    ).path.endswith(".csv")
    body_file = f"{name}.csv" if is_csv else f"{name}.json"
    (out / body_file).write_bytes(body)
    meta: dict[str, Any] = {"method": "GET", "url": response.url, "status": response.status}
    meta["headers"] = {k: response.headers[k] for k in UPSTREAM_HEADERS if k in response.headers}
    if response.redirected_to:
        meta["redirected_to"] = response.redirected_to
    meta |= {
        "retrieved_at": utc_text(response.retrieved_at),
        "body_file": body_file,
        "original_sha256": response.original_sha256,
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "redacted_fields": fields,
    }
    (out / f"{name}.meta.json").write_bytes((json.dumps(meta, indent=2) + "\n").encode("utf-8"))
    print(f"{folder}/{name}: HTTP {response.status}, {len(body)} bytes, redacted {fields}")
    return response


def _json(response: Response) -> Any:
    try:
        return json.loads(response.body)
    except ValueError:
        return None


def _crossref_updated_by(fetcher: UrlFetcher, update_type: str) -> tuple[str, Response] | None:
    """A work whose ``updated-by`` lists ``update_type``, found through its notices."""
    search = f"{CROSSREF}/works?filter=update-type:{update_type}&rows=10"
    items = (_json(fetcher.get(search)) or {}).get("message", {}).get("items", [])
    for notice in items:
        for target in notice.get("update-to") or []:
            doi = str(target.get("DOI", "")).lower()
            if not doi:
                continue
            work = fetcher.get(f"{CROSSREF}/works/{doi}")
            message = (_json(work) or {}).get("message", {})
            types = {entry.get("type") for entry in message.get("updated-by") or []}
            if (
                work.status == 200
                and update_type in types
                and not types
                & {
                    "retraction",
                    "withdrawal",
                    "removal",
                }
            ):
                return doi, work
    return None


def record_crossref(fetcher: UrlFetcher) -> None:
    folder = "crossref"
    response = fetcher.get(f"{CROSSREF}/works/{RETRACTED_DOI}")
    _write_upstream(folder, "retracted", response, "crossref")
    _note(folder, f"retracted: {RETRACTED_DOI} (named in tasks T019 and research U2)")
    response = fetcher.get(f"{CROSSREF}/works/{UNRETRACTED_DOI}")
    updates = (_json(response) or {}).get("message", {}).get("updated-by")
    _write_upstream(folder, "unretracted", response, "crossref")
    _note(folder, f"unretracted: {UNRETRACTED_DOI} (chosen by hand; updated-by: {updates!r})")
    for update_type, name in (("correction", "correction"), ("expression_of_concern", "concern")):
        found = _crossref_updated_by(fetcher, update_type)
        if found is None:
            _note(folder, f"{name}: none found with filter=update-type:{update_type}&rows=10")
            continue
        doi, work = found
        _write_upstream(folder, name, work, "crossref")
        _note(
            folder,
            f"{name}: {doi}, found as the target (`update-to`) of a notice listed by"
            f" `works?filter=update-type:{update_type}&rows=10`; its `updated-by` lists"
            f" {update_type} and no retraction, withdrawal or removal",
        )
    response = fetcher.get(f"{CROSSREF}/works/10.1177/{MISSING_SUFFIX}")
    _write_upstream(folder, "not-found", response, "crossref")
    _note(folder, f"not-found: 10.1177/{MISSING_SUFFIX} (made up)")


def _datacite_relation(fetcher: UrlFetcher, relation: str) -> tuple[str, Response] | None:
    query = f"relatedIdentifiers.relationType:{relation}"
    search = f"{DATACITE}/dois?query={query}&resource-type-id=dataset&page%5Bsize%5D=5"
    for item in (_json(fetcher.get(search)) or {}).get("data", []):
        doi = str(item.get("id", "")).lower()
        record = fetcher.get(f"{DATACITE}/dois/{doi}")
        attributes = (_json(record) or {}).get("data", {}).get("attributes", {})
        relations = {r.get("relationType") for r in attributes.get("relatedIdentifiers") or []}
        if record.status == 200 and relation in relations:
            return doi, record
    return None


def record_datacite(fetcher: UrlFetcher) -> None:
    folder = "datacite"
    response = fetcher.get(f"{DATACITE}/dois/{ZENODO_DOI}")
    _write_upstream(folder, "findable", response, "datacite")
    _note(folder, f"findable: {ZENODO_DOI} (named in tasks T015 and research U1)")
    response = fetcher.get(f"{DATACITE}/dois/10.5281/{MISSING_SUFFIX}")
    _write_upstream(folder, "not-found", response, "datacite")
    _note(folder, f"not-found: 10.5281/{MISSING_SUFFIX} (made up)")
    for relation, name in (
        ("IsObsoletedBy", "obsoleted"),
        ("IsPreviousVersionOf", "previous-version"),
        ("HasVersion", "has-version"),
    ):
        found = _datacite_relation(fetcher, relation)
        if found is None:
            _note(
                folder, f"{name}: none found with query relatedIdentifiers.relationType:{relation}"
            )
            continue
        doi, record = found
        _write_upstream(folder, name, record, "datacite")
        _note(
            folder,
            f"{name}: {doi}, the first dataset returned by `dois?query=relatedIdentifiers."
            f"relationType:{relation}&resource-type-id=dataset` whose record lists {relation}",
        )
        if name == "previous-version":
            break  # IsPreviousVersionOf found; HasVersion is the alternative T019 allows


def _deleted_zenodo_id(fetcher: UrlFetcher) -> tuple[str, str] | None:
    """The first record id in Zenodo's deleted-records dump, read from its first 64 KiB only.

    The dump's ``removal_note`` and ``citation_text`` can name people; they are read in memory to
    find an id and never written.
    """
    exporter = _json(fetcher.get(f"{ZENODO}/exporter")) or {}
    url = None
    for value in json.dumps(exporter).split('"'):
        if value.startswith("http") and "records-deleted" in value:
            url = value
            break
    if url is None:
        return None
    request = urllib.request.Request(
        url, headers={"User-Agent": DEFAULT_USER_AGENT, "Range": "bytes=0-65535"}, method="GET"
    )
    with urllib.request.urlopen(request, timeout=60) as raw:
        chunk = raw.read()
    text = zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(chunk).decode("utf-8", "replace")
    lines = text.splitlines()
    header = next(csv.reader([lines[0]]))
    column = header.index("record_id")
    for row in csv.reader(lines[1:-1]):
        if len(row) > column and row[column].isdigit():
            return row[column], url
    return None


def record_zenodo(fetcher: UrlFetcher) -> None:
    folder = "zenodo"
    response = fetcher.get(f"{ZENODO}/records/3242074")
    _write_upstream(folder, "record-3242074", response, "zenodo")
    _note(folder, "record-3242074: Zenodo record 3242074 (named in tasks T019)")
    search = f"{ZENODO}/records?q=resource_type.type:dataset&all_versions=true&size=25&sort=oldest"
    hits = ((_json(fetcher.get(search)) or {}).get("hits") or {}).get("hits", [])
    for hit in hits:
        if (hit.get("versions") or {}).get("is_latest") is False:
            record_id = str(hit["id"])
            record = fetcher.get(f"{ZENODO}/records/{record_id}")
            _write_upstream(folder, "older-version", record, "zenodo")
            latest_url = ((_json(record) or {}).get("links") or {}).get("latest")
            if latest_url:
                latest = fetcher.get(latest_url, follow_redirects=False)
                _write_upstream(folder, "older-version-latest", latest, "zenodo")
            _note(
                folder,
                f"older-version: record {record_id}, the first hit of"
                " `records?q=resource_type.type:"
                "dataset&all_versions=true&size=25&sort=oldest` with `versions.is_latest: false`;"
                f" `links.latest` is {latest_url}",
            )
            break
    else:
        _note(folder, "older-version: none found in the first 25 hits of the search")
    found = _deleted_zenodo_id(fetcher)
    if found is None:
        _note(folder, "deleted: no record id found in the deleted-records dump")
        return
    record_id, dump = found
    response = fetcher.get(f"{ZENODO}/records/{record_id}")
    _write_upstream(folder, "deleted", response, "zenodo")
    _note(
        folder,
        f"deleted: record {record_id}, the first `record_id` in the first 64 KiB of {dump}"
        " (listed by `GET /api/exporter`); the dump itself was not stored",
    )


def record_figshare(fetcher: UrlFetcher) -> None:
    folder = "figshare"
    listing = _json(fetcher.get(f"{FIGSHARE}/articles?page_size=10")) or []
    public = cc_by = None
    for item in listing:
        article = fetcher.get(f"{FIGSHARE}/articles/{item['id']}")
        licence = ((_json(article) or {}).get("license") or {}).get("name")
        if licence == "CC BY 4.0" and cc_by is None:
            cc_by = (item["id"], article)
        elif public is None and licence != "CC BY 4.0":
            public = (item["id"], article, licence)
        if cc_by and public:
            break
    if public is None and cc_by is not None:
        public = (cc_by[0], cc_by[1], "CC BY 4.0")
    if public is not None:
        _write_upstream(folder, "public-article", public[1], "figshare")
        _note(
            folder,
            f"public-article: {public[0]}, from `articles?page_size=10` (licence {public[2]!r})",
        )
    if cc_by is not None:
        _write_upstream(folder, "cc-by-4.0", cc_by[1], "figshare")
        _note(
            folder,
            f"cc-by-4.0: {cc_by[0]}, the first of `articles?page_size=10` licensed CC BY 4.0",
        )
    else:
        _note(folder, "cc-by-4.0: none of the first 10 articles is licensed CC BY 4.0")
    response = fetcher.get(f"{FIGSHARE}/articles/1")
    _write_upstream(folder, "not-found", response, "figshare")
    _note(folder, f"not-found: article 1 (HTTP {response.status})")


def _takedown_models(csv_body: bytes) -> list[str]:
    models = []
    for row in csv.DictReader(io.StringIO(csv_body.decode("utf-8"))):
        content = (row.get("reported_content") or "").strip()
        path = content.split("huggingface.co/", 1)[-1].strip("/")
        parts = path.split("/")
        if len(parts) == 2 and parts[0] not in ("datasets", "spaces") and all(parts):
            models.append(path)
    return models


def record_hf_upstream(fetcher: UrlFetcher) -> None:
    folder = "hf_upstream"
    for name, repo in (
        ("model-normal", NORMAL_MODEL),
        ("model-gated", GATED_MODEL),
        ("model-missing", MISSING_REPO),
    ):
        _write_upstream(
            folder,
            name,
            fetcher.get(f"{HF}/api/models/{repo}{MODEL_EXPAND}", follow_redirects=False),
            "hf-hub",
        )
        _note(folder, f"{name}: {repo}")
    for name, repo in (
        ("dataset-disabled", DISABLED_DATASET),
        ("dataset-missing", MISSING_REPO),
        ("dataset-moved", MOVED_DATASET),
    ):
        response = fetcher.get(f"{HF}/api/datasets/{repo}{DATASET_EXPAND}", follow_redirects=False)
        _write_upstream(folder, name, response, "hf-hub")
        _note(folder, f"{name}: {repo} (HTTP {response.status})")
        if response.redirected_to:
            target = fetcher.get(response.redirected_to, follow_redirects=False)
            _write_upstream(folder, f"{name}-target", target, "hf-hub")
            _note(folder, f"{name}-target: {response.redirected_to} (HTTP {target.status})")


def record_hf_takedowns(fetcher: UrlFetcher) -> bytes:
    folder = "hf_takedowns"
    response = fetcher.get(TAKEDOWN_INDEX, follow_redirects=False)
    if response.redirected_to:
        _write_upstream(folder, "index-redirect", response, "hf-takedowns")
        _note(folder, f"index-redirect: {TAKEDOWN_INDEX} answers {response.status} to the target")
        response = fetcher.get(response.redirected_to, follow_redirects=False)
        _note(folder, f"index: the redirect target, recorded at its own URL {response.url}")
    _write_upstream(folder, "index", response, "hf-takedowns")
    body = redact("hf-takedowns", response.body).body
    rows = list(csv.DictReader(io.StringIO(body.decode("utf-8"))))
    _note(folder, f"index: {len(rows)} data rows; columns {list(rows[0]) if rows else []}")
    return body


def record_disabled_model(fetcher: UrlFetcher, takedown_csv: bytes) -> None:
    """Look for a disabled model among the takedown log's model paths (research U7)."""
    folder = "hf_upstream"
    candidates = _takedown_models(takedown_csv)
    _note(folder, f"disabled-model search: {len(candidates)} model-like paths in index.csv")
    statuses = []
    for repo in candidates[:8]:
        response = fetcher.get(f"{HF}/api/models/{repo}{MODEL_EXPAND}", follow_redirects=False)
        info = _json(response)
        disabled = info.get("disabled") if isinstance(info, dict) else None
        statuses.append(f"{repo}: HTTP {response.status}, disabled={disabled!r}")
        if response.status == 200 and disabled is True:
            _write_upstream(folder, "model-disabled", response, "hf-hub")
            _note(
                folder,
                f"model-disabled: {repo}, a model path from index.csv;"
                " answers 200 with disabled: true",
            )
            return
    _note(folder, "model-disabled: none found; tried " + "; ".join(statuses))


def record_doi_ra(fetcher: UrlFetcher) -> None:
    folder = "doi_ra"
    for name, doi in (("datacite", ZENODO_DOI), ("crossref", RETRACTED_DOI)):
        response = fetcher.get(f"https://doi.org/doiRA/{doi}")
        _write_upstream(folder, name, response, "doi-ra")
        _note(folder, f"{name}: doiRA for {doi} answered {response.body.decode('utf-8').strip()}")


def _write_notes() -> None:
    day = datetime.now(UTC).strftime("%Y-%m-%d")
    for folder, lines in NOTES.items():
        text = [
            f"# {folder} fixtures",
            "",
            f"Recorded {day} by `tools/record_fixtures.py upstream`",
        ]
        text += ["(anonymous, generic User-Agent, no token, redacted per research U10).", ""]
        text += [f"- {line}" for line in lines]
        (ROOT / "tests" / "fixtures" / folder / "NOTES.md").write_text(
            "\n".join(text) + "\n", encoding="utf-8"
        )


def record_upstream() -> None:
    fetcher = UrlFetcher()
    record_doi_ra(fetcher)
    record_crossref(fetcher)
    record_datacite(fetcher)
    record_zenodo(fetcher)
    record_figshare(fetcher)
    record_hf_upstream(fetcher)
    takedowns = record_hf_takedowns(fetcher)
    record_disabled_model(fetcher, takedowns)
    _write_notes()


RECORDERS = {
    "hf": record_hf,
    "osv": record_osv,
    "hf-scan": record_hf_scan,
    "upstream": record_upstream,
}


def main(argv: list[str]) -> int:
    if len(argv) != 1 or argv[0] not in RECORDERS:
        print(__doc__)
        return 1
    RECORDERS[argv[0]]()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

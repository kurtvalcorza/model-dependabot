"""Record live source responses into ``tests/fixtures`` (run by hand, never by the tests).

Usage::

    uv run python tools/record_fixtures.py hf
    uv run python tools/record_fixtures.py osv

Requests are anonymous and carry only the generic User-Agent of ``UrlFetcher``; no token is sent.
Each response is written in ``RecordedFetcher``'s format: ``NAME.meta.json`` beside the body file.
Large lists the tests do not need are trimmed, and each trim is recorded in the meta file
(``trimmed``) and in the directory's ``NOTES.md``.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from model_dependabot.sources.fetcher import Response, UrlFetcher
from model_dependabot.store import utc_text

ROOT = Path(__file__).resolve().parent.parent
HF_API = "https://huggingface.co/api/models"
HF_REPO = "openai-community/gpt2"
HF_MISSING_REPO = "model-dependabot-fixture/does-not-exist"
KEPT_HEADERS = ("content-type", "x-repo-commit", "etag")

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


RECORDERS = {"hf": record_hf, "osv": record_osv}


def main(argv: list[str]) -> int:
    if len(argv) != 1 or argv[0] not in RECORDERS:
        print(__doc__)
        return 1
    RECORDERS[argv[0]]()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

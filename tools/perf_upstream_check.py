"""Time one upstream check against recorded answers with real pacing (feature 002, T060; plan.md).

The model has a base model and ten datasets: four DOI datasets from the recordings (a Zenodo record
tied to a retracted paper, a deleted Zenodo record, a Figshare article and a DOI doi.org does not
know), the disabled hub dataset ``yavon/muxue`` and five hub datasets derived from its recording
under made-up names. Requests go through ``UrlFetcher`` with its per-host pacing and real sleeps;
only the opener is replaced, so it answers from the recordings and nothing touches the network.

    uv run python tools/perf_upstream_check.py

Prints one JSON object with the timings and the check's exit code. Budget: 60 seconds.
"""

from __future__ import annotations

import email.message
import io
import json
import shutil
import sys
import tempfile
import time
import urllib.error
from pathlib import Path
from typing import Any

from model_dependabot.cli import main, make_handlers
from model_dependabot.sources.datacite import doi_url
from model_dependabot.sources.doi_ra import doi_ra_url
from model_dependabot.sources.fetcher import UrlFetcher
from model_dependabot.sources.hf import dataset_info_url

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
DIRS = ("crossref", "datacite", "zenodo", "figshare", "doi_ra", "hf_upstream", "hf_takedowns")
GPT2_SHA = "607a30d783dfa663caf39e06633721c8d4cfcd7e"
MUXUE_SHA = "9408684b4d7410bf12651eff99ad6da74d746811"
FIGSHARE = "10.6084/m9.figshare.34763127.v1"
DERIVED_HUB = [f"perf-fixture/dataset-{n}" for n in range(1, 6)]
BUDGET_SECONDS = 60.0


def recordings(root: Path) -> dict[str, tuple[dict[str, Any], bytes]]:
    for name in DIRS:
        shutil.copytree(FIXTURES / name, root / name, ignore=shutil.ignore_patterns("*.md"))
    found: dict[str, tuple[dict[str, Any], bytes]] = {}
    for meta_path in root.rglob("*.meta.json"):
        meta = json.loads(meta_path.read_text("utf-8"))
        body = (meta_path.parent / meta["body_file"]).read_bytes() if "body_file" in meta else b""
        found[meta["url"]] = (meta, body)
    # Derived: five more hub datasets answering as the recorded disabled one does.
    meta, body = found[dataset_info_url("yavon/muxue")]
    for repo in DERIVED_HUB:
        document = json.loads(body) | {"id": repo}
        found[dataset_info_url(repo)] = (
            meta | {"url": dataset_info_url(repo)},
            json.dumps(document).encode(),
        )
    # Derived: the Figshare DOI's doi.org and DataCite answers, as in test_register_licences.py.
    ra = json.dumps([{"DOI": FIGSHARE, "RA": "DataCite"}]).encode()
    found[doi_ra_url(FIGSHARE)] = ({"status": 200, "headers": {}}, ra)
    record = json.loads((FIXTURES / "datacite" / "previous-version.json").read_bytes())
    record["data"]["attributes"]["doi"] = FIGSHARE
    record["data"]["attributes"]["url"] = (
        "https://figshare.com/articles/dataset/Data_Analysis/34763127"
    )
    found[doi_url(FIGSHARE)] = ({"status": 200, "headers": {}}, json.dumps(record).encode())
    return found


class Answer:
    def __init__(self, status: int, body: bytes, headers: email.message.Message) -> None:
        self.status, self._body, self.headers = status, body, headers

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> Answer:
        return self

    def __exit__(self, *_: object) -> None:
        return None


def opener(found: dict[str, tuple[dict[str, Any], bytes]], log: list[str]) -> Any:
    def open_recorded(request: Any, timeout: float) -> Answer:
        url = request.full_url
        log.append(url)
        if url not in found:
            raise urllib.error.URLError(f"no recording for {url}")
        meta, body = found[url]
        headers = email.message.Message()
        for key, value in (meta.get("headers") or {}).items():
            headers[key] = value
        status = int(meta.get("status", 599))
        if "error" in meta:
            raise urllib.error.URLError(meta["error"])
        if status >= 300:
            raise urllib.error.HTTPError(url, status, "recorded", headers, io.BytesIO(body))
        return Answer(status, body, headers)

    return open_recorded


def manifest(directory: Path) -> Path:
    datasets = [
        'doi = "10.5281/zenodo.3242074"\npaper_doi = ["10.1177/1758835919874651"]',
        'doi = "10.5281/zenodo.12584226"',
        f'doi = "{FIGSHARE}"',
        'doi = "10.5281/model-dependabot-fixture-does-not-exist"',
        f'hub = "hf:datasets/yavon/muxue"\nrevision = "{MUXUE_SHA}"',
        *[f'hub = "hf:datasets/{repo}"\nrevision = "{MUXUE_SHA}"' for repo in DERIVED_HUB],
    ]
    lines = ["[model]", 'id = "perf"', "", "[base_model]", 'hub = "hf:openai-community/gpt2"']
    lines.append(f'revision = "{GPT2_SHA}"')
    for item in datasets:
        lines += ["", "[[datasets]]", item]
    path = directory / "model.toml"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def run() -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as scratch:
        work = Path(scratch)
        found = recordings(work / "recordings")
        db = str(work / "md.db")
        path = manifest(work)
        log: list[str] = []
        timings: dict[str, float] = {}
        codes: dict[str, int] = {}
        registered = 0
        for step, argv in (
            ("register", ["register", str(path)]),
            ("check", ["check", "--all", "--scheduled"]),
        ):
            fetcher = UrlFetcher(
                opener=opener(found, log)
            )  # fresh: no in-memory cache across steps
            start = time.monotonic()
            buffer = io.StringIO()
            stdout, sys.stdout = sys.stdout, buffer
            try:
                codes[step] = main(
                    [*argv, "--db", db, "--json"], handlers=make_handlers(fetcher=fetcher)
                )
            finally:
                sys.stdout = stdout
            timings[step] = round(time.monotonic() - start, 2)
            if step == "check":
                checked = json.loads(buffer.getvalue())
                hosts: dict[str, int] = {}
                for url in log[registered:]:
                    host = url.split("/")[2]
                    hosts[host] = hosts.get(host, 0) + 1
            registered = len(log)
        return {
            "datasets": 10,
            "base_model": 1,
            "register_seconds": timings["register"],
            "check_seconds": timings["check"],
            "budget_seconds": BUDGET_SECONDS,
            "within_budget": timings["check"] <= BUDGET_SECONDS,
            "exit_codes": codes,
            "requests": len(log),
            "check_requests_by_host": hosts,
            "sources": checked["sources"],
        }


if __name__ == "__main__":
    result = run()
    print(json.dumps(result, indent=2))
    sys.exit(0 if result["within_budget"] and result["exit_codes"]["check"] == 0 else 1)

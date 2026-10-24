"""Record live source responses into ``tests/fixtures`` (run by hand, never by the tests).

Usage::

    uv run python tools/record_fixtures.py hf

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


def _write(out: Path, name: str, response: Response, body: bytes, trimmed: str | None) -> None:
    out.mkdir(parents=True, exist_ok=True)
    body_file = f"{name}.json"
    (out / body_file).write_bytes(body)
    meta: dict[str, Any] = {
        "method": "GET",
        "url": response.url,
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


def main(argv: list[str]) -> int:
    if argv != ["hf"]:
        print(__doc__)
        return 1
    record_hf()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

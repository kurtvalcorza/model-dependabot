"""The hub's public takedown log, ``huggingface-legal/takedown-notices`` ``index.csv`` (U5).

The log records notices received, not confirmed disablements, so a row alone never raises an
alert: a match only enriches a ``dataset_removed`` alert raised by the hub's ``disabled: true``,
with the row's ``date`` labelled a notice date (never a removal date) and its
``reported_content``. ``reported_content`` is a bare ``owner/name`` path with no type; a row matches
a hub dataset when, with surrounding spaces removed and compared without case, it equals the
dataset's ``owner/name``. Rows reading ``Multiple`` (in any spelling) never match. The
``requesting_entity`` and ``file`` columns are removed by the fetcher before the body is stored and
are skipped again when the log is read, so they never reach the store (FR-005, research U10). The
log is read at most once per check run, and only when a hub dataset is in scope.
"""

from __future__ import annotations

import csv
import io
from dataclasses import dataclass, field, replace

from model_dependabot.sources.fetcher import Fetcher, Response, SourceFailedError

SOURCE = "hf-takedowns"
INDEX_URL = (
    "https://huggingface.co/datasets/huggingface-legal/takedown-notices/resolve/main/index.csv"
)
NOTICE_LABEL = "notice date, not removal date"
KEPT_COLUMNS = ("date", "reported_content")
_MULTIPLE = "multiple"


def parse_index(body: bytes) -> list[dict[str, str]]:
    """The log's rows, keeping only ``date`` and ``reported_content``."""
    reader = csv.DictReader(io.StringIO(body.decode("utf-8-sig")))
    rows = []
    for row in reader:
        rows.append({name: (row.get(name) or "") for name in KEPT_COLUMNS})
    return rows


def matches(reported_content: str, repo: str) -> bool:
    """Whether a row's ``reported_content`` names the hub dataset ``owner/name`` (research U5)."""
    value = reported_content.strip().lower()
    if not value or value == _MULTIPLE:
        return False
    return value == repo.strip().lower()


@dataclass(frozen=True)
class TakedownLog:
    """The log as read in one run: the response (for evidence) and its kept rows."""

    response: Response
    notices: list[dict[str, str]] = field(default_factory=list)

    def find(self, repo: str) -> list[dict[str, str]]:
        """The notices naming ``repo``: only their notice date and reported content."""
        return [
            {"notice_date": row["date"], "reported_content": row["reported_content"]}
            for row in self.notices
            if matches(row["reported_content"], repo)
        ]


def evidence_detail(notice: dict[str, str]) -> dict[str, str]:
    return {
        "notice_date": notice["notice_date"],
        "reported_content": notice["reported_content"],
        "label": NOTICE_LABEL,
    }


class TakedownIndex:
    """Reads the log once; later calls in the same run reuse the answer."""

    def __init__(self, fetcher: Fetcher) -> None:
        self.fetcher = fetcher
        self._log: TakedownLog | None = None

    def read(self) -> TakedownLog:
        if self._log is None:
            response = self.fetcher.get(INDEX_URL)
            if response.status != 200:
                raise SourceFailedError(SOURCE, f"HTTP {response.status} for the takedown log")
            # Evidence points to the log by its URL; the redirect target is kept beside it.
            final = response.url
            response = replace(response, url=INDEX_URL, redirected_from=None)
            if final != INDEX_URL:
                response = replace(response, redirected_to=final)
            self._log = TakedownLog(response, parse_index(response.body))
        return self._log

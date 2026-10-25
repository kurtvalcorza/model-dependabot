"""Figshare: watch events only (FR-005, research U6).

The article id comes from the DataCite record's ``url``; ``GET
https://api.figshare.com/v2/articles/{id}`` answers 200 with the licence (``license.name``) or 404,
which Figshare shares between removed, private and nonexistent items. So no Figshare answer is a
removal: a 404 records a ``dataset_unreachable`` watch event, and an unpublished item can still
raise DataCite's "no longer findable" alert. ``authors`` and ``citation`` are removed by the
fetcher (research U10).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.parse import quote

from model_dependabot.sources.datacite import route
from model_dependabot.sources.fetcher import Fetcher, Response, SourceFailedError

SOURCE = "figshare"
ARTICLES_ENDPOINT = "https://api.figshare.com/v2/articles/"


def article_url(article_id: str) -> str:
    return ARTICLES_ENDPOINT + quote(str(article_id), safe="")


def article_id(url: str) -> str | None:
    """The Figshare article id in a DataCite landing URL, or ``None`` if it is not Figshare's."""
    repository, identifier = route(url)
    return identifier if repository == "figshare" else None


@dataclass(frozen=True)
class FigshareArticle:
    """What Figshare answered for one article."""

    article_id: str
    response: Response
    outcome: str
    licence: str | None = None

    @property
    def removal(self) -> None:
        """Figshare publishes no removal signal (research U6)."""
        return None

    def alert_kind(self) -> None:
        return None

    def not_found_kind(self) -> str | None:
        return "dataset_unreachable" if self.outcome == "not_found" else None


def parse_article(identifier: str, response: Response) -> FigshareArticle:
    if response.status == 404:
        return FigshareArticle(identifier, response, "not_found")
    if response.status != 200:
        raise SourceFailedError(SOURCE, f"HTTP {response.status} for article {identifier}")
    try:
        licence = (json.loads(response.body).get("license") or {}).get("name")
    except (ValueError, AttributeError):
        licence = None
    return FigshareArticle(identifier, response, "reachable", licence)


class Figshare:
    """Read-only access to ``/v2/articles/{id}``."""

    def __init__(self, fetcher: Fetcher) -> None:
        self.fetcher = fetcher

    def article(self, identifier: str) -> FigshareArticle:
        return parse_article(identifier, self.fetcher.get(article_url(identifier)))

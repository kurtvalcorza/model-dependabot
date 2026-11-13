"""Discovery's hub lookups, only with ``--upstream`` (research A11; FR-021, US4).

For each base model and each hub dataset the card names, the hub's model or dataset info is read
through the injected ``Fetcher`` (the CLI passes a ``UrlFetcher`` without an ETag cache: discovery
opens no database). A reachable answer gives a ``proposed_revision``, the repository's current
commit labelled as observed then, never as the training revision, and the declared licence with
its SPDX form. A refusal or a failure makes the candidate ``unavailable`` with the reason;
discovery still completes. Nothing else is looked up: no DOI, no URL from a file.
"""

from __future__ import annotations

from typing import Any

from model_dependabot.discover.candidate import UNAVAILABLE, utc_text
from model_dependabot.sources import hf
from model_dependabot.sources.fetcher import Fetcher, SourceFailedError
from model_dependabot.upstream.licences import normalise

LABEL = "head at observation time, not established as the training revision"
SOURCE = "hf-hub"


def _unavailable(item: dict[str, Any], reason: str) -> None:
    item["status"] = UNAVAILABLE
    item["gaps"].append(reason)


def _apply(item: dict[str, Any], answer: hf.HubModel | hf.HubDataset, what: str) -> None:
    response = answer.response
    retrieved = utc_text(response.retrieved_at)
    item["upstream"] = {
        "source": SOURCE,
        "url": response.url,
        "retrieved_at": retrieved,
        "status": response.status,
        "outcome": answer.outcome,
    }
    if answer.outcome == "refused":
        _unavailable(item, f"the hub refused the {what} lookup (HTTP {response.status})")
        return
    if answer.outcome == "redirected":
        moved = answer.moved_to or "an unnamed repository"
        _unavailable(item, f"the hub answers that the {what} moved to {moved}; not followed")
        return
    if answer.sha:
        item["proposed_revision"] = {
            "revision": answer.sha,
            "observed_at": retrieved,
            "label": LABEL,
        }
    if answer.licence:
        licence = normalise(answer.licence)
        item["upstream"]["licence"] = answer.licence
        item["upstream"]["spdx"] = licence.normalised if licence.recognised else None


def look_up(candidates: list[dict[str, Any]], fetcher: Fetcher) -> None:
    """Read the hub for the base models and hub datasets named in the project, in place."""
    for item in candidates:
        if item["status"] == UNAVAILABLE:
            continue
        repo = item["identity"].get("hub_repo")
        if item["kind"] == "base_model":
            read, what = hf.read_model, "model"
        elif item["kind"] == "dataset" and repo:
            read, what = hf.read_dataset, "dataset"
        else:
            continue
        try:
            answer = read(fetcher, repo)
        except SourceFailedError as error:
            _unavailable(item, f"the {what} lookup failed: {error.reason}")
            continue
        _apply(item, answer, what)

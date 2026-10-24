"""Hugging Face Hub: file hashes from the tree API and the revision a file is pinned to (R5).

A hub file's SHA-256 is the tree API's ``lfs.oid``; files outside LFS have only a git blob id,
which is not a SHA-256 of the content, so they cannot be pinned by hash. The revision is taken from
the ``X-Repo-Commit`` header when a response carries one, else from the model-info ``sha`` (the
tree and model-info API responses recorded on 2026-10-24 carried no ``X-Repo-Commit``; see
``tests/fixtures/hf/NOTES.md``). Anything the hub will not answer, including a ``401`` for a
private or missing repository, is a gap, never an error. Requests are anonymous ``GET``s.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from posixpath import dirname
from urllib.parse import quote

from model_dependabot.sources.fetcher import Fetcher, Response, SourceFailedError

HF_ENDPOINT = "https://huggingface.co"
_REPO = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")

FILE_NOT_FOUND = "file not found at revision"
NO_HUB_SHA256 = "no SHA-256 from the hub"


def parse_hub(text: str) -> str:
    """The repository of an ``hf:owner/name`` reference."""
    if not text.startswith("hf:") or not _REPO.match(text[3:]):
        raise ValueError(f"expected a Hugging Face reference 'hf:owner/name', got {text!r}")
    return text[3:]


def is_commit(revision: str | None) -> bool:
    return revision is not None and bool(_COMMIT.match(revision))


def _path(text: str) -> str:
    return quote(text, safe="/")


def resolve_url(repo: str, revision: str, file: str, endpoint: str = HF_ENDPOINT) -> str:
    """The download URL of a file at a revision."""
    return f"{endpoint}/{_path(repo)}/resolve/{quote(revision, safe='')}/{_path(file)}"


@dataclass(frozen=True)
class HubFile:
    path: str
    size: int | None
    sha256: str | None
    git_oid: str | None


@dataclass(frozen=True)
class TreeResult:
    files: dict[str, HubFile] = field(default_factory=dict)
    gap_reason: str | None = None


@dataclass(frozen=True)
class RevisionResult:
    commit: str | None
    gap_reason: str | None = None


@dataclass(frozen=True)
class HubFileResult:
    commit: str | None
    file: HubFile | None
    gap_reason: str | None = None


def _refusal(response: Response) -> str | None:
    if response.status == 200:
        return None
    if response.status in (401, 403):
        return f"hub returned HTTP {response.status} (private or missing repository)"
    if response.status == 404:
        return "hub returned HTTP 404 (repository or revision not found)"
    return f"hub returned HTTP {response.status}"


class HuggingFace:
    """Read-only access to the parts of the hub API that pin a file."""

    def __init__(self, fetcher: Fetcher, endpoint: str = HF_ENDPOINT) -> None:
        self.fetcher = fetcher
        self.endpoint = endpoint

    def _get(self, url: str) -> tuple[Response | None, str | None]:
        try:
            response = self.fetcher.get(url)
        except SourceFailedError as error:
            return None, f"hub not reachable: {error.reason}"
        return response, _refusal(response)

    def tree(self, repo: str, revision: str, directory: str = "") -> TreeResult:
        """The files in one directory of a repository at a revision."""
        url = f"{self.endpoint}/api/models/{_path(repo)}/tree/{quote(revision, safe='')}"
        if directory:
            url += f"/{_path(directory)}"
        response, gap = self._get(url)
        if response is None or gap is not None:
            return TreeResult(gap_reason=gap)
        try:
            items = json.loads(response.body)
        except ValueError:
            return TreeResult(gap_reason="hub tree response is not JSON")
        files: dict[str, HubFile] = {}
        for item in items if isinstance(items, list) else []:
            if not isinstance(item, dict) or item.get("type") != "file" or "path" not in item:
                continue
            lfs = item.get("lfs") if isinstance(item.get("lfs"), dict) else {}
            oid = str(lfs.get("oid", "")).lower()
            size = lfs.get("size", item.get("size"))
            files[item["path"]] = HubFile(
                path=item["path"],
                size=size if isinstance(size, int) else None,
                sha256=oid if _SHA256.match(oid) else None,
                git_oid=item.get("oid"),
            )
        return TreeResult(files=files)

    def revision(self, repo: str, revision: str) -> RevisionResult:
        """The commit a revision names: ``X-Repo-Commit`` if sent, else the model-info ``sha``."""
        url = f"{self.endpoint}/api/models/{_path(repo)}/revision/{quote(revision, safe='')}"
        response, gap = self._get(url)
        if response is None or gap is not None:
            return RevisionResult(commit=None, gap_reason=gap)
        commit = response.headers.get("X-Repo-Commit")
        if commit is None:
            try:
                commit = json.loads(response.body).get("sha")
            except (ValueError, AttributeError):
                commit = None
        if not is_commit(commit):
            return RevisionResult(commit=None, gap_reason="hub gave no commit for the revision")
        return RevisionResult(commit=commit)

    def hub_file(self, repo: str, revision: str, file: str) -> HubFileResult:
        """A file's hash and size at a revision, and the commit that revision is."""
        tree = self.tree(repo, revision, dirname(file))
        if tree.gap_reason is not None:
            return HubFileResult(commit=None, file=None, gap_reason=tree.gap_reason)
        found = tree.files.get(file)
        if found is None:
            return HubFileResult(commit=None, file=None, gap_reason=FILE_NOT_FOUND)
        if found.sha256 is None:
            return HubFileResult(commit=None, file=found, gap_reason=NO_HUB_SHA256)
        pinned = self.revision(repo, revision)
        if pinned.gap_reason is not None:
            return HubFileResult(commit=None, file=found, gap_reason=pinned.gap_reason)
        return HubFileResult(commit=pinned.commit, file=found)

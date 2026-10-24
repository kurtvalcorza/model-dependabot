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


# --- security status (research R5; FR-012) -------------------------------------------------------
#
# ``GET /api/models/{repo}?securityStatus=true`` is undocumented. Its ``securityRepoStatus`` object
# (recorded on 2026-10-24, see ``tests/fixtures/hf/NOTES.md``) has ``scansDone`` and
# ``filesWithIssues``, a list of ``{"path", "level"}`` for the files at the model's ``sha``. The
# per-scanner results and each file's SHA-256 come from the tree at that commit with
# ``expand=true`` (``securityFileStatus`` and ``lfs.oid``). Anything not recognised fails safe: it
# becomes a watch event, never an alert.

UNSAFE = "unsafe"
CAUTION = "caution"
CLEAN = "clean"
PENDING = "pending"
MISSING = "missing"
UNRECOGNISED = "unrecognised"
LISTED_LEVELS = {"unsafe": UNSAFE, "caution": CAUTION, "safe": CLEAN}


@dataclass(frozen=True)
class SecurityStatus:
    """The hub's security status for one repository: ``answered``, ``pending`` or ``missing``."""

    repo: str
    response: Response
    state: str
    commit: str | None = None
    levels: dict[str, str] = field(default_factory=dict)
    reason: str | None = None


@dataclass(frozen=True)
class FileVerdict:
    """The hub's verdict for one file: ``unsafe``, ``caution``, ``clean``, ``pending``, ``missing``
    or ``unrecognised``, with the hub's SHA-256 of the file at the verdict's commit."""

    repo: str
    file: str
    state: str
    status: SecurityStatus
    level: str | None = None
    hub_sha256: str | None = None
    scanners: dict[str, str] = field(default_factory=dict)
    file_status: dict[str, object] | None = None
    tree_response: Response | None = None
    reason: str | None = None


def security_status_url(repo: str, endpoint: str = HF_ENDPOINT) -> str:
    return f"{endpoint}/api/models/{_path(repo)}?securityStatus=true"


def _parse_status(repo: str, response: Response) -> SecurityStatus:
    if response.status != 200:
        return SecurityStatus(repo, response, MISSING, reason=_refusal(response))
    try:
        info = json.loads(response.body)
    except ValueError:
        return SecurityStatus(repo, response, MISSING, reason="response is not JSON")
    status = info.get("securityRepoStatus") if isinstance(info, dict) else None
    if not isinstance(status, dict):
        return SecurityStatus(repo, response, MISSING, reason="no securityRepoStatus in response")
    commit = info.get("sha")
    commit = commit if is_commit(commit) else None
    if status.get("scansDone") is not True:
        return SecurityStatus(repo, response, PENDING, commit, reason="scans not done")
    issues = status.get("filesWithIssues")
    if not isinstance(issues, list) or commit is None:
        reason = "no commit in response" if commit is None else "filesWithIssues is not a list"
        return SecurityStatus(repo, response, UNRECOGNISED, commit, reason=reason)
    levels: dict[str, str] = {}
    for item in issues:
        if isinstance(item, dict) and isinstance(item.get("path"), str):
            levels[item["path"]] = str(item.get("level"))
    return SecurityStatus(repo, response, "answered", commit, levels)


def _scanners(file_status: dict[str, object]) -> dict[str, str]:
    found = {}
    for name, value in sorted(file_status.items()):
        if name.endswith("Scan") and isinstance(value, dict) and "status" in value:
            found[name] = str(value["status"])
    return found


class HubSecurity:
    """Read-only access to the hub's scan verdicts. A request that fails raises
    ``SourceFailedError`` so the check run records the source as failed (FR-016)."""

    def __init__(self, fetcher: Fetcher, endpoint: str = HF_ENDPOINT) -> None:
        self.fetcher = fetcher
        self.endpoint = endpoint
        self._trees: dict[tuple[str, str, str], Response] = {}

    def status(self, repo: str) -> SecurityStatus:
        return _parse_status(repo, self.fetcher.get(security_status_url(repo, self.endpoint)))

    def _tree(self, repo: str, commit: str, directory: str) -> Response:
        key = (repo, commit, directory)
        if key not in self._trees:
            url = f"{self.endpoint}/api/models/{_path(repo)}/tree/{quote(commit, safe='')}"
            if directory:
                url += f"/{_path(directory)}"
            self._trees[key] = self.fetcher.get(url + "?expand=true")
        return self._trees[key]

    def verdict(self, status: SecurityStatus, file: str) -> FileVerdict:
        """The verdict for one file; a listed file's hash and scanners come from the tree."""
        if status.state != "answered":
            return FileVerdict(status.repo, file, status.state, status, reason=status.reason)
        level = status.levels.get(file)
        if level is None:
            return FileVerdict(status.repo, file, CLEAN, status)
        state = LISTED_LEVELS.get(level)
        if state is None:
            return FileVerdict(
                status.repo, file, UNRECOGNISED, status, level, reason=f"level {level!r}"
            )
        if state == CLEAN:
            return FileVerdict(status.repo, file, CLEAN, status, level)
        assert status.commit is not None
        response = self._tree(status.repo, status.commit, dirname(file))
        sha256, file_status = None, None
        if response.status == 200:
            try:
                items = json.loads(response.body)
            except ValueError:
                items = []
            for item in items if isinstance(items, list) else []:
                if isinstance(item, dict) and item.get("path") == file:
                    lfs = item.get("lfs") if isinstance(item.get("lfs"), dict) else {}
                    oid = str(lfs.get("oid", "")).lower()
                    sha256 = oid if _SHA256.match(oid) else None
                    raw = item.get("securityFileStatus")
                    file_status = raw if isinstance(raw, dict) else None
        return FileVerdict(
            status.repo,
            file,
            state,
            status,
            level,
            hub_sha256=sha256,
            scanners=_scanners(file_status or {}),
            file_status=file_status,
            tree_response=response,
        )

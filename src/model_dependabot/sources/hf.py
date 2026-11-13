"""Hugging Face Hub: file hashes from the tree API and the revision a file is pinned to (R5).

A hub file's SHA-256 is the tree API's ``lfs.oid``; files outside LFS have only a git blob id,
which is not a SHA-256 of the content, so they cannot be pinned by hash. The revision is taken from
the ``X-Repo-Commit`` header when a response carries one, else from the model-info ``sha`` (the
tree and model-info API responses recorded on 2026-10-24 carried no ``X-Repo-Commit``; see
``tests/fixtures/hf/NOTES.md``). Anything the hub will not answer, including a ``401`` for a
private or missing repository, is a gap, never an error. Requests are anonymous ``GET``s.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import datetime
from posixpath import dirname
from typing import Any
from urllib.parse import quote, unquote, urlsplit

from model_dependabot.sources.fetcher import Fetcher, Response, SourceFailedError, source_of
from model_dependabot.upstream.licences import join_licences

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


# Feature 003, research A4 (published in contracts/cli.md): the first range of a header read, and
# the most a safetensors header may take with its 8-byte length.
HEADER_LEAD = 1 << 20
HEADER_LIMIT = 16 << 20


def tree_url(repo: str, revision: str, directory: str = "", endpoint: str = HF_ENDPOINT) -> str:
    """The tree API URL of one directory of a repository at a revision."""
    url = f"{endpoint}/api/models/{_path(repo)}/tree/{quote(revision, safe='')}"
    return f"{url}/{_path(directory)}" if directory else url


def _parse_tree(body: bytes) -> TreeResult:
    try:
        items = json.loads(body)
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


def _fail_on_server_error(response: Response) -> None:
    """A server error the fetcher handed back (a recorded one) fails the source, as live ones do."""
    if response.status >= 500:
        raise SourceFailedError(source_of(response.url), f"HTTP {response.status}")


def _total_size(response: Response) -> int | None:
    """The file's size: from ``Content-Range`` for a 206, ``Content-Length`` for a 200."""
    if response.status == 206:
        value = response.headers.get("Content-Range") or ""
        total = value.rpartition("/")[2]
    else:
        total = response.headers.get("Content-Length") or ""
    return int(total) if total.isdigit() else None


@dataclass(frozen=True)
class HeaderRead:
    """What a header read of one hub file found (feature 003, research A4).

    ``identity`` is ``confirmed`` when the tree lists the pinned hash, ``contradicted`` when it
    lists another and ``unreadable`` when it cannot say. ``format`` and ``can_run_code`` are the
    measured class when the header was read and classified; otherwise ``reason`` says why not.
    """

    repo: str
    commit: str
    file: str
    url: str
    tree_url: str
    identity: str = "unreadable"
    hub_sha256: str | None = None
    format: str | None = None
    can_run_code: bool | None = None
    reason: str | None = None
    status: int | None = None
    content_range: str | None = None
    total_size: int | None = None
    lead_sha256: str | None = None
    lead_length: int | None = None
    retrieved_at: datetime | None = None

    def summary(self) -> dict[str, Any]:
        """The evidence body: what was asked and seen, never the file's bytes."""
        return {
            "url": self.url,
            "tree_url": self.tree_url,
            "commit": self.commit,
            "file": self.file,
            "hub_sha256": self.hub_sha256,
            "status": self.status,
            "content_range": self.content_range,
            "total_size": self.total_size,
            "lead_sha256": self.lead_sha256,
            "lead_length": self.lead_length,
            "measured_format": self.format,
            "measured_can_run_code": self.can_run_code,
            "identity": self.identity,
            "reason": self.reason,
        }


def answered_for(repo: str, info: object) -> str | None:
    """Why an answer is for another repository, or ``None`` when it is for ``repo`` or names none.

    Model and dataset info, security status and revision answers name their repository in ``id``
    (model answers also in ``modelId``). The hub treats repository ids case-insensitively, so case
    is ignored. An answer naming another repository is unreadable for ``repo`` (data-model.md,
    Identity and clearance); one with no such field is read as before.
    """
    if not isinstance(info, dict):
        return None
    for name in ("id", "modelId"):
        if name not in info:
            continue
        value = info[name]
        if not isinstance(value, str) or value.lower() != repo.lower():
            return f"the answer is for {value!r}"
    return None


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

    def dataset(self, repo: str) -> HubDataset:
        """A hub dataset's info for the upstream watch (feature 002, research U5)."""
        return read_dataset(self.fetcher, repo, self.endpoint)

    def tree(self, repo: str, revision: str, directory: str = "") -> TreeResult:
        """The files in one directory of a repository at a revision."""
        response, gap = self._get(tree_url(repo, revision, directory, self.endpoint))
        if response is None or gap is not None:
            return TreeResult(gap_reason=gap)
        return _parse_tree(response.body)

    def read_header(
        self, repo: str, commit: str, file: str, expected_sha256: str, *, header: bool = True
    ) -> HeaderRead:
        """Confirm a pinned hub file's identity and read its format from a bounded header read.

        The tree at ``commit`` must list ``file`` with ``expected_sha256`` (64 hex digits, no
        prefix): a different hash contradicts the identity, and the header is then not read; a
        missing file, no hub SHA-256 or a refusal is ``unreadable``. With ``header``, the first
        ``HEADER_LEAD`` bytes are read by range at ``commit`` and classified with the rules for
        local files (``classify_lead``); a safetensors header longer than that is read with one
        more range of up to ``HEADER_LIMIT`` bytes, and a longer one is unreadable. A refusal
        (401, 403, 404) is a reason, never a failure; a network error, a server error after the
        fetcher's retries or an answer cut off mid-read raises ``SourceFailedError``
        (FR-002a, FR-002b, research A4). Nothing of the file but the lead is read, and only a
        summary of it is kept.
        """
        listing = tree_url(repo, commit, dirname(file), self.endpoint)
        url = resolve_url(repo, commit, file, self.endpoint)
        result = HeaderRead(repo=repo, commit=commit, file=file, url=url, tree_url=listing)
        tree = self.fetcher.get(listing)
        _fail_on_server_error(tree)
        if tree.status != 200:
            return replace(result, identity="unreadable", reason=_refusal(tree))
        found = _parse_tree(tree.body)
        hub_file = found.files.get(file)
        if found.gap_reason is not None or hub_file is None:
            return replace(result, identity="unreadable", reason=found.gap_reason or FILE_NOT_FOUND)
        if hub_file.sha256 is None:
            return replace(result, identity="unreadable", reason=NO_HUB_SHA256)
        result = replace(result, hub_sha256=hub_file.sha256, retrieved_at=tree.retrieved_at)
        if hub_file.sha256 != expected_sha256.lower():
            reason = f"the hub lists {hub_file.sha256}, the inventory pins {expected_sha256}"
            return replace(result, identity="contradicted", reason=reason)
        result = replace(result, identity="confirmed")
        return self._read_lead(result, file) if header else result

    def _read_lead(self, result: HeaderRead, file: str) -> HeaderRead:
        # build.py imports this module, so the classification rules are imported when used.
        from model_dependabot.inventory.build import NO_ONNX_STRUCTURE, classify_lead, shows_onnx

        length = HEADER_LEAD
        while True:
            response = self.fetcher.get_range(result.url, length)
            _fail_on_server_error(response)
            result = replace(
                result,
                status=response.status,
                content_range=response.headers.get("Content-Range"),
                lead_sha256=hashlib.sha256(response.body).hexdigest(),
                lead_length=len(response.body),
                retrieved_at=response.retrieved_at,
            )
            if response.status not in (200, 206):
                return replace(result, reason=_refusal(response))
            total = _total_size(response)
            if total is None:
                return replace(result, reason="the hub gave no size for the file")
            result = replace(result, total_size=total)
            answer = classify_lead(file, response.body, total)
            if answer == ("onnx", False) and not shows_onnx(response.body, total):
                # Only imported claims are read here; the name alone never confirms them (R5).
                return replace(result, reason=NO_ONNX_STRUCTURE)
            if isinstance(answer, tuple):
                return replace(result, format=answer[0], can_run_code=answer[1])
            if answer.length > HEADER_LIMIT or length != HEADER_LEAD:
                reason = f"the safetensors header is longer than {HEADER_LIMIT} bytes"
                return replace(result, reason=reason)
            length = answer.length

    def revision(self, repo: str, revision: str) -> RevisionResult:
        """The commit a revision names: ``X-Repo-Commit`` if sent, else the model-info ``sha``."""
        url = f"{self.endpoint}/api/models/{_path(repo)}/revision/{quote(revision, safe='')}"
        response, gap = self._get(url)
        if response is None or gap is not None:
            return RevisionResult(commit=None, gap_reason=gap)
        try:
            info = json.loads(response.body)
        except ValueError:
            info = None
        other = answered_for(repo, info)
        if other is not None:
            return RevisionResult(commit=None, gap_reason=f"hub {other}, not {repo}")
        commit = response.headers.get("X-Repo-Commit")
        if commit is None:
            commit = info.get("sha") if isinstance(info, dict) else None
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
    in_tree: bool | None = None  # whether the tree at the verdict's commit lists the file


def security_status_url(repo: str, endpoint: str = HF_ENDPOINT) -> str:
    return f"{endpoint}/api/models/{_path(repo)}?securityStatus=true"


def _parse_status(repo: str, response: Response) -> SecurityStatus:
    if response.status != 200:
        return SecurityStatus(repo, response, MISSING, reason=_refusal(response))
    try:
        info = json.loads(response.body)
    except ValueError:
        return SecurityStatus(repo, response, MISSING, reason="response is not JSON")
    other = answered_for(repo, info)
    if other is not None:
        return SecurityStatus(repo, response, UNRECOGNISED, reason=other)
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

    def verdict(self, status: SecurityStatus, file: str, *, confirm: bool = False) -> FileVerdict:
        """The verdict for one file; a listed file's hash and scanners come from the tree.

        A clean verdict is read from the tree too when ``confirm`` is set, so that an explicit
        ``safe`` file status for the matching hash can clear an alert (FR-023), and so that a
        clean verdict for a head commit other than the pinned revision can be compared with the
        pinned hash: the hub's security status describes the head commit only.
        """
        if status.state != "answered":
            return FileVerdict(status.repo, file, status.state, status, reason=status.reason)
        level = status.levels.get(file)
        state = CLEAN if level is None else LISTED_LEVELS.get(level)
        if state is None:
            return FileVerdict(
                status.repo, file, UNRECOGNISED, status, level, reason=f"level {level!r}"
            )
        if state == CLEAN and not confirm:
            return FileVerdict(status.repo, file, CLEAN, status, level)
        assert status.commit is not None
        response = self._tree(status.repo, status.commit, dirname(file))
        sha256, file_status, in_tree = None, None, None
        if response.status == 200:
            try:
                items = json.loads(response.body)
            except ValueError:
                items = []
            if isinstance(items, list):
                in_tree = False
            for item in items if isinstance(items, list) else []:
                if isinstance(item, dict) and item.get("path") == file:
                    in_tree = True
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
            in_tree=in_tree,
        )


# --- hub datasets (feature 002, research U5) ------------------------------------------------------

DATASET_EXPAND = "expand[]=disabled&expand[]=gated&expand[]=private&expand[]=cardData&expand[]=sha"
DATASET_SOURCE = "hf-hub"


def dataset_info_url(repo: str, endpoint: str = HF_ENDPOINT) -> str:
    """Dataset info with the fields the upstream watch reads."""
    return f"{endpoint}/api/datasets/{_path(repo)}?{DATASET_EXPAND}"


def _declared_licence(card: object) -> str | None:
    """``cardData.license``: every entry of a list, one per line (owner decision of 2026-10-24)."""
    licence = card.get("license") if isinstance(card, dict) else None
    if isinstance(licence, list):
        return join_licences([str(item) for item in licence if item])
    return str(licence) if licence else None


def _gated(value: object) -> str | None:
    if value is None:
        return None
    if value is False:
        return "false"
    return str(value).lower()


@dataclass(frozen=True)
class HubDataset:
    """What the hub answered for one dataset: ``reachable``, ``refused`` or ``redirected``."""

    repo: str
    response: Response
    outcome: str
    disabled: bool | None = None
    gated: str | None = None
    sha: str | None = None
    licence: str | None = None
    moved_to: str | None = None
    # A move's target, read once without following a further redirect (FR-005), or why it was not.
    target: HubDataset | None = None
    target_error: str | None = None


def _moved_to(target: str | None, prefix: str = "/api/datasets/") -> str | None:
    if not target:
        return None
    path = urlsplit(target).path
    return unquote(path[len(prefix) :]) if path.startswith(prefix) else None


def _read_target[T: (HubDataset, HubModel)](answer: T, read: Callable[[str], T]) -> T:
    """``answer``, a redirect, with its target read once by the name the redirect gives.

    The target is read like the pinned name: no redirect is followed and the answer must name the
    target (answer identity). A target that cannot be read, or that redirects again, is recorded
    as ``target_error``; the redirect alone then opens and closes nothing (data-model.md).
    """
    if answer.moved_to is None:
        return replace(answer, target_error="the redirect names no repository")
    try:
        target = read(answer.moved_to)
    except SourceFailedError as error:
        return replace(answer, target_error=f"the new name could not be read: {error.reason}")
    if target.outcome == "redirected":
        return replace(answer, target_error="the new name redirects again (not followed)")
    return replace(answer, target=target)


def parse_dataset(repo: str, response: Response) -> HubDataset:
    status = response.status
    if 300 <= status < 400:
        target = _moved_to(response.redirected_to)
        return HubDataset(repo, response, "redirected", moved_to=target)
    if status in (401, 403, 404):
        return HubDataset(repo, response, "refused")
    if status != 200:
        raise SourceFailedError(DATASET_SOURCE, f"HTTP {status} for dataset {repo}")
    try:
        info = json.loads(response.body)
    except ValueError as error:
        raise SourceFailedError(DATASET_SOURCE, f"unreadable answer for {repo}: {error}") from None
    if not isinstance(info, dict):
        raise SourceFailedError(DATASET_SOURCE, f"unreadable answer for {repo}")
    other = answered_for(repo, info)
    if other is not None:
        raise SourceFailedError(DATASET_SOURCE, f"unreadable answer for {repo}: {other}")
    sha = info.get("sha")
    return HubDataset(
        repo,
        response,
        "reachable",
        disabled=bool(info.get("disabled", False)),
        gated=_gated(info.get("gated", False)),
        sha=sha if isinstance(sha, str) else None,
        licence=_declared_licence(info.get("cardData")),
    )


def read_dataset(fetcher: Fetcher, repo: str, endpoint: str = HF_ENDPOINT) -> HubDataset:
    """One dataset's info; a move is never followed, but its target is read once (U5, FR-005)."""

    def read(name: str) -> HubDataset:
        return parse_dataset(
            name, fetcher.get(dataset_info_url(name, endpoint), follow_redirects=False)
        )

    dataset = read(repo)
    return _read_target(dataset, read) if dataset.outcome == "redirected" else dataset


MODEL_EXPAND = DATASET_EXPAND + "&expand[]=lastModified"


def model_info_url(repo: str, endpoint: str = HF_ENDPOINT) -> str:
    """Model info with the fields the upstream watch reads."""
    return f"{endpoint}/api/models/{_path(repo)}?{MODEL_EXPAND}"


@dataclass(frozen=True)
class HubModel:
    """What the hub answered for a base model: ``reachable``, ``refused`` or ``redirected``."""

    repo: str
    response: Response
    outcome: str
    disabled: bool | None = None
    gated: str | None = None
    sha: str | None = None
    licence: str | None = None
    private: bool | None = None
    last_modified: str | None = None
    card: dict[str, object] | None = None
    card_hash: str | None = None
    new_version: str | None = None
    unrecognised: str | None = None
    moved_to: str | None = None
    # A rename's target, read once without following a further redirect, or why it was not.
    target: HubModel | None = None
    target_error: str | None = None


# Research U7: a disabled model answers HTTP 200 with ``disabled: true`` (recorded in
# ``model-disabled``). Any other value of ``disabled`` is not that shape, so it opens no alert.
UNRECOGNISED_DISABLED = "the hub's disabled field is not true or false"
# Left out of ``card_hash``: the licence fields are compared on their own (FR-008) and
# ``new_version`` is its own watch event (data-model.md, Upstream observation).
CARD_EXCLUDED = ("license", "license_name", "license_link", "new_version")


def card_hash(card: object) -> str:
    """SHA-256 of the canonical ``cardData`` without licence fields and ``new_version``."""
    fields = card if isinstance(card, dict) else {}
    kept = {name: value for name, value in fields.items() if name not in CARD_EXCLUDED}
    canonical = json.dumps(kept, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def parse_model(repo: str, response: Response) -> HubModel:
    status = response.status
    if 300 <= status < 400:
        target = _moved_to(response.redirected_to, "/api/models/")
        return HubModel(repo, response, "redirected", moved_to=target)
    if status in (401, 403, 404):
        return HubModel(repo, response, "refused")
    if status != 200:
        raise SourceFailedError(DATASET_SOURCE, f"HTTP {status} for model {repo}")
    try:
        info = json.loads(response.body)
    except ValueError as error:
        raise SourceFailedError(DATASET_SOURCE, f"unreadable answer for {repo}: {error}") from None
    if not isinstance(info, dict):
        raise SourceFailedError(DATASET_SOURCE, f"unreadable answer for {repo}")
    other = answered_for(repo, info)
    if other is not None:
        raise SourceFailedError(DATASET_SOURCE, f"unreadable answer for {repo}: {other}")
    sha = info.get("sha")
    # The reader always asks for expand[]=disabled; an answer without it is not the recorded
    # shape, so it is unrecognised (a watch event), never false (which would clear an alert).
    disabled = info.get("disabled")
    card = info.get("cardData")
    card = card if isinstance(card, dict) else None
    pointer = (card or {}).get("new_version")
    modified = info.get("lastModified")
    return HubModel(
        repo,
        response,
        "reachable",
        disabled=disabled if isinstance(disabled, bool) else None,
        gated=_gated(info.get("gated", False)),
        sha=sha if isinstance(sha, str) else None,
        licence=_declared_licence(card),
        private=info.get("private") if isinstance(info.get("private"), bool) else None,
        last_modified=modified if isinstance(modified, str) else None,
        card=card,
        card_hash=card_hash(card),
        new_version=pointer if isinstance(pointer, str) and pointer else None,
        unrecognised=None if isinstance(disabled, bool) else UNRECOGNISED_DISABLED,
    )


def read_model(fetcher: Fetcher, repo: str, endpoint: str = HF_ENDPOINT) -> HubModel:
    """A base model's info; a rename is never followed, but its target is read once."""

    def read(name: str) -> HubModel:
        return parse_model(
            name, fetcher.get(model_info_url(name, endpoint), follow_redirects=False)
        )

    model = read(repo)
    return _read_target(model, read) if model.outcome == "redirected" else model

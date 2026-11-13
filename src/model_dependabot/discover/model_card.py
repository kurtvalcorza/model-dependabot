"""The model card's front matter (research A6; FR-018).

The card is the project's top-level ``README.md``. Its metadata is YAML front matter between
``---`` lines at the top, read with PyYAML's safe loader, wrapped to refuse anchors and aliases so
that a crafted card cannot expand into a huge structure, and only from the first 256 KiB. Only
``base_model``, ``base_model_relation``, ``datasets``, ``license``, ``license_name`` and
``license_link`` are read; any other key is listed as not read. Nothing is inferred from the
card's body text, and ``license_link`` is kept as text and never fetched. A card that cannot be
read is listed under ``skipped`` and discovery continues.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import yaml

from model_dependabot.discover.candidate import (
    DECLARED,
    NO_REVISION,
    NOT_A_HUB_NAME,
    SEVERAL_BASE_MODELS,
    UNAVAILABLE,
    candidate,
)
from model_dependabot.discover.walk import OUTSIDE, Limits, Walk, larger_than, skip
from model_dependabot.discover.walk import UNREADABLE as UNREAD
from model_dependabot.upstream.licences import normalise

CARD = "README.md"
KEYS = (
    "base_model",
    "base_model_relation",
    "datasets",
    "license",
    "license_name",
    "license_link",
)
UNREADABLE = "model card front matter unreadable"
# Room after the 256 KiB of front matter for its opening and closing lines.
_CLOSING_SLACK = 64
NOT_RECOGNISED = "licence not recognised"
_REPO_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")


class AliasRefusedError(yaml.YAMLError):
    """The front matter uses an anchor or an alias, which this reader refuses."""


class NoAliasLoader(yaml.SafeLoader):
    """PyYAML's safe loader, refusing every anchor and alias before it is composed."""

    def compose_node(self, parent: Any, index: Any) -> Any:
        event = self.peek_event()
        if isinstance(event, yaml.AliasEvent):
            raise AliasRefusedError(f"an alias (*{event.anchor}) is not accepted")
        if getattr(event, "anchor", None) is not None:
            raise AliasRefusedError(f"an anchor (&{event.anchor}) is not accepted")
        return super().compose_node(parent, index)


def load_front_matter(text: str) -> Any:
    """The parsed YAML of front matter text; raises ``yaml.YAMLError`` or ``RecursionError``."""
    return yaml.load(text, Loader=NoAliasLoader)


def front_matter(data: bytes, limit: int) -> str | None:
    """The front matter text of a card, ``None`` when it has none; ``ValueError`` when the
    closing line is not within ``limit`` bytes or the text is not UTF-8."""
    text = data.decode("utf-8-sig")
    lines = text.splitlines(keepends=True)
    if not lines or lines[0].rstrip("\r\n").rstrip() != "---":
        return None
    size = len(lines[0].encode("utf-8"))
    body: list[str] = []
    for line in lines[1:]:
        if line.rstrip("\r\n").rstrip() in ("---", "..."):
            return "".join(body)
        size += len(line.encode("utf-8"))
        if size > limit:
            break
        body.append(line)
    raise ValueError(f"the front matter is {larger_than(limit)} or is not closed")


def _hub_name(text: str) -> bool:
    owner, _, name = text.partition("/")
    return bool(owner and name and set(owner) <= _REPO_CHARS and set(name) <= _REPO_CHARS)


def _texts(value: Any, key: str) -> list[str]:
    if value is None:  # the key is absent or empty: nothing is declared (review F4)
        return []
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return [item.strip() for item in value if item.strip()]
    raise ValueError(f"{key} is not text or a list of text")


def _base_models(meta: Mapping[str, Any], observed_at: str) -> list[dict[str, Any]]:
    names = _texts(meta.get("base_model"), "base_model")
    relation = meta.get("base_model_relation")
    found = []
    for name in names:
        gaps = [NO_REVISION]
        if len(names) > 1:
            gaps.append(SEVERAL_BASE_MODELS)
        status = DECLARED
        if not _hub_name(name):
            gaps.append(NOT_A_HUB_NAME)
            status = UNAVAILABLE
        identity: dict[str, Any] = {"hub_repo": name, "revision": None}
        if isinstance(relation, str) and relation.strip():
            identity["relation"] = relation.strip()
        origin = {"file": CARD, "key": "base_model"}
        found.append(candidate("base_model", identity, origin, status, observed_at, gaps))
    return found


def _datasets(meta: Mapping[str, Any], observed_at: str) -> list[dict[str, Any]]:
    found = []
    for name in _texts(meta.get("datasets"), "datasets"):
        gaps = [NO_REVISION]
        status = DECLARED
        if not _hub_name(name):
            gaps.append(NOT_A_HUB_NAME)
            status = UNAVAILABLE
        origin = {"file": CARD, "key": "datasets"}
        found.append(candidate("dataset", {"hub_repo": name}, origin, status, observed_at, gaps))
    return found


def _licence(meta: Mapping[str, Any], observed_at: str) -> list[dict[str, Any]]:
    declared = meta.get("license")
    key = "license"
    if declared == "other" and isinstance(meta.get("license_name"), str):
        declared, key = meta["license_name"], "license_name"
    if declared is None:
        return []
    texts = _texts(declared, key)
    if not texts:
        return []
    text = "\n".join(texts)
    normalised = normalise(text)
    identity: dict[str, Any] = {
        "licence": text,
        "spdx": normalised.normalised if normalised.recognised else None,
    }
    link = meta.get("license_link")
    if isinstance(link, str) and link.strip():
        identity["link"] = link.strip()  # kept as text, never fetched (FR-020)
    gaps = [] if normalised.recognised else [NOT_RECOGNISED]
    origin = {"file": CARD, "key": key}
    return [candidate("licence", identity, origin, DECLARED, observed_at, gaps)]


def discover_card(
    found: Walk, observed_at: str, limits: Limits
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """The candidates the card's front matter names explicitly, and what could not be read."""
    if CARD not in found.files:
        return [], []
    length = limits.card_bytes + _CLOSING_SLACK
    data = _head(found, length)
    if isinstance(data, dict):
        return [], [data]
    if len(data) == length:
        data = data[: data.rfind(b"\n") + 1]  # never decode a character cut in two
    try:
        text = front_matter(data, limits.card_bytes)
        if text is None:
            return [], []
        meta = load_front_matter(text)
    except (yaml.YAMLError, ValueError, RecursionError, UnicodeDecodeError) as error:
        reason = str(error).splitlines()[0] if str(error) else type(error).__name__
        if isinstance(error, RecursionError):
            reason = "nested too deeply"
        return [], [skip(CARD, f"{UNREADABLE}: {reason}")]
    if meta is None:
        return [], []
    if not isinstance(meta, Mapping):
        return [], [skip(CARD, f"{UNREADABLE}: the front matter is not a mapping")]
    candidates: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for read in (_base_models, _datasets, _licence):
        try:
            candidates += read(meta, observed_at)
        except ValueError as error:
            skipped.append(skip(CARD, f"{UNREADABLE}: {error}"))
    unknown = sorted(str(key) for key in meta if key not in KEYS)
    if unknown:
        skipped.append(skip(CARD, "front matter keys not read", keys=unknown))
    return candidates, skipped


def _head(found: Walk, length: int) -> bytes | dict[str, Any]:
    try:
        with found.path(CARD).open("rb") as handle:
            return handle.read(length)
    except PermissionError:
        return skip(CARD, OUTSIDE)
    except OSError as error:
        return skip(CARD, f"{UNREAD}: {error.strerror or error}")

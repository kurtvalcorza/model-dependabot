"""Changes between observations of one upstream item (data-model.md, research U7, U8).

A new observation is compared with the previous observation of the same item from the same source.
The first observation is the baseline: it is recorded and raises nothing by itself. Later stories
add the licence comparison, the refusal-span rule and the watch-event detection on top of this core.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from model_dependabot.store import Store

COMPARED_FIELDS = (
    "http_status",
    "outcome",
    "redirected_to",
    "disabled",
    "gated",
    "head_revision",
    "declared_licence",
    "licence_form",
    "card_hash",
    "new_version_pointer",
    "updates",
    "removal",
)


@dataclass(frozen=True)
class Comparison:
    """An observation, the one before it from the same source and the fields that differ."""

    previous: dict[str, Any] | None
    current: dict[str, Any]
    baseline: bool
    changed: tuple[str, ...]


def compare_rows(previous: dict[str, Any] | None, current: dict[str, Any]) -> Comparison:
    if previous is None:
        return Comparison(None, current, True, ())
    changed = tuple(name for name in COMPARED_FIELDS if previous.get(name) != current.get(name))
    return Comparison(previous, current, False, changed)


def compare(store: Store, observation: dict[str, Any]) -> Comparison:
    """Compare a stored observation with the previous one of its item and source."""
    previous = store.previous_observation(
        observation["item"], observation["source"], observation["observation_id"]
    )
    return compare_rows(previous, observation)

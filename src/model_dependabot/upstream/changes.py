"""Changes between observations of one upstream item (data-model.md, research U7, U8).

A new observation is compared with the previous observation of the same item from the same source.
The first observation is the baseline: it is recorded and raises nothing by itself. The licence
comparison is below (US2); later stories add the refusal-span rule and the watch-event
detection on top of this core.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from model_dependabot.store import Store
from model_dependabot.upstream.licences import Licence, normalise, recorded, same_licence

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


# Sources whose observations carry a declared licence (FR-008).
LICENCE_SOURCES = ("datacite", "zenodo", "figshare", "hf-hub")


@dataclass(frozen=True)
class LicenceReference:
    """What a declared licence is compared with: the recorded licence or the baseline (U8).

    ``origin`` is ``inventory`` for the licence recorded at registration, or ``baseline`` for the
    first stored observation that declared one when nothing was recorded; the inventory itself is
    never changed.
    """

    licence: Licence
    origin: str
    observation_id: int | None


def licence_reference(store: Store, entry: Mapping[str, Any]) -> LicenceReference | None:
    """The licence an item's declared licences are compared with, or ``None`` if none yet."""
    licence = recorded(entry.get("recorded_licence"), entry.get("licence_form"))
    if licence is not None:
        return LicenceReference(licence, "inventory", None)
    for observation in store.observations(entry["identifier"]):
        if observation["source"] in LICENCE_SOURCES and observation["declared_licence"]:
            baseline = normalise(observation["declared_licence"])
            return LicenceReference(baseline, "baseline", observation["observation_id"])
    return None


def compare_licence(reference: LicenceReference, observation: Mapping[str, Any]) -> str | None:
    """``changed``, ``same``, ``unrecognised``, ``missing`` or ``None`` (nothing to report).

    ``changed`` only when both licences are recognised and their normalised forms differ; an
    unrecognised declared licence is compared as text; the baseline observation is the reference
    itself.
    """
    if observation.get("observation_id") == reference.observation_id:
        return "same"
    declared = normalise(observation.get("declared_licence"))
    if declared.form == "none":
        return "missing"
    if not declared.recognised:
        return None if same_licence(declared, reference.licence) else "unrecognised"
    if not reference.licence.recognised:
        return None
    return "same" if same_licence(declared, reference.licence) else "changed"

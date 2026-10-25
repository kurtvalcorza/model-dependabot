"""Changes between observations of one upstream item (data-model.md, research U7, U8).

A new observation is compared with the previous observation of the same item from the same source.
The first observation is the baseline: it is recorded and raises nothing by itself. The licence
comparison (US2), the refusal-span rule (US3) and the watch-event detection (US4) are below.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from model_dependabot.store import Store
from model_dependabot.upstream.licences import LicenceSet, normalise, recorded, same_licence

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

    licence: LicenceSet
    origin: str
    observation_id: int | None


def licence_reference(
    store: Store, entry: Mapping[str, Any], scope: str | None = None
) -> LicenceReference | None:
    """The licence an item's declared licences are compared with, or ``None`` if none yet.

    With ``scope`` (a hub repository's identity), the baseline is the first observation that
    declared a licence for any revision of that repository: a hub licence is read from the
    repository's info, so re-pinning a revision does not start a new baseline (identity and
    clearance table).
    """
    licence = recorded(entry.get("recorded_licence"), entry.get("licence_form"))
    if licence is not None:
        return LicenceReference(licence, "inventory", None)
    found = (
        store.observations(entry["identifier"])
        if scope is None
        else store.observations_in_repository(scope)
    )
    for observation in found:
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


# Research U7, FR-012: the owner's guard against transient refusals.
REFUSAL_SPAN = timedelta(hours=24)


@dataclass(frozen=True)
class RefusalRun:
    """The unbroken run of scheduled refusals the latest observation belongs to (research U7).

    ``refusals`` are the run's scheduled refusals, oldest first; ``counted`` is whether the latest
    observation is one of them (a scheduled refusal); ``qualifies`` is whether the run spans at
    least ``REFUSAL_SPAN`` from its first to its latest refusal.
    """

    refusals: tuple[dict[str, Any], ...]
    counted: bool
    qualifies: bool


def _moment(text: str) -> datetime:
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def refusal_run(observations: Sequence[Mapping[str, Any]]) -> RefusalRun:
    """Apply the refusal-span rule to one item's hub observations, oldest first (research U7).

    Walking back from the latest observation: a scheduled refusal joins the run, an on-demand
    refusal is passed over (it neither counts nor breaks the run) and any other answer, from any
    run, ends it. A failed request wrote no observation, so it is never seen here.
    """
    if not observations or observations[-1].get("outcome") != "refused":
        return RefusalRun((), False, False)
    run: list[dict[str, Any]] = []
    for observation in reversed(observations):
        if observation.get("outcome") != "refused":
            break
        if observation.get("trigger") == "scheduled":
            run.append(dict(observation))
    run.reverse()
    counted = observations[-1].get("trigger") == "scheduled"
    if not run:
        return RefusalRun((), counted, False)
    span = _moment(run[-1]["observed_at"]) - _moment(run[0]["observed_at"])
    return RefusalRun(tuple(run), counted, span >= REFUSAL_SPAN)


def previous_answer(store: Store, observation: Mapping[str, Any]) -> dict[str, Any] | None:
    """The latest earlier ``reachable`` observation of the same item from the same source."""
    earlier = [
        seen
        for seen in store.observations(observation["item"], observation["source"])
        if seen["observation_id"] < observation["observation_id"] and seen["outcome"] == "reachable"
    ]
    return earlier[-1] if earlier else None


def appeared(previous: Mapping[str, Any] | None, current: Mapping[str, Any], name: str) -> bool:
    """A pointer to something newer is present and was not there, or was another, before.

    For the newest revision, the ``new_version`` pointer and a dataset's newest version: each is
    recorded once when it first appears (on the baseline too) and again only when it changes.
    """
    value = current.get(name)
    return bool(value) and (previous is None or previous.get(name) != value)


def changed(previous: Mapping[str, Any] | None, current: Mapping[str, Any], name: str) -> bool:
    """A field differs from the previous answer; the baseline, or a field it lacked, is no change.

    For ``gated`` and ``card_hash`` (FR-013): only a change between two answers is reported.
    """
    if previous is None or previous.get(name) is None or current.get(name) is None:
        return False
    return previous.get(name) != current.get(name)

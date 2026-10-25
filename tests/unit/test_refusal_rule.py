"""The refusal-span rule (T043; research U7, FR-012, SC-003).

"The alert opens when an unbroken run of refusal observations from scheduled check runs, with no
reachable observation from any run in between, spans at least 24 hours from its first to its latest
refusal." On-demand refusals neither count towards the span nor break the run; a reachable
observation from any run ends it; a failed request writes no observation, so it is never seen.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from model_dependabot.upstream.changes import REFUSAL_SPAN, refusal_run

DAY0 = datetime(2026, 10, 24, 6, 0, tzinfo=UTC)
SHORT = timedelta(hours=24) - timedelta(seconds=5)


def seen(outcome: str, at: datetime, trigger: str = "scheduled") -> dict[str, Any]:
    stamp = at.strftime("%Y-%m-%dT%H:%M:%SZ")
    return {"outcome": outcome, "trigger": trigger, "observed_at": stamp}


def refused(at: datetime, trigger: str = "scheduled") -> dict[str, Any]:
    return seen("refused", at, trigger)


def test_the_span_is_24_hours() -> None:
    assert timedelta(hours=24) == REFUSAL_SPAN


def test_one_scheduled_refusal_does_not_qualify() -> None:
    run = refusal_run([refused(DAY0)])
    assert (run.counted, run.qualifies, len(run.refusals)) == (True, False, 1)


def test_two_scheduled_refusals_24_hours_apart_qualify() -> None:
    run = refusal_run([refused(DAY0), refused(DAY0 + timedelta(hours=24))])
    assert (run.counted, run.qualifies, len(run.refusals)) == (True, True, 2)


def test_two_scheduled_refusals_23_hours_apart_do_not_qualify() -> None:
    run = refusal_run([refused(DAY0), refused(DAY0 + timedelta(hours=23))])
    assert (run.counted, run.qualifies) == (True, False)


def test_daily_runs_a_few_seconds_short_qualify_on_the_third_run() -> None:
    first, second, third = DAY0, DAY0 + SHORT, DAY0 + 2 * SHORT
    assert not refusal_run([refused(first), refused(second)]).qualifies
    run = refusal_run([refused(first), refused(second), refused(third)])
    assert run.qualifies
    assert [r["observed_at"] for r in run.refusals] == [
        refused(t)["observed_at"] for t in (first, second, third)
    ]


def test_an_on_demand_refusal_neither_counts_nor_breaks_the_run() -> None:
    between = refused(DAY0 + timedelta(hours=12), "on_demand")
    run = refusal_run([refused(DAY0), between, refused(DAY0 + timedelta(hours=24))])
    assert run.qualifies
    assert len(run.refusals) == 2
    assert between not in run.refusals


def test_an_on_demand_refusal_alone_is_not_counted() -> None:
    late = refused(DAY0 + timedelta(hours=30), "on_demand")
    run = refusal_run([refused(DAY0), late])
    assert (run.counted, run.qualifies, len(run.refusals)) == (False, False, 1)


def test_an_on_demand_refusal_does_not_stretch_the_span() -> None:
    run = refusal_run([refused(DAY0), refused(DAY0 + timedelta(hours=25), "on_demand")])
    assert not run.qualifies


def test_a_scheduled_reachable_observation_ends_the_run() -> None:
    history = [refused(DAY0), seen("reachable", DAY0 + timedelta(hours=12))]
    run = refusal_run([*history, refused(DAY0 + timedelta(hours=24))])
    assert (run.qualifies, len(run.refusals)) == (False, 1)


def test_an_on_demand_reachable_observation_ends_the_run() -> None:
    history = [refused(DAY0), seen("reachable", DAY0 + timedelta(hours=12), "on_demand")]
    run = refusal_run([*history, refused(DAY0 + timedelta(hours=24))])
    assert (run.qualifies, len(run.refusals)) == (False, 1)


def test_the_next_refusal_after_a_reachable_one_starts_a_new_run() -> None:
    history = [refused(DAY0), seen("reachable", DAY0 + timedelta(hours=1))]
    later = [refused(DAY0 + timedelta(hours=2)), refused(DAY0 + timedelta(hours=26))]
    run = refusal_run([*history, *later])
    assert (run.qualifies, [r["observed_at"] for r in run.refusals]) == (
        True,
        [r["observed_at"] for r in later],
    )


def test_a_failed_request_writes_no_observation_and_changes_nothing() -> None:
    # The failed run between them stored nothing, so the rule sees only the two refusals.
    run = refusal_run([refused(DAY0), refused(DAY0 + timedelta(hours=24))])
    assert run.qualifies


def test_a_reachable_latest_observation_is_no_run() -> None:
    run = refusal_run([refused(DAY0), seen("reachable", DAY0 + timedelta(hours=30))])
    assert (run.counted, run.qualifies, run.refusals) == (False, False, ())

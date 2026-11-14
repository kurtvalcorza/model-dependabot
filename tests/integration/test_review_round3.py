"""PR #17 review round 3 (issue #18): a check that asks no weight source changes a
``globals_policy`` alert only for the globals whose exception lapsed.

Pickles are crafted opcode bytes built at test time; nothing is ever loaded.
"""

from __future__ import annotations

import hashlib
import shutil
import sqlite3
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
import test_review_round2 as round2
from test_review_round2 import (
    ALPHA,
    BETA,
    NOW,
    Clock,
    _global,
    _model,
    _policy_alerts,
    _register,
    two_suspicious,
)

from model_dependabot import lifecycle
from model_dependabot.cli import EXIT_OK

cli = round2.cli  # the round 2 fixtures, shared
clock = round2.clock

A = ".".join(ALPHA)
B = ".".join(BETA)


def test_a_lapse_does_not_apply_a_policy_set_strict_since_the_last_weight_check(
    cli: Any, tmp_path: Path
) -> None:
    sha = _register(cli, tmp_path / "m", "m", two_suspicious())
    cli("check", "m", "--source", "picklescan")  # scanned under the default policy
    _, made = cli("exception", "record", "--global", A, "--sha256", sha, "--reason", "r",
                  "--by", "O")  # fmt: skip
    cli("exception", "revoke", str(made["exception_id"]), "--reason", "r", "--by", "O")
    cli("policy", "m", "--globals", "strict", "--by", "Owner")
    cli("check", "m", "--source", "osv")
    assert _policy_alerts(cli, "m") == []  # the policy change waits for a weight check
    cli("check", "m", "--source", "picklescan")
    [opened] = _policy_alerts(cli, "m")
    assert opened["cause"]["unlisted"] == [A, B]


def test_a_lapse_does_not_apply_an_exception_recorded_since_the_last_weight_check(
    cli: Any, tmp_path: Path, clock: Clock
) -> None:
    sha = _register(cli, tmp_path / "m", "m", two_suspicious())
    cli("policy", "m", "--globals", "strict", "--by", "Owner")
    cli("exception", "record", "--global", A, "--sha256", sha, "--reason", "r",
        "--by", "O", "--expires", "2026-11-15")  # fmt: skip
    cli("check", "m", "--source", "picklescan")
    [first] = _policy_alerts(cli, "m")
    assert first["cause"]["unlisted"] == [B]
    clock.at = NOW + timedelta(days=30)  # A's exception has expired
    cli("exception", "record", "--global", B, "--sha256", sha, "--reason", "r", "--by", "O")
    cli("check", "m", "--source", "osv")
    [carried] = _policy_alerts(cli, "m")
    assert carried["alert_id"] == first["alert_id"]
    assert carried["cause"]["unlisted"] == [A, B]  # A is back; B's exception waits
    cli("check", "m", "--source", "picklescan")
    [applied] = _policy_alerts(cli, "m")
    assert applied["cause"]["unlisted"] == [A]


def _snapshots(tmp_path: Path) -> list[str]:
    with sqlite3.connect(tmp_path / "db" / "md.db") as conn:
        rows = conn.execute(
            "SELECT detail FROM evidence WHERE source = 'globals-snapshot' ORDER BY evidence_id"
        ).fetchall()
    return [row[0] for row in rows]


def test_every_weight_check_records_one_snapshot_per_file_under_either_policy(
    cli: Any, tmp_path: Path
) -> None:
    sha = _register(cli, tmp_path / "m", "m", two_suspicious())
    cli("check", "m", "--source", "picklescan")  # default policy
    cli("check", "m", "--source", "osv")  # no weight source: no snapshot
    cli("policy", "m", "--globals", "strict", "--by", "Owner")
    for name in (A, B):
        cli("exception", "record", "--global", name, "--sha256", sha, "--reason", "r",
            "--by", "O")  # fmt: skip
    cli("check", "m", "--source", "picklescan")  # strict, nothing left unlisted
    first, second = _snapshots(tmp_path)
    assert '"globals_policy": "default"' in first
    assert '"globals_policy": "strict"' in second and '"unlisted": []' in second
    assert _policy_alerts(cli, "m") == []


def test_a_store_without_snapshots_waits_for_a_weight_check(
    cli: Any, tmp_path: Path, clock: Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    sha = _register(cli, tmp_path / "m", "m", two_suspicious())
    cli("policy", "m", "--globals", "strict", "--by", "Owner")
    for name in (A, B):
        cli("exception", "record", "--global", name, "--sha256", sha, "--reason", "r",
            "--by", "O", "--expires", "2026-11-15")  # fmt: skip
    with monkeypatch.context() as patched:  # a weight check from before the snapshots
        patched.setattr(lifecycle, "_record_globals_snapshots", lambda *args: None)
        cli("check", "m", "--source", "picklescan")
    assert _snapshots(tmp_path) == []
    clock.at = NOW + timedelta(days=30)  # both exceptions have expired
    cli("check", "m", "--source", "osv")
    assert _policy_alerts(cli, "m") == []  # nothing says what the last weight check applied
    cli("check", "m", "--source", "picklescan")
    [opened] = _policy_alerts(cli, "m")
    assert opened["cause"]["unlisted"] == [A, B]


def test_a_lapse_follows_the_snapshot_policy_not_a_later_change_to_default(
    cli: Any, tmp_path: Path, clock: Clock
) -> None:
    sha = _register(cli, tmp_path / "m", "m", two_suspicious())
    cli("policy", "m", "--globals", "strict", "--by", "Owner")
    cli("exception", "record", "--global", A, "--sha256", sha, "--reason", "r",
        "--by", "O", "--expires", "2026-11-15")  # fmt: skip
    cli("check", "m", "--source", "picklescan")
    cli("policy", "m", "--globals", "default", "--by", "Owner")
    clock.at = NOW + timedelta(days=30)
    cli("check", "m", "--source", "osv")
    [open_alert] = _policy_alerts(cli, "m")  # the change to default waits too
    assert open_alert["cause"]["unlisted"] == [A, B]
    cli("check", "m", "--source", "picklescan")
    assert _policy_alerts(cli, "m") == []  # cleared: policy


def test_a_renewed_exception_opens_nothing_at_a_check_without_a_weight_source(
    cli: Any, tmp_path: Path, clock: Clock
) -> None:
    sha = _register(cli, tmp_path / "m", "m", two_suspicious())
    cli("policy", "m", "--globals", "strict", "--by", "Owner")
    cli("exception", "record", "--global", A, "--sha256", sha, "--reason", "r",
        "--by", "O", "--expires", "2026-11-15")  # fmt: skip
    cli("exception", "record", "--global", B, "--sha256", sha, "--reason", "r", "--by", "O")
    cli("check", "m", "--source", "picklescan")
    assert _policy_alerts(cli, "m") == []
    clock.at = NOW + timedelta(days=30)  # A's exception has expired ...
    cli("exception", "record", "--global", A, "--sha256", sha, "--reason", "renewed",
        "--by", "O")  # fmt: skip  # ... and is renewed before any check
    _, checked = cli("check", "m", "--source", "osv", "--fail-on", "LOW")
    # Review P2: no alert trips the gate. (It still trips as "not checked": OSV has nothing to read
    # in a weights-only model, FR-021, which a renewal does not change.)
    assert checked["gate"]["alerts"] == [], checked["gate"]
    assert checked["gate"]["unchecked"] == ["m"], checked["gate"]
    assert _policy_alerts(cli, "m") == []
    cli("check", "m", "--source", "picklescan")
    assert _policy_alerts(cli, "m") == []


def test_each_model_and_file_reads_its_own_snapshot(cli: Any, tmp_path: Path, clock: Clock) -> None:
    two = two_suspicious()
    alpha_only = b"\x80\x02" + _global(*ALPHA) + b"0."
    weights = ["[[weights]]", 'path = "w.pkl"', "", "[[weights]]", 'path = "v.pkl"']
    _model(cli, tmp_path / "s", "s", weights, {"w.pkl": two, "v.pkl": alpha_only})
    assert cli("register", str(tmp_path / "s" / "model.toml"))[0] == EXIT_OK
    sha_two = _register(cli, tmp_path / "d", "d", two)  # the same bytes, default policy
    sha_alpha = hashlib.sha256(alpha_only).hexdigest()
    cli("policy", "s", "--globals", "strict", "--by", "Owner")
    for sha in (sha_two, sha_alpha):
        cli("exception", "record", "--global", A, "--sha256", sha, "--reason", "r",
            "--by", "O", "--expires", "2026-11-15")  # fmt: skip
    cli("check", "s", "--source", "picklescan")
    cli("check", "d", "--source", "picklescan")
    [first] = _policy_alerts(cli, "s")
    assert first["cause"]["unlisted"] == [B]  # w.pkl; v.pkl has nothing left
    clock.at = NOW + timedelta(days=30)
    cli("check", "s", "--source", "osv")
    cli("check", "d", "--source", "osv")
    lists = {a["cause"]["identifier"]: a["cause"]["unlisted"] for a in _policy_alerts(cli, "s")}
    assert lists == {f"sha256:{sha_two}": [A, B], f"sha256:{sha_alpha}": [A]}
    assert _policy_alerts(cli, "d") == []  # its snapshot is default


# --- round 2 of the review: a renewal in both passes, and its edges ----------------------------

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
GETATTR = "__builtin__.getattr"


def _lapse_then(cli: Any, tmp_path: Path, clock: Clock, *expiring: str) -> str:
    """Strict policy, an expiring exception for each of ``expiring`` and one for every other
    global, a weight check (nothing listed), then 30 days later: those exceptions have expired."""
    sha = _register(cli, tmp_path / "m", "m", two_suspicious())
    cli("policy", "m", "--globals", "strict", "--by", "Owner")
    for name in (A, B):
        expiry = ("--expires", "2026-11-15") if name in expiring else ()
        cli("exception", "record", "--global", name, "--sha256", sha, "--reason", "r",
            "--by", "O", *expiry)  # fmt: skip
    cli("check", "m", "--source", "picklescan")
    assert _policy_alerts(cli, "m") == []
    clock.at = NOW + timedelta(days=30)
    return sha


def _renew(cli: Any, name: str, sha: str, *extra: str) -> dict[str, Any]:
    _, made = cli("exception", "record", "--global", name, "--sha256", sha, "--reason", "renewed",
                  "--by", "O", *extra)  # fmt: skip
    return made


def _unlisted(cli: Any) -> list[list[str]]:
    return [a["cause"]["unlisted"] for a in _policy_alerts(cli, "m")]


def test_a_renewal_keeps_a_dangerous_global_excepted_at_a_packages_only_check(
    cli: Any, tmp_path: Path, clock: Clock, craft: Any
) -> None:
    sha = _register(cli, tmp_path / "m", "m", craft.protocol2_getattr())
    cli("exception", "record", "--global", GETATTR, "--sha256", sha, "--reason", "r",
        "--by", "O", "--expires", "2026-11-15")  # fmt: skip
    code, checked = cli("check", "m", "--source", "picklescan", "--fail-on", "HIGH")
    assert code == EXIT_OK, checked["gate"]
    clock.at = NOW + timedelta(days=30)
    _renew(cli, GETATTR, sha)
    _, checked = cli("check", "m", "--source", "osv", "--fail-on", "HIGH")
    assert checked["gate"]["alerts"] == [], checked["gate"]  # MDB101 stays excepted
    _, listed = cli("alerts", "m")
    assert [a["kind"] for a in listed["alerts"]] == []


def test_a_renewal_passes_the_gate_of_an_osv_checked_model(
    cli: Any, tmp_path: Path, clock: Clock, craft: Any
) -> None:
    root = tmp_path / "m"
    root.mkdir()
    (root / "w.pkl").write_bytes(craft.protocol2_getattr())
    shutil.copy(FIXTURES / "locks" / "fixed.txt", root / "requirements.txt")
    (root / "model.toml").write_text(
        '[model]\nid = "m"\n\n[environment]\nlock = "requirements.txt"\n\n'
        '[[weights]]\npath = "w.pkl"\n',
        encoding="utf-8",
    )
    osv = FIXTURES / "osv"
    assert cli("register", str(root / "model.toml"), recordings=osv)[0] == EXIT_OK
    sha = hashlib.sha256((root / "w.pkl").read_bytes()).hexdigest()
    cli("exception", "record", "--global", GETATTR, "--sha256", sha, "--reason", "r",
        "--by", "O", "--expires", "2026-11-15")  # fmt: skip
    code, checked = cli("check", "m", "--source", "osv,picklescan", "--fail-on", "HIGH",
                        recordings=osv)  # fmt: skip
    assert code == EXIT_OK, checked["gate"]
    clock.at = NOW + timedelta(days=30)
    _renew(cli, GETATTR, sha)
    code, checked = cli("check", "m", "--source", "osv", "--fail-on", "HIGH", recordings=osv)
    assert code == EXIT_OK, checked["gate"]


def test_a_partial_renewal_lists_only_the_global_not_renewed(
    cli: Any, tmp_path: Path, clock: Clock
) -> None:
    sha = _lapse_then(cli, tmp_path, clock, A, B)
    _renew(cli, A, sha)
    cli("check", "m", "--source", "osv")
    assert _unlisted(cli) == [[B]]


def test_a_renewal_that_expired_in_turn_returns_the_global(
    cli: Any, tmp_path: Path, clock: Clock
) -> None:
    sha = _lapse_then(cli, tmp_path, clock, A)
    _renew(cli, A, sha, "--expires", "2026-12-20")
    cli("check", "m", "--source", "osv")
    assert _unlisted(cli) == []
    clock.at = NOW + timedelta(days=60)
    cli("check", "m", "--source", "osv")
    assert _unlisted(cli) == [[A]]


def test_a_renewal_revoked_returns_the_global(cli: Any, tmp_path: Path, clock: Clock) -> None:
    sha = _lapse_then(cli, tmp_path, clock, A)
    made = _renew(cli, A, sha)
    cli("exception", "revoke", str(made["exception_id"]), "--reason", "r", "--by", "O")
    cli("check", "m", "--source", "osv")
    assert _unlisted(cli) == [[A]]


def test_an_exception_for_other_bytes_is_no_renewal(cli: Any, tmp_path: Path, clock: Clock) -> None:
    _lapse_then(cli, tmp_path, clock, A)
    _renew(cli, A, hashlib.sha256(b"other bytes").hexdigest())
    cli("check", "m", "--source", "osv")
    assert _unlisted(cli) == [[A]]

"""State-machine tests of feature 004: exceptions, the globals policy, held dismissals and the gate.

A sibling of ``test_alert_lifecycle_machine.py``. Hypothesis drives one model through the command
line (``cli.main``, an injected clock, recorded or failing OSV answers) with random sequences of:
registering one of three crafted pickles from one of three folders or from a registration record,
dismissing an alert, recording an exception (optionally expiring) or revoking one, setting the
globals policy, advancing the clock, letting OSV fail or answer and checking a random subset of
sources, for the model or ``--all``, with or without ``--fail-on``. Two compound rules make the
short default run reach excepted alerts and lapsed exceptions: one excepts the current file's
dangerous globals and asks picklescan, the other lets an exception expire or revokes one,
sometimes records a new one, and asks OSV only. The guided tour and
``tests/integration/test_review_round2.py`` pin the rest, such as a new exception waiting while a
lapse acts. The
pickles are opcode bytes: ``mixed`` and ``dangerous`` are built by
``tests/fixtures/pickles/craft.py`` and ``two`` is built inline below; nothing is ever loaded and
nothing reaches the network.

After every check these hold. Which exceptions are active (pair, expiry and revocation) and which
sources can cover the model come from the machine's own model, never from the product; alert
states and severities are read from the store:

a. an excepted alert never counts as open: the ids ``alerts`` lists as open and as excepted, and
   the audit's ``alerts_open`` and ``alerts_excepted``, match the store's open alerts split by
   ``excepted_at``, and the gate counts none of them;
b. the exit code: 2 exactly when a source failed; otherwise, with ``--fail-on``, 4 exactly when the
   gate tripped and 0 when it did not, and the gate lists exactly the open alerts at or above the
   severity that are not excepted, the incomplete source (``picklescan`` on a model registered
   from a record, whose files are not on disk) and the unchecked model (no asked source that can
   read it answered); without ``--fail-on`` never 4;
c. a dismissal holds unless the evidence is new: the same bytes (from any folder or record) and the
   same advisory never reopen a dismissed alert, while a globals list that grows past the list at
   dismissal does reopen it;
d. after a check that asks a weight source under the strict policy, the ``globals_policy`` alert of
   the current file lists exactly its scanned globals that are neither on the safe list nor
   excepted, and no other file has one open; under the default policy no ``globals_policy`` alert
   is left open (FR-010); after a packages-only check that follows such a strict check, every
   global the model expects is still listed, so a lapsed exception's finding is back;
e. an alert marked excepted is covered by exceptions active at the check's time, and after a check
   that asks a weight source a ``weight_file_scan`` alert whose dangerous globals are all covered
   is excepted; an exception covers only its own SHA-256 (FR-002); ``exception record`` is refused
   exactly when an active exception covers the same pair or the expiry date is in the past, and
   ``exception list`` shows exactly the active exceptions;
f. at most one open alert per cause, and every alert has evidence;
g. a check that asks no weight source applies no new exception and no policy change (FR-010),
   judged against the machine's own record of the last check that asked one (its policy, when that
   policy was set and the exceptions then active): no alert becomes excepted and no open
   ``globals_policy`` alert closes or loses a global; with no record, or under a policy changed
   since, no ``globals_policy`` alert changes; otherwise the current file's alert lists exactly
   the globals that recorded exceptions still active leave unlisted, and opens or grows only for
   a recorded exception that has lapsed since.

The default run is derandomised and short; ``MODEL_DEPENDABOT_PROPERTY_EXAMPLES`` set to a number
runs that many random sequences instead (unset or empty: the default run).

Covered elsewhere, not here: the same bytes under other models
(``tests/integration/test_exceptions.py``), the
empty scope (``tests/contract/test_exit_codes.py`` and ``tests/integration/test_overview.py``),
``format-check`` and the ``released`` citation (``tests/integration/test_exceptions.py``), hub
files (``tests/integration/test_check_weights.py``), scanner-version evidence
(``tests/integration/test_review_round1.py``) and the overview rows
(``tests/integration/test_overview.py``).
"""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import shutil
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from hypothesis import HealthCheck, settings
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, invariant, rule

from model_dependabot.assurance import globals_policy
from model_dependabot.cli import main, make_handlers
from model_dependabot.matching.severity import SEVERITIES, severity_rank
from model_dependabot.sources.fetcher import RecordedFetcher, SourceFailedError
from model_dependabot.store import Store

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
NOW = datetime(2026, 11, 14, 9, 0, tzinfo=UTC)
MODEL = "m"
WEIGHT_SOURCES = {"picklescan", "hf-scan", "format-check"}
SOURCES = ("picklescan", "osv", "hf-scan")


def _craft() -> Any:
    spec = importlib.util.spec_from_file_location(
        "craft_machine", FIXTURES / "pickles" / "craft.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CRAFT = _craft()
ALPHA = ("model_dependabot_fixture.layers", "Alpha")
BETA = ("model_dependabot_fixture.layers", "Beta")


def _global(module: str, name: str) -> bytes:
    return b"c" + module.encode() + b"\n" + name.encode() + b"\n"


# Each file: its bytes and what picklescan 1.0.5 reports, (module, name, safety).
FILES: dict[str, tuple[bytes, tuple[tuple[str, str, str], ...]]] = {
    "mixed": (
        CRAFT.mixed(),
        (
            ("collections", "OrderedDict", "innocuous"),
            ("model_dependabot_fixture.layers", "CustomLayer", "suspicious"),
            ("os", "system", "dangerous"),
        ),
    ),
    "two": (
        b"\x80\x02" + _global(*ALPHA) + b"0" + _global(*BETA) + b"0.",
        ((*ALPHA, "suspicious"), (*BETA, "suspicious")),
    ),
    "dangerous": (CRAFT.dangerous(), (("os", "system", "dangerous"),)),
}
SAFE = globals_policy.load_safe_list().entries


class DownFetcher:
    """Every request fails: OSV is unreachable."""

    def get(self, *args: Any, **kwargs: Any) -> Any:
        raise SourceFailedError("osv.dev", "HTTP 503 after 3 tries")

    head = get_range = post = get


class ScanPolicyMachine(RuleBasedStateMachine):
    def __init__(self) -> None:
        super().__init__()
        self.root = Path(tempfile.mkdtemp(prefix="md-scan-machine-"))
        self.db = self.root / "db" / "md.db"
        self.now = NOW
        self.osv_down = False
        self.file = "mixed"
        self.strict = False
        self.from_record = False
        # exception_id -> the file's SHA-256, the global, the last day it covers (None: no
        # expiry) and whether it was revoked. The oracles read this model, never the store.
        self.exceptions: dict[int, dict[str, Any]] = {}
        # The SHA-256 of the file a weight source last checked under the strict policy, while that
        # file is current.
        self.strict_scan: str | None = None
        # cause_key -> what the dismissed alert stood on: its id and, for a globals policy
        # alert, its list at dismissal.
        self.dismissed: dict[str, dict[str, Any]] = {}
        self.versions = 0
        # When the globals policy was last set (the clock then; None until first set) and what the
        # last check that asked a weight source applied: (strict, set at) and the active exception
        # ids. The oracles of (g) read this, never the product's mark.
        self.policy_set_at: datetime | None = None
        self.mark: dict[str, Any] | None = None
        self.last: tuple[int, Any] = (0, None)
        self.register(file="mixed", folder="a", via_record=False)

    def teardown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    # -- the command line --

    def cli(self, *argv: str) -> tuple[int, Any]:
        fetcher = DownFetcher() if self.osv_down else RecordedFetcher(FIXTURES / "osv")
        handlers = make_handlers(fetcher=fetcher, now=lambda: self.now)
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = main([*argv, "--db", str(self.db), "--json"], handlers=handlers)
        text = out.getvalue()
        return code, json.loads(text) if text.strip() else None

    def ok(self, *argv: str) -> Any:
        code, payload = self.cli(*argv)
        assert code == 0, (argv, code, payload)
        return payload

    def _store(self) -> Store:
        return Store.open_read_only(self.db, now=lambda: self.now)

    def _alerts(self) -> list[dict[str, Any]]:
        with self._store() as store:
            return store.alerts_for(MODEL)

    def _sha(self) -> str:
        return hashlib.sha256(FILES[self.file][0]).hexdigest()

    # -- the model of the exceptions --

    def _is_active(self, exception: dict[str, Any]) -> bool:
        """Active until revoked or past its expiry date: that whole day in UTC is covered."""
        expires = exception["expires_on"]
        return not exception["revoked"] and (expires is None or self.now.date() <= expires)

    def _active(self) -> set[tuple[str, str]]:
        """The (SHA-256, ``module.name``) pairs that active exceptions cover now."""
        return {(e["sha"], e["global"]) for e in self.exceptions.values() if self._is_active(e)}

    def _expected_unlisted(self) -> set[str]:
        active = self._active()
        return {
            f"{m}.{n}"
            for m, n, _ in FILES[self.file][1]
            if (m, n) not in SAFE and (self._sha(), f"{m}.{n}") not in active
        }

    # -- the rules --

    @rule(
        file=st.sampled_from(sorted(FILES)),
        folder=st.sampled_from(["a", "b", "c"]),
        via_record=st.booleans(),
    )
    def register(self, file: str, folder: str, via_record: bool) -> None:
        self.versions += 1
        place = self.root / f"{folder}-{self.versions}"
        (place / "weights").mkdir(parents=True)
        (place / "weights" / "w.pkl").write_bytes(FILES[file][0])
        shutil.copy(FIXTURES / "locks" / "vulnerable.txt", place / "requirements.txt")
        manifest = place / "model.toml"
        manifest.write_text(
            f'[model]\nid = "{MODEL}"\n\n[environment]\nlock = "requirements.txt"\n\n'
            '[[weights]]\npath = "weights/w.pkl"\n',
            encoding="utf-8",
        )
        if via_record:
            record = place / "model.record.json"
            self.ok("record", str(manifest), "--out", str(record))
            ci = self.root / f"ci-{self.versions}"
            ci.mkdir()
            for name in ("model.toml", "requirements.txt", "model.record.json"):
                shutil.copy(place / name, ci / name)
            argv = (
                "register",
                str(ci / "model.toml"),
                "--from-record",
                str(ci / "model.record.json"),
            )
        else:
            argv = ("register", str(manifest))
        self.ok(*argv, "--model-id", MODEL)
        if file != self.file:
            self.strict_scan = None
        self.file = file
        self.from_record = via_record  # the weights stay behind: picklescan cannot read them
        self._held_invariant()

    @rule(
        pick=st.integers(min_value=0, max_value=7),
        kind=st.none()
        | st.sampled_from(["weight_file_scan", "globals_policy", "package_advisory"]),
    )
    def dismiss(self, pick: int, kind: str | None = None) -> None:
        live = [
            a
            for a in self._alerts()
            if a["state"] == "open" and (kind is None or a["kind"] == kind)
        ]
        if not live:
            return
        alert = live[pick % len(live)]
        self.ok(
            "alert", "dismiss", str(alert["alert_id"]), "--reason", "risk_accepted", "--by", "O"
        )
        self.dismissed[alert["cause_key"]] = {
            "alert_id": alert["alert_id"],
            "kind": alert["kind"],
            "unlisted": set(alert["cause"].get("unlisted") or []),
        }

    @rule(pick=st.integers(min_value=0, max_value=3), days=st.none() | st.integers(-1, 3))
    def record_exception(self, pick: int, days: int | None) -> None:
        names = [(m, n) for m, n, _ in FILES[self.file][1]]
        self._record(*names[pick % len(names)], days)

    def _record(self, module: str, name: str, days: int | None) -> None:
        sha = self._sha()
        argv = ["exception", "record", "--global", f"{module}:{name}", "--sha256", sha]
        argv += ["--reason", "reviewed", "--by", "O"]
        expires = None
        if days is not None:
            expires = (self.now + timedelta(days=days)).date()
            argv += ["--expires", expires.isoformat()]
        code, recorded = self.cli(*argv)
        # (e) refused exactly while an active exception covers the same pair, or when the expiry
        # date is in the past (assurance/exceptions.py, _expiry)
        duplicate = (sha, f"{module}.{name}") in self._active()
        refused = duplicate or (days is not None and days < 0)
        assert code == (1 if refused else 0), (argv, code, recorded)
        if code == 0:
            self.exceptions[int(recorded["exception_id"])] = {
                "sha": sha,
                "global": f"{module}.{name}",
                "expires_on": expires,
                "revoked": False,
            }

    @rule(pick=st.integers(min_value=0, max_value=7))
    def revoke(self, pick: int) -> None:
        _, listed = self.cli("exception", "list")
        active = sorted(i for i, e in self.exceptions.items() if self._is_active(e))
        # (e) the list shows exactly the active exceptions
        assert sorted(item["exception_id"] for item in listed["exceptions"]) == active, listed
        if not active:
            return
        chosen = active[pick % len(active)]
        self.ok("exception", "revoke", str(chosen), "--reason", "r", "--by", "O")
        self.exceptions[chosen]["revoked"] = True

    @rule(strict=st.booleans())
    def globals(self, strict: bool) -> None:
        self.ok("policy", MODEL, "--globals", "strict" if strict else "default", "--by", "O")
        self.strict = strict
        self.policy_set_at = self.now

    @rule(days=st.integers(min_value=1, max_value=20))
    def advance(self, days: int) -> None:
        self.now += timedelta(days=days)

    @rule(down=st.booleans())
    def osv(self, down: bool) -> None:
        self.osv_down = down

    @rule(days=st.none() | st.integers(0, 1), fail_on=st.none() | st.sampled_from(SEVERITIES))
    def except_and_scan(self, days: int | None, fail_on: str | None) -> None:
        """Except every dangerous global of the current file, then ask picklescan."""
        found = FILES[self.file][1]
        wanted = [(m, n) for m, n, s in found if s == "dangerous"] or [found[0][:2]]
        for module, name in wanted:
            if (self._sha(), f"{module}.{name}") not in self._active():
                self._record(module, name, days)
        self.check(sources=["picklescan"], fail_on=fail_on)

    @rule(
        pick=st.integers(min_value=0, max_value=7),
        fail_on=st.none() | st.sampled_from(SEVERITIES),
        fresh=st.booleans(),
    )
    def lapse_and_check(self, pick: int, fail_on: str | None, fresh: bool = False) -> None:
        """Let the first expiring exception expire, or else revoke one; with ``fresh`` record an
        exception for a global left uncovered, which must wait; then ask OSV only."""
        ends = [e["expires_on"] for e in self.exceptions.values() if self._is_active(e)]
        ends = [day for day in ends if day is not None]
        if ends:
            self.now = datetime.combine(min(ends) + timedelta(days=1), NOW.timetz())
        else:
            self.revoke(pick=pick)
        if fresh:
            active = self._active()
            for module, name, _ in FILES[self.file][1]:
                if (self._sha(), f"{module}.{name}") not in active:
                    self._record(module, name, None)
                    break
        self.check(sources=["osv"], fail_on=fail_on)

    @rule(
        sources=st.lists(st.sampled_from(SOURCES), min_size=1, max_size=3, unique=True),
        fail_on=st.none() | st.sampled_from(SEVERITIES),
        everything=st.booleans(),
    )
    def check(self, sources: list[str], fail_on: str | None, everything: bool = False) -> None:
        before = {a["alert_id"]: a for a in self._alerts()}
        argv = ["check", "--all" if everything else MODEL, "--source", ",".join(sources)]
        if fail_on is not None:
            argv += ["--fail-on", fail_on.lower()]
        code, checked = self.cli(*argv)
        self.last = (code, checked)
        assert code in (0, 2, 4), (code, checked)
        # (b) only OSV can fail, and a failed source decides the exit, both ways
        failed = any(status.startswith("failed") for status in checked["sources"].values())
        assert failed == ("osv" in sources and self.osv_down), checked["sources"]
        assert (code == 2) == failed, (code, checked["sources"])
        if fail_on is None:
            assert code != 4 and "gate" not in checked
        else:
            gate = checked["gate"]
            assert gate["decided_exit"] is (not failed)
            # (a) and (b): the gate counts exactly the open alerts at or above the severity that
            # are not excepted
            gating = {
                a["alert_id"]
                for a in self._alerts()
                if a["state"] == "open"
                and not a["excepted_at"]
                and severity_rank(a["severity"]) <= severity_rank(fail_on)
            }
            assert {a["alert_id"] for a in gate["alerts"]} == gating, (gate, gating)
            # FR-021: hf-scan reads hub files only and this model has none; a failed OSV reads
            # nothing; a model registered from a record has no weights on disk for picklescan.
            unchecked = "picklescan" not in sources and ("osv" not in sources or self.osv_down)
            assert gate["unchecked"] == ([MODEL] if unchecked else []), (sources, gate)
            incomplete = self.from_record and "picklescan" in sources
            want = [{"model_id": MODEL, "source": "picklescan"}] if incomplete else []
            assert gate["incomplete"] == want, (sources, gate)
            assert not gate["empty_scope"]
            tripped = bool(gating) or unchecked or incomplete
            assert gate["tripped"] is tripped, gate
            if not failed:
                assert code == (4 if tripped else 0), (code, gate)
        self._after_check(set(sources), before)

    @rule(fail_on=st.none() | st.sampled_from(SEVERITIES))
    def check_without_weight_sources(self, fail_on: str | None) -> None:
        """A pipeline gating on packages only: nothing here asks a weight source."""
        self.check(sources=["osv"], fail_on=fail_on)

    # -- checks after a run --

    def _after_check(self, sources: set[str], before: dict[int, dict[str, Any]]) -> None:
        alerts = self._alerts()
        new = [a for a in alerts if a["alert_id"] not in before]
        active = self._active()
        expected = self._expected_unlisted()
        weight_asked = bool(sources & WEIGHT_SOURCES)
        with self._store() as store:
            scanned = store.latest_file_scan(self._sha()) is not None
        # (e) excepted exactly when the model's active exceptions cover every dangerous global
        for alert in alerts:
            if alert["state"] != "open":
                continue
            sha = alert["cause"].get("identifier", "").removeprefix("sha256:")
            names = set(alert["cause"].get("dangerous") or [])
            covered = bool(names) and all((sha, name) in active for name in names)
            if alert["excepted_at"]:
                assert covered, (alert["cause"], active)
            elif weight_asked and alert["kind"] == "weight_file_scan":
                assert not covered, (alert["cause"], active)
        # (c) a dismissal holds unless the evidence is new
        for key, gone in list(self.dismissed.items()):
            reopened = [a for a in new if a["cause_key"] == key]
            if gone["kind"] in ("weight_file_scan", "package_advisory"):
                assert not reopened, (key, reopened)
            elif (
                gone["kind"] == "globals_policy"
                and weight_asked
                and self.strict
                and scanned
                and key.endswith(self._sha())
            ):
                grew = bool(expected - gone["unlisted"])
                assert bool(reopened) == grew, (key, expected, gone, reopened)
            if reopened:
                del self.dismissed[key]
        # (g) FR-010 and the round 2 ruling: outside a weight check only a lapsed exception acts
        # (lifecycle.py, _apply_globals_rules with apply_new=False and _apply_globals_policy with
        # lapse_only), so nothing becomes excepted and no globals policy list shrinks or closes
        if not weight_asked:
            open_now = {a["cause_key"]: a for a in alerts if a["state"] == "open"}
            for alert in open_now.values():
                if alert["excepted_at"]:
                    prior = before.get(alert["alert_id"])
                    assert prior is not None and prior["excepted_at"], (alert, prior)
            for prior in before.values():
                if prior["state"] != "open" or prior["kind"] != "globals_policy":
                    continue
                after = open_now.get(prior["cause_key"])
                assert after is not None, (prior, sorted(open_now))
                kept = set(prior["cause"]["unlisted"])
                assert kept <= set(after["cause"]["unlisted"]), (prior["cause"], after["cause"])
            self._judge_against_mark(alerts, before, scanned)
        # (d) the globals policy lists exactly what is neither safe-listed nor excepted
        key = f"globals_policy:{self._sha()}"
        policy_open = [a for a in alerts if a["state"] == "open" and a["kind"] == "globals_policy"]
        live = [a for a in policy_open if a["cause_key"] == key]
        if weight_asked and not self.strict:
            assert not policy_open, policy_open  # FR-010: the default policy clears them
            self.strict_scan = None
        elif weight_asked:
            assert all(a["cause_key"] == key for a in policy_open), policy_open
            self.strict_scan = self._sha() if scanned else None
            if scanned and not (key in self.dismissed and not live):
                if expected:
                    assert len(live) == 1, (live, expected)
                    assert set(live[0]["cause"]["unlisted"]) == expected, (live, expected)
                else:
                    assert not live, live
        elif (
            self.strict
            and self.strict_scan == self._sha()
            and key not in self.dismissed
            and self._mark_matches()
        ):
            # Round 2: a lapsed exception's global is back at a packages-only check; one recorded
            # since the last weight check waits for the next, so the list may be longer ((g) pins
            # that it never shrinks).
            if expected:
                assert len(live) == 1, (live, expected)
                assert expected <= set(live[0]["cause"]["unlisted"]), (live, expected)
        if weight_asked:
            self.mark = {
                "policy": (self.strict, self.policy_set_at),
                "ids": {i for i, e in self.exceptions.items() if self._is_active(e)},
            }

    def _mark_matches(self) -> bool:
        return self.mark is not None and self.mark["policy"] == (self.strict, self.policy_set_at)

    def _policy_view(self, alerts: Any) -> set[tuple[str, tuple[str, ...]]]:
        return {
            (a["cause_key"], tuple(sorted(a["cause"]["unlisted"])))
            for a in alerts
            if a["state"] == "open" and a["kind"] == "globals_policy"
        }

    def _judge_against_mark(
        self, alerts: list[dict[str, Any]], before: dict[int, dict[str, Any]], scanned: bool
    ) -> None:
        """(g) at a check without a weight source, against the model's record of the last one."""
        key = f"globals_policy:{self._sha()}"
        if not (self.strict and self._mark_matches() and scanned):
            # no record, a policy changed since, the default policy or no scan: nothing changes
            assert self._policy_view(alerts) == self._policy_view(before.values()), key
            return
        if key in self.dismissed:
            return  # a held dismissal decides; (c) judges it at the next weight check
        assert self.mark is not None
        applied = self.mark["ids"]
        sha = self._sha()
        live = {
            e["global"] for i, e in self.exceptions.items()
            if i in applied and e["sha"] == sha and self._is_active(e)
        }  # fmt: skip
        lapsed = {
            e["global"] for i, e in self.exceptions.items()
            if i in applied and e["sha"] == sha and not self._is_active(e)
        }  # fmt: skip
        want = {f"{m}.{n}" for m, n, _ in FILES[self.file][1] if (m, n) not in SAFE} - live
        prior = [a for a in before.values() if a["state"] == "open" and a["cause_key"] == key]
        now = [a for a in alerts if a["state"] == "open" and a["cause_key"] == key]
        base = set(prior[0]["cause"]["unlisted"]) if prior else set()
        if (want - base) & lapsed:
            assert len(now) == 1 and set(now[0]["cause"]["unlisted"]) == want, (now, want)
        elif prior:
            assert len(now) == 1 and set(now[0]["cause"]["unlisted"]) == base, (now, base)
        else:
            assert not now, (now, want, lapsed)

    def _held_invariant(self) -> None:
        """Registration applies a record's scans: the same bytes never reopen a dismissal."""
        for key, gone in self.dismissed.items():
            if gone["kind"] == "weight_file_scan":
                reopened = [
                    a for a in self._alerts() if a["cause_key"] == key and a["state"] == "open"
                ]
                assert not reopened, (key, reopened)

    # -- after every step --

    @invariant()
    def excepted_never_counts_as_open(self) -> None:
        # (a) judged against the store's own columns, not the product's helper that reads them
        stored = [a for a in self._alerts() if a["state"] == "open"]
        is_open = {a["alert_id"] for a in stored if not a["excepted_at"]}
        excepted = {a["alert_id"] for a in stored if a["excepted_at"]}
        listed = self.ok("alerts", MODEL)
        assert {a["alert_id"] for a in listed["alerts"]} == is_open, (listed, is_open)
        assert {a["alert_id"] for a in listed["excepted"]} == excepted, (listed, excepted)
        audit = self.ok("inventory", "audit", MODEL)
        assert audit["summary"]["alerts_open"] == len(is_open), audit["summary"]
        assert audit["summary"]["alerts_excepted"] == len(excepted), audit["summary"]

    @invariant()
    def one_open_alert_per_cause_and_evidence(self) -> None:
        # (f)
        with self._store() as store:
            alerts = store.alerts_for(MODEL)
            keys = [a["cause_key"] for a in alerts if a["state"] == "open"]
            assert len(keys) == len(set(keys)), keys
            for alert in alerts:
                assert store.alert_evidence(alert["alert_id"]), alert["cause_key"]


EXPLORE = os.environ.get("MODEL_DEPENDABOT_PROPERTY_EXAMPLES") or None
ScanPolicyMachine.TestCase.settings = settings(
    # Every step runs the command line, so the default run is ten derandomised sequences. This
    # whole file took between about 60 and 160 seconds on one development machine and longer on
    # the same machine under load; wall time varies widely, mostly with SQLite file I/O. The ten
    # sequences are derived from the source of the machine class, so any edit inside the class
    # replaces them all: after such an edit, check again that the default run still excepts,
    # expires and holds (the guided tour below pins those states whatever the sequences are).
    max_examples=int(EXPLORE or "10"),
    stateful_step_count=20,
    deadline=None,
    derandomize=EXPLORE is None,
    database=None,
    suppress_health_check=[HealthCheck.too_slow],
)
TestScanPolicyMachine = ScanPolicyMachine.TestCase

CUSTOM_LAYER = "model_dependabot_fixture.layers.CustomLayer"


def test_the_machine_reaches_excepted_held_and_gated_states() -> None:
    """The world above does except, hold, lapse and gate, so the properties are not vacuous.

    After every step the two invariants run as well, as they do in the random run. The asserts
    pin states in a fixed order: a new exception waiting at a packages-only check while a revoked
    one returns its global (FR-010), an exception that covers only its own SHA-256 (FR-002), a
    held ``globals_policy`` dismissal under a re-applied policy (K2), a lapsed exception at a
    packages-only check (K5), an expiry that turns exit 0 into exit 4, a policy set strict that
    waits even for a lapse and a lapse that opens the alert while its re-recorded exception waits
    (both review 3), the refusals of an
    unresolved global and of a past expiry, the default policy clearing the alert, an unchecked
    model and an incomplete source.
    """
    machine = ScanPolicyMachine()

    def step(rule: Any, **kwargs: Any) -> None:
        rule(**kwargs)
        machine.excepted_never_counts_as_open()
        machine.one_open_alert_per_cause_and_evidence()

    def open_alerts(kind: str) -> list[dict[str, Any]]:
        return [a for a in machine._alerts() if a["state"] == "open" and a["kind"] == kind]

    def unlisted() -> set[str]:
        live = open_alerts("globals_policy")
        assert len(live) == 1, live
        return set(live[0]["cause"]["unlisted"])

    def weight_alert() -> dict[str, Any]:
        key = f"weight_file_scan:{machine._sha()}"
        live = [a for a in open_alerts("weight_file_scan") if a["cause_key"] == key]
        assert len(live) == 1, live
        return live[0]

    try:
        step(machine.check, sources=["hf-scan"], fail_on="LOW")
        code, checked = machine.last
        assert code == 4 and checked["gate"]["unchecked"] == [MODEL]
        step(machine.globals, strict=True)
        step(machine.check, sources=["picklescan", "osv"], fail_on=None)
        kinds = {a["kind"] for a in machine._alerts() if a["state"] == "open"}
        assert {"weight_file_scan", "globals_policy", "package_advisory"} <= kinds
        assert unlisted() == {CUSTOM_LAYER, "os.system"}
        step(machine.record_exception, pick=1, days=None)  # 1: CustomLayer in the mixed file
        step(machine.check, sources=["picklescan"], fail_on=None)
        assert unlisted() == {"os.system"}
        # FR-010: at a packages-only check the revoked exception's global is back, while the new
        # one for os.system waits for a check that asks a weight source
        step(machine.record_exception, pick=2, days=None)  # 2: os.system
        step(machine.revoke, pick=0)  # 1
        step(machine.check, sources=["osv"], fail_on=None)
        assert unlisted() == {CUSTOM_LAYER, "os.system"}
        assert not weight_alert()["excepted_at"]
        step(machine.check, sources=["picklescan"], fail_on=None)
        assert unlisted() == {CUSTOM_LAYER}
        assert weight_alert()["excepted_at"]
        # FR-002: exception 2 covers os.system in the mixed file only
        step(machine.register, file="dangerous", folder="a", via_record=False)
        step(machine.check, sources=["picklescan"], fail_on=None)
        assert not weight_alert()["excepted_at"]
        step(machine.register, file="mixed", folder="a", via_record=False)
        step(machine.check, sources=["picklescan"], fail_on=None)
        assert weight_alert()["excepted_at"] and unlisted() == {CUSTOM_LAYER}
        # FR-010: the default policy clears the alert; strict raises it again
        step(machine.globals, strict=False)
        step(machine.check, sources=["picklescan"], fail_on=None)
        assert not open_alerts("globals_policy")
        step(machine.globals, strict=True)
        step(machine.check, sources=["picklescan"], fail_on="HIGH")
        assert unlisted() == {CUSTOM_LAYER}
        # K2: neither re-applying the same policy nor default and back reopens the dismissal
        step(machine.dismiss, pick=0, kind="globals_policy")
        step(machine.globals, strict=True)
        step(machine.check, sources=["picklescan"], fail_on=None)
        assert not open_alerts("globals_policy")
        step(machine.globals, strict=False)
        step(machine.check, sources=["picklescan"], fail_on=None)
        step(machine.globals, strict=True)
        step(machine.check, sources=["picklescan", "osv"], fail_on=None)
        assert not open_alerts("globals_policy")
        # K5: the revoked exception's global is back at a packages-only check, past the dismissal
        step(machine.revoke, pick=0)  # 2
        step(machine.check, sources=["osv"], fail_on=None)
        assert unlisted() == {CUSTOM_LAYER, "os.system"}
        assert f"globals_policy:{machine._sha()}" not in machine.dismissed
        # Dismissed advisories hold, so below the exceptions decide the exit
        while open_alerts("package_advisory"):
            step(machine.dismiss, pick=0, kind="package_advisory")
        step(machine.check, sources=["osv"], fail_on=None)
        assert not open_alerts("package_advisory")
        # Exceptions expiring today cover the whole day; a second one for the pair is refused, as
        # are a past expiry and an unresolved global
        step(machine.record_exception, pick=1, days=0)
        step(machine.record_exception, pick=2, days=0)  # os.system
        step(machine.record_exception, pick=2, days=None)
        step(machine.record_exception, pick=0, days=-1)
        code, _ = machine.cli(
            "exception", "record", "--global", "unknown.eval", "--sha256", machine._sha(),
            "--reason", "r", "--by", "O",
        )  # fmt: skip
        assert code == 1
        step(machine.check, sources=["picklescan"], fail_on="HIGH")
        assert weight_alert()["excepted_at"] and not open_alerts("globals_policy")
        assert machine.last[0] == 0
        # The next day both have expired: the finding and the globals are back without a scan
        step(machine.advance, days=1)
        step(machine.check, sources=["osv"], fail_on="HIGH")
        assert not weight_alert()["excepted_at"]
        assert unlisted() == {CUSTOM_LAYER, "os.system"}
        assert machine.last[0] == 4
        # K4: identical bytes from a fresh record never reopen a dismissal
        assert open_alerts("weight_file_scan") == [weight_alert()]
        step(machine.dismiss, pick=0, kind="weight_file_scan")
        step(machine.check, sources=["picklescan", "osv"], fail_on="CRITICAL")
        step(machine.register, file="mixed", folder="b", via_record=True)
        step(machine.check, sources=["osv"], fail_on="LOW", everything=True)
        step(machine.check, sources=["picklescan"], fail_on="CRITICAL")
        code, checked = machine.last
        assert code == 4
        assert checked["gate"]["incomplete"] == [{"model_id": MODEL, "source": "picklescan"}]

        def record(pick: int) -> int:
            step(machine.record_exception, pick=pick, days=None)
            return max(machine.exceptions)

        def revoke(exception_id: int) -> None:
            machine.ok("exception", "revoke", str(exception_id), "--reason", "r", "--by", "O")
            machine.exceptions[exception_id]["revoked"] = True
            machine.excepted_never_counts_as_open()
            machine.one_open_alert_per_cause_and_evidence()

        alpha, beta = ".".join(ALPHA), ".".join(BETA)
        # Review 3: a policy set strict since the last weight check waits, even for a lapse
        step(machine.register, file="two", folder="c", via_record=False)
        step(machine.globals, strict=False)
        first = record(0)  # Alpha in the two file
        step(machine.check, sources=["picklescan"], fail_on=None)
        step(machine.globals, strict=True)
        revoke(first)
        step(machine.check, sources=["osv"], fail_on="MODERATE")
        assert not open_alerts("globals_policy")
        step(machine.check, sources=["picklescan"], fail_on=None)
        assert unlisted() == {alpha, beta}
        # Review 3: with every global covered, a lapse opens the alert while the exception
        # recorded again for the same global waits for a weight check
        second = record(0)
        record(1)  # Beta
        step(machine.check, sources=["picklescan"], fail_on=None)
        assert not open_alerts("globals_policy")
        revoke(second)
        record(0)
        step(machine.check, sources=["osv"], fail_on=None)
        assert unlisted() == {alpha}
        step(machine.check, sources=["picklescan"], fail_on=None)
        assert not open_alerts("globals_policy")
    finally:
        machine.teardown()

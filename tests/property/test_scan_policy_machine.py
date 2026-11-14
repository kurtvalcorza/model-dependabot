"""State-machine tests of feature 004: exceptions, the globals policy, held dismissals and the gate.

A sibling of ``test_alert_lifecycle_machine.py``. Hypothesis drives one model through the command
line (``cli.main``, an injected clock, recorded or failing OSV answers) with random sequences of:
registering one of three crafted pickles from one of three folders or from a registration record,
dismissing an alert, recording an exception (optionally expiring) or revoking one, setting the
globals policy, advancing the clock, letting OSV fail or answer, and checking a random subset of
sources with or without ``--fail-on``. The pickles are opcode bytes built by
``tests/fixtures/pickles/craft.py``; nothing is ever loaded and nothing reaches the network.

After every check these hold:

a. an excepted alert never counts as open: not in ``alerts``, not in the audit's ``alerts_open``
   and not in the gate;
b. the gate: a failed source exits 2; exit 0 with ``--fail-on`` means nothing tripped it (no alert
   at or above the severity, no incomplete source, no unchecked model, a scope that matched); exit 4
   only with ``--fail-on``;
c. a dismissal holds unless the evidence is new: the same bytes (from any folder or record) and the
   same advisory never reopen a dismissed alert, while a globals list that grows past the list at
   dismissal does reopen it;
d. after a check that asks a weight source under the strict policy, the ``globals_policy`` alert of
   the current file lists exactly its scanned globals that are neither on the safe list nor
   excepted;
e. an alert marked excepted is covered by exceptions active at the check's time, so a lapsed
   exception's finding is back by the next check of any sources;
f. at most one open alert per cause, and every alert has evidence.

The default run is derandomised and short; ``MODEL_DEPENDABOT_PROPERTY_EXAMPLES`` set to a number
runs that many random sequences instead.
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
        # cause_key -> what the dismissed alert stood on: its id and, for a globals policy
        # alert, its list at dismissal.
        self.dismissed: dict[str, dict[str, Any]] = {}
        self.versions = 0
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
        self.file = file
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

    @rule(pick=st.integers(min_value=0, max_value=3), days=st.none() | st.integers(0, 3))
    def record_exception(self, pick: int, days: int | None) -> None:
        names = [(m, n) for m, n, _ in FILES[self.file][1]]
        module, name = names[pick % len(names)]
        argv = ["exception", "record", "--global", f"{module}:{name}", "--sha256", self._sha()]
        argv += ["--reason", "reviewed", "--by", "O"]
        if days is not None:
            argv += ["--expires", (self.now + timedelta(days=days)).date().isoformat()]
        code, _ = self.cli(*argv)
        assert code in (0, 1)  # refused while an active exception covers the same pair

    @rule(pick=st.integers(min_value=0, max_value=7))
    def revoke(self, pick: int) -> None:
        _, listed = self.cli("exception", "list")
        if not listed["exceptions"]:
            return
        item = listed["exceptions"][pick % len(listed["exceptions"])]
        self.ok("exception", "revoke", str(item["exception_id"]), "--reason", "r", "--by", "O")

    @rule(strict=st.booleans())
    def globals(self, strict: bool) -> None:
        self.ok("policy", MODEL, "--globals", "strict" if strict else "default", "--by", "O")
        self.strict = strict

    @rule(days=st.integers(min_value=1, max_value=20))
    def advance(self, days: int) -> None:
        self.now += timedelta(days=days)

    @rule(down=st.booleans())
    def osv(self, down: bool) -> None:
        self.osv_down = down

    @rule(
        sources=st.lists(st.sampled_from(SOURCES), min_size=1, max_size=3, unique=True),
        fail_on=st.none() | st.sampled_from(SEVERITIES),
    )
    def check(self, sources: list[str], fail_on: str | None) -> None:
        before = {a["alert_id"] for a in self._alerts()}
        argv = ["check", MODEL, "--source", ",".join(sources)]
        if fail_on is not None:
            argv += ["--fail-on", fail_on.lower()]
        code, checked = self.cli(*argv)
        assert code in (0, 2, 4), (code, checked)
        failed = any(status.startswith("failed") for status in checked["sources"].values())
        # (b)
        if failed:
            assert code == 2, code
        if fail_on is None:
            assert code != 4 and "gate" not in checked
        else:
            gate = checked["gate"]
            assert gate["decided_exit"] is (not failed)
            if code == 0:
                assert not gate["tripped"]
                assert not (gate["alerts"] or gate["incomplete"] or gate["unchecked"])
                assert not gate["empty_scope"]
                for alert in self._alerts():
                    if alert["state"] == "open" and not alert["excepted_at"]:
                        assert severity_rank(alert["severity"]) > severity_rank(fail_on), alert
            if code == 4:
                assert gate["tripped"] and gate["decided_exit"]
            # (a): the gate never counts an excepted alert
            excepted = {a["alert_id"] for a in self._alerts() if a["excepted_at"]}
            assert not excepted & {a["alert_id"] for a in gate["alerts"]}
        self._after_check(set(sources), before)

    @rule(fail_on=st.none() | st.sampled_from(SEVERITIES))
    def check_without_weight_sources(self, fail_on: str | None) -> None:
        """A pipeline gating on packages only: nothing here asks a weight source."""
        self.check(sources=["osv"], fail_on=fail_on)

    # -- checks after a run --

    def _expected_unlisted(self, store: Store) -> set[str]:
        active = store.exceptions(self._sha())
        return {
            f"{m}.{n}"
            for m, n, _ in FILES[self.file][1]
            if (m, n) not in SAFE and not any(e["module"] == m and e["name"] == n for e in active)
        }

    def _after_check(self, sources: set[str], before: set[int]) -> None:
        alerts = self._alerts()
        new = [a for a in alerts if a["alert_id"] not in before]
        with self._store() as store:
            expected = self._expected_unlisted(store)
            scanned = store.latest_file_scan(self._sha()) is not None
            # (e) every excepted alert is covered by exceptions active now
            for alert in alerts:
                if alert["state"] == "open" and alert["excepted_at"]:
                    sha = alert["cause"]["identifier"].removeprefix("sha256:")
                    active = {f"{e['module']}.{e['name']}" for e in store.exceptions(sha)}
                    assert set(alert["cause"]["dangerous"]) <= active, (alert["cause"], active)
        # (c) a dismissal holds unless the evidence is new
        weight_asked = bool(sources & WEIGHT_SOURCES)
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
        # (d) the globals policy lists exactly what is neither safe-listed nor excepted
        if weight_asked and self.strict and scanned:
            key = f"globals_policy:{self._sha()}"
            live = [a for a in alerts if a["state"] == "open" and a["cause_key"] == key]
            if key in self.dismissed and not live:
                return
            if expected:
                [alert] = live
                assert set(alert["cause"]["unlisted"]) == expected, (alert["cause"], expected)
            else:
                assert not live, live

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
        # (a)
        listed = self.ok("alerts", MODEL)
        assert all(a["state"] == "open" for a in listed["alerts"])
        assert all(a["state"] == "excepted" for a in listed["excepted"])
        audit = self.ok("inventory", "audit", MODEL)
        assert audit["summary"]["alerts_open"] == len(listed["alerts"])
        assert audit["summary"]["alerts_excepted"] == len(listed["excepted"])

    @invariant()
    def one_open_alert_per_cause_and_evidence(self) -> None:
        # (f)
        with self._store() as store:
            alerts = store.alerts_for(MODEL)
            keys = [a["cause_key"] for a in alerts if a["state"] == "open"]
            assert len(keys) == len(set(keys)), keys
            for alert in alerts:
                assert store.alert_evidence(alert["alert_id"]), alert["cause_key"]


EXPLORE = os.environ.get("MODEL_DEPENDABOT_PROPERTY_EXAMPLES")
ScanPolicyMachine.TestCase.settings = settings(
    # The default run stays short (about a minute). On the code before the pull request review
    # fixes, the guided tour below caught a dismissal reopened by identical bytes from a fresh
    # record (round 1, K4); deeper random searches (``MODEL_DEPENDABOT_PROPERTY_EXAMPLES=150`` and
    # up) also found a re-asserted policy reopening a dismissal (K2) and an expired exception still
    # silencing its alert at a packages-only check (K5).
    max_examples=int(EXPLORE or "20"),
    stateful_step_count=20,
    deadline=None,
    derandomize=EXPLORE is None,
    database=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
)
TestScanPolicyMachine = ScanPolicyMachine.TestCase


def test_the_machine_reaches_excepted_held_and_gated_states() -> None:
    """The world above does except, hold and gate, so the properties are not vacuous."""
    machine = ScanPolicyMachine()
    try:
        machine.globals(strict=True)
        machine.check(sources=["picklescan", "osv"], fail_on=None)
        kinds = {a["kind"] for a in machine._alerts() if a["state"] == "open"}
        assert {"weight_file_scan", "globals_policy", "package_advisory"} <= kinds
        machine.record_exception(pick=2, days=None)  # os.system in the mixed file
        machine.check(sources=["picklescan"], fail_on="HIGH")
        assert any(a["excepted_at"] for a in machine._alerts())
        machine.dismiss(pick=0)
        machine.check(sources=["picklescan", "osv"], fail_on="CRITICAL")
        machine.register(file="mixed", folder="b", via_record=True)
        machine.check(sources=["osv"], fail_on="LOW")
    finally:
        machine.teardown()

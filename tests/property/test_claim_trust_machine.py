"""State-machine test of the claim trust rule (T053; SC-001, FR-004, research A1 to A3).

Hypothesis drives one model through random sequences of: registering a new version as ``register``
and ``import`` do (stored, then the open alerts settled against it): imported, manifest-registered
or a legacy version with no origin, holding a pickle and a sibling claimed
code-free whose real bytes are a well-formed safetensors file, a pickle or missing; changing the
format policy; and running a check with ``picklescan`` and ``format-check``, or with
``picklescan`` alone. Every file is local, so nothing reaches the network.

After every check, under the strict policy, a sibling whose claim needs confirmation and whose
latest claim check is not ``confirmed`` never suppresses the ``format_policy`` alert on the
pickle. And a claim is only ever ``confirmed`` when its bytes really are code-free.

The default search is derandomised, so the default run is reproducible. Setting
``MODEL_DEPENDABOT_PROPERTY_EXAMPLES`` to a number runs that many random sequences instead.
"""

from __future__ import annotations

import hashlib
import importlib.util
import os
import shutil
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from hypothesis import HealthCheck, settings
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, invariant, rule

from model_dependabot.assurance.trust import needs_confirmation
from model_dependabot.lifecycle import reevaluate_version, run_check
from model_dependabot.sources.fetcher import RecordedFetcher
from model_dependabot.store import Store

MODEL = "m"
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
TINY = (FIXTURES / "manifests" / "weights" / "tiny.safetensors").read_bytes()
START = datetime(2026, 11, 13, tzinfo=UTC)
# Which origin each registration route records, and the format origin of its entries.
ROUTES = {"import": ("import", "import"), "manifest": ("manifest", "bytes"), "legacy": (None, None)}
SIBLING_BYTES = ("safetensors", "pickle", "missing")


def _craft() -> Any:
    spec = importlib.util.spec_from_file_location(
        "craft_pickles", FIXTURES / "pickles" / "craft.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PICKLE = _craft().innocuous()  # built, never loaded
PICKLE_ID = f"sha256:{hashlib.sha256(PICKLE).hexdigest()}"


def _entry(name: str, data: bytes, file_format: str, code: bool, origin: str | None):
    return {
        "kind": "weight_file",
        "identifier": f"sha256:{hashlib.sha256(data).hexdigest()}",
        "pinned": True,
        "location": name,
        "size": len(data),
        "format": file_format,
        "can_run_code": code,
        "format_origin": origin,
    }


class ClaimTrust(RuleBasedStateMachine):
    def __init__(self) -> None:
        super().__init__()
        self.directory = Path(tempfile.mkdtemp(prefix="claim-trust-"))
        self.clock = START
        self.store = Store(self.directory / "md.db", now=lambda: self.clock)
        self.store.add_model(MODEL)
        self.fetcher = RecordedFetcher(self.directory / "no-recordings")
        self.versions = 0
        self.policy = "default"
        self.checked = False  # whether a check has run since the last change
        self.real_bytes: dict[str, str] = {}  # sibling identifier -> what its bytes are

    def teardown(self) -> None:
        self.store.close()
        shutil.rmtree(self.directory, ignore_errors=True)

    def _tick(self) -> None:
        self.clock += timedelta(minutes=1)

    @rule(route=st.sampled_from(sorted(ROUTES)), sibling=st.sampled_from(SIBLING_BYTES))
    def new_version(self, route: str, sibling: str) -> None:
        origin, format_origin = ROUTES[route]
        if route == "manifest":
            sibling = "safetensors"  # registration measured it: a manifest claim is the bytes'
        self.versions += 1
        base = self.directory / f"v{self.versions}"
        base.mkdir()
        (base / "model.pt").write_bytes(PICKLE)
        claimed = {"safetensors": TINY, "pickle": PICKLE + b"\x00", "missing": TINY + b"\x00"}
        data = claimed[sibling]
        if sibling != "missing":
            (base / "claimed.safetensors").write_bytes(data)
        entries = [
            _entry("model.pt", PICKLE, "pickle", True, format_origin),
            _entry("claimed.safetensors", data, "safetensors", False, format_origin),
        ]
        self.real_bytes[entries[1]["identifier"]] = sibling
        self._tick()
        version = self.store.add_version(MODEL, {}, "0" * 64, entries, base_dir=base, origin=origin)
        reevaluate_version(self.store, MODEL, version)  # as register and import do
        self.checked = False

    @rule(policy=st.sampled_from(("default", "strict")))
    def set_policy(self, policy: str) -> None:
        self._tick()
        self.store.set_format_policy(MODEL, policy, set_by="Owner")
        self.policy = policy
        self.checked = False

    @rule(confirm=st.booleans())
    def check(self, confirm: bool) -> None:
        if not self.versions:
            return
        self._tick()
        sources = ["picklescan", "format-check"] if confirm else ["picklescan"]
        run_check(self.store, self.fetcher, [MODEL], sources)
        self.checked = True

    def sibling(self) -> tuple[int, dict[str, Any], str | None]:
        version = self.store.latest_version(MODEL)
        assert version is not None
        origin = self.store.get_version(MODEL, version)["origin"]
        entries = self.store.entries(MODEL, version)
        found = next(e for e in entries if e["location"] == "claimed.safetensors")
        return version, found, origin

    def policy_alerts(self) -> list[dict[str, Any]]:
        return [
            alert
            for alert in self.store.alerts_for(MODEL, ["open"])
            if alert["kind"] == "format_policy" and alert["cause"]["identifier"] == PICKLE_ID
        ]

    @invariant()
    def an_unconfirmed_claim_never_suppresses_the_alert(self) -> None:
        if not (self.versions and self.checked and self.policy == "strict"):
            return
        version, sibling, origin = self.sibling()
        if not needs_confirmation(sibling, origin):
            return
        latest = self.store.latest_claim_check(MODEL, version, sibling["identifier"])
        if latest is not None and latest["outcome"] == "confirmed":
            return
        assert self.policy_alerts(), (origin, latest)

    @invariant()
    def only_code_free_bytes_are_confirmed(self) -> None:
        for version in range(1, self.versions + 1):
            for check in self.store.claim_checks(MODEL, version):
                if check["claim"] == "code_free" and check["outcome"] == "confirmed":
                    assert self.real_bytes[check["entry_identifier"]] == "safetensors", check


def test_the_machine_reaches_both_sides_of_the_rule() -> None:
    """An imported forgery keeps the alert open; a confirmed real sibling suppresses it, so the
    invariant is not satisfied vacuously."""
    machine = ClaimTrust()
    try:
        machine.set_policy(policy="strict")
        machine.new_version(route="import", sibling="pickle")
        machine.check(confirm=True)
        machine.an_unconfirmed_claim_never_suppresses_the_alert()
        assert machine.policy_alerts()
        machine.new_version(route="import", sibling="safetensors")
        machine.check(confirm=True)
        version, sibling, _ = machine.sibling()
        latest = machine.store.latest_claim_check(MODEL, version, sibling["identifier"])
        assert latest is not None and latest["outcome"] == "confirmed"
        assert machine.policy_alerts() == []
    finally:
        machine.teardown()


EXPLORE = os.environ.get("MODEL_DEPENDABOT_PROPERTY_EXAMPLES")
ClaimTrust.TestCase.settings = settings(
    max_examples=int(EXPLORE or "60"),
    stateful_step_count=12,
    deadline=None,
    derandomize=EXPLORE is None,
    database=None,
    suppress_health_check=[HealthCheck.too_slow],
)
TestClaimTrust = ClaimTrust.TestCase

"""State-machine tests of the alert lifecycle (2026-10-25 review, methodology point 1).

Hypothesis drives one model through random sequences of three kinds of step: registering a new
version (the same pins, another revision of the same repository, a gap, a different repository or
the dependency dropped), changing what a source answers (an OSV advisory listed or withdrawn, a
base model or hub dataset disabled or enabled, the base model's licence changed or reverted, a
dataset's or a tied paper's retraction listed or gone, a dataset licence changed or reverted at
DataCite or Figshare) and running a check with each source
``ok``, failed or not selected (``--source``). Every answer is built in memory from a recording
under ``tests/fixtures``; nothing reaches the network.

After every step the store is compared with a small model of the identity and clearance table in
``specs/002-upstream-watch/data-model.md`` (which cause keys are open), and these invariants hold:

a. an alert never closes on a check run in which the source that owns its cause failed or was not
   selected;
b. a gap never yields ``fixed``;
c. a repository-scoped cause is never ``fixed`` while the new version still depends on that
   repository;
d. at most one open alert per cause key;
e. every close has evidence linked in that step, from the source that closed it (constitution I);
f. ``withdrawn`` comes only from an OSV record that says the advisory is withdrawn.

The default search is derandomised, so the default run is reproducible. Setting
``MODEL_DEPENDABOT_PROPERTY_EXAMPLES`` to a number runs that many random sequences instead.
"""

from __future__ import annotations

import copy
import json
import os
import shutil
import tempfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from hypothesis import HealthCheck, settings
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, invariant, rule

from conftest import fixture_json
from model_dependabot.lifecycle import package_cause_key, reevaluate_version, run_check
from model_dependabot.sources.crossref import works_url
from model_dependabot.sources.datacite import doi_url
from model_dependabot.sources.fetcher import Response, SourceFailedError
from model_dependabot.sources.figshare import article_url
from model_dependabot.sources.hf import dataset_info_url, model_info_url
from model_dependabot.sources.osv import OSV_API
from model_dependabot.store import Store

NOW = datetime(2026, 10, 25, tzinfo=UTC)
MODEL = "m"

# --- the dependencies ---------------------------------------------------------------------------

ADVISORY = "GHSA-cp9v-662q-vvx9"  # pillow, introduced 12.0.0, fixed 13.0.0 (recorded)
PACKAGE_KEY = package_cause_key(ADVISORY, "pillow")
PACKAGE_STATES = ("12.3.0", "13.0.0", "gap", "absent")

REPO = "owner/model"
OTHER = "owner/other"
REPOS = (REPO, OTHER)
SHA_A = "a" * 40
SHA_B = "b" * 40
# (repository, revision): a revision of None is a gap naming the repository; None is no base model
BASE_STATES: tuple[tuple[str, str | None] | None, ...] = (
    (REPO, SHA_A),
    (REPO, SHA_B),
    (REPO, None),
    (OTHER, SHA_A),
    (OTHER, None),
    None,
)
HUB_LICENCES = ("mit", "apache-2.0")

RETRACTED_BODY = fixture_json("crossref/retracted")
DOI_R = RETRACTED_BODY["message"]["DOI"].lower()  # a dataset DOI registered with Crossref

FIGSHARE_BODY = fixture_json("figshare/cc-by-4.0")
ARTICLE = str(FIGSHARE_BODY["id"])
DOI_L = FIGSHARE_BODY["doi"].lower()  # a dataset DOI registered with DataCite, held by Figshare
RECORDED_LICENCE = "CC-BY-4.0"
DATASET_LICENCES = ("CC-BY-4.0", "MIT")

DATA_REPO = "owner/data"
HUB_STATES: tuple[str | None, ...] = (SHA_A, SHA_B, "gap", None)  # a revision, a gap or no dataset
PAPER = "10.1234/paper"  # a paper registered with Crossref, tied to the hub dataset by the owner

SOURCES = ("osv", "hf-hub", "crossref", "datacite", "figshare")
# The evidence ``source`` each check source writes, and the ``inventory`` evidence of a fix.
EVIDENCE_SOURCE = {
    "osv": "osv.dev",
    "hf-hub": "hf-hub",
    "crossref": "crossref",
    "datacite": "datacite",
    "figshare": "figshare",
}


def disabled_key(repo: str) -> str:
    return f"base_model_disabled:pkg:huggingface/{repo}"


def licence_key(repo: str) -> str:
    return f"licence_changed:pkg:huggingface/{repo}"


RETRACTED_KEY = f"dataset_retracted:{DOI_R}"
HUB_REMOVED_KEY = f"dataset_removed:hf-dataset:{DATA_REPO}"
PAPER_KEY = f"paper_retracted:hf-dataset:{DATA_REPO}:{PAPER}"
DATASET_LICENCE_KEY = f"licence_changed:{DOI_L}"


def package_entry(state: str) -> dict[str, Any] | None:
    if state == "absent":
        return None
    if state == "gap":
        return {"kind": "package", "name": "pillow", "pinned": False, "gap_reason": "no version"}
    return {
        "kind": "package",
        "identifier": f"pkg:pypi/pillow@{state}",
        "name": "pillow",
        "version": state,
        "pinned": True,
    }


def base_entry(state: tuple[str, str | None] | None) -> dict[str, Any] | None:
    if state is None:
        return None
    repo, revision = state
    if revision is None:
        return {"kind": "base_model", "name": repo, "pinned": False, "gap_reason": "no revision"}
    return {
        "kind": "base_model",
        "identifier": f"pkg:huggingface/{repo}@{revision}",
        "name": repo,
        "version": revision,
        "pinned": True,
    }


def inventory(inv: Inventory) -> list[dict[str, Any]]:
    entries = [package_entry(inv.package), base_entry(inv.base)]
    if inv.doi_r:
        entries.append({"kind": "dataset", "identifier": DOI_R, "pinned": True})
    if inv.doi_l:
        entries.append(
            {
                "kind": "dataset",
                "identifier": DOI_L,
                "pinned": True,
                "recorded_licence": RECORDED_LICENCE,
                "licence_form": "spdx",
            }
        )
    if inv.hub is not None:
        hub: dict[str, Any] = {"kind": "dataset", "hub_repo": DATA_REPO}
        if inv.hub == "gap":
            hub |= {"pinned": False, "gap_reason": "no revision"}
        else:
            hub |= {"identifier": f"hf-dataset:{DATA_REPO}@{inv.hub}", "pinned": True}
            hub["hub_revision"] = inv.hub
        if inv.tied:
            hub["paper_dois"] = [PAPER]
        entries.append(hub)
    return [entry for entry in entries if entry is not None]


@dataclass(frozen=True)
class Inventory:
    package: str
    base: tuple[str, str | None] | None
    doi_r: bool
    doi_l: bool
    hub: str | None = SHA_A
    tied: bool = True

    @property
    def hub_pinned(self) -> bool:
        return self.hub not in (None, "gap")

    def base_pinned_in(self, repo: str) -> bool:
        return self.base is not None and self.base[0] == repo and self.base[1] is not None

    def base_gap_in(self, repo: str) -> bool:
        return self.base is not None and self.base[0] == repo and self.base[1] is None


# --- what the sources answer ----------------------------------------------------------------------


@dataclass
class World:
    osv_listed: bool = True
    osv_withdrawn: bool = False
    disabled: dict[str, bool] = field(default_factory=lambda: dict.fromkeys(REPOS, False))
    hub_licence: dict[str, str] = field(default_factory=lambda: dict.fromkeys(REPOS, "mit"))
    retracted: bool = True
    hub_dataset_disabled: bool = True
    paper_retracted: bool = True
    datacite_licence: str = RECORDED_LICENCE
    figshare_licence: str = RECORDED_LICENCE


ADVISORY_BODY = fixture_json(f"osv/vuln-{ADVISORY}")
HUB_BODY = fixture_json("hf_upstream/model-normal")
DATACITE_BODY = fixture_json("datacite/findable")
HUB_DATASET_BODY = fixture_json("hf_upstream/dataset-disabled")


def osv_record(world: World) -> dict[str, Any]:
    record = copy.deepcopy(ADVISORY_BODY)
    if world.osv_withdrawn:
        record["withdrawn"] = "2026-10-25T00:00:00Z"
    return record


def hub_model(world: World, repo: str) -> dict[str, Any]:
    body = copy.deepcopy(HUB_BODY)
    body["id"] = repo
    body["disabled"] = world.disabled[repo]
    body["cardData"] = body["cardData"] | {"license": world.hub_licence[repo]}
    return body


def crossref_work(world: World, malformed: bool) -> dict[str, Any]:
    if malformed:
        return {"status": "ok", "message-type": "work", "message": []}
    body = copy.deepcopy(RETRACTED_BODY)
    if not world.retracted:
        body["message"].pop("updated-by", None)
    return body


def hub_dataset(world: World) -> dict[str, Any]:
    body = copy.deepcopy(HUB_DATASET_BODY)
    body["id"] = DATA_REPO
    body["disabled"] = world.hub_dataset_disabled
    return body


def paper_work(world: World, malformed: bool) -> dict[str, Any]:
    if malformed:
        return {"status": "ok", "message-type": "work", "message": []}
    body = copy.deepcopy(RETRACTED_BODY)
    body["message"]["DOI"] = PAPER
    if not world.paper_retracted:
        body["message"].pop("updated-by", None)
    return body


def datacite_record(world: World) -> dict[str, Any]:
    body = copy.deepcopy(DATACITE_BODY)
    attributes = body["data"]["attributes"]
    body["data"]["id"] = DOI_L
    attributes["doi"] = DOI_L
    attributes["url"] = FIGSHARE_BODY["url_public_html"]
    attributes["rightsList"] = [{"rightsIdentifier": world.datacite_licence.lower()}]
    return body


def figshare_article(world: World) -> dict[str, Any]:
    body = copy.deepcopy(FIGSHARE_BODY)
    name = {"CC-BY-4.0": "CC BY 4.0"}.get(world.figshare_licence, world.figshare_licence)
    body["license"] = {"value": 1, "name": name, "url": ""}
    return body


class WorldFetcher:
    """Answers every request from ``World``; a failed source raises ``SourceFailedError``.

    A request no rule here expects is a test failure, so the machine also notices a source being
    asked when it was not selected.
    """

    def __init__(self, world: World, failed: set[str], malformed: bool) -> None:
        self.world = world
        self.failed = failed
        self.malformed = malformed
        self.asked: set[str] = set()

    def _answer(self, source: str, url: str, body: Any) -> Response:
        self.asked.add(source)
        if source in self.failed:
            raise SourceFailedError(EVIDENCE_SOURCE[source], "timeout")
        return Response(200, json.dumps(body).encode(), url, NOW)

    def post(self, url: str, body: bytes, **kwargs: Any) -> Response:
        assert url == f"{OSV_API}/querybatch", url
        queries = json.loads(body)["queries"]
        listed = self.world.osv_listed and not self.world.osv_withdrawn
        results = []
        for query in queries:
            affected = query["package"]["name"] == "pillow" and query["version"] == "12.3.0"
            vulns = [{"id": ADVISORY, "modified": "2026-10-21T20:45:04Z"}]
            results.append({"vulns": vulns} if affected and listed else {})
        return self._answer("osv", url, {"results": results})

    def get(self, url: str, **kwargs: Any) -> Response:
        if url == f"{OSV_API}/vulns/{ADVISORY}":
            return self._answer("osv", url, osv_record(self.world))
        for repo in REPOS:
            if url == model_info_url(repo):
                return self._answer("hf-hub", url, hub_model(self.world, repo))
        if url == dataset_info_url(DATA_REPO):
            return self._answer("hf-hub", url, hub_dataset(self.world))
        if url == works_url(PAPER):
            return self._answer("crossref", url, paper_work(self.world, self.malformed))
        if url == works_url(DOI_R):
            return self._answer("crossref", url, crossref_work(self.world, self.malformed))
        if url == doi_url(DOI_L):
            return self._answer("datacite", url, datacite_record(self.world))
        if url == article_url(ARTICLE):
            return self._answer("figshare", url, figshare_article(self.world))
        raise AssertionError(f"unexpected request: {url}")


# --- the machine ---------------------------------------------------------------------------------

ALL_OK = dict.fromkeys(("osv", "hf", "crossref", "datacite", "figshare"), "ok")
CHECK_SOURCE = st.sampled_from(("ok", "failed", "not selected"))
CROSSREF_STATE = st.sampled_from(("ok", "failed", "malformed", "not selected"))


class AlertLifecycle(RuleBasedStateMachine):
    def __init__(self) -> None:
        super().__init__()
        self.root = Path(tempfile.mkdtemp(prefix="md-machine-"))
        self.store = Store(self.root / "md.db", now=lambda: NOW)
        self.store.add_model(MODEL)
        self.store.set_routing(DOI_R, agency="Crossref")
        self.store.set_routing(PAPER, agency="Crossref")
        self.store.set_routing(
            DOI_L, agency="DataCite", repository="figshare", repository_id=ARTICLE
        )
        self.inv = Inventory("12.3.0", (REPO, SHA_A), True, True)
        self.store.add_version(MODEL, {}, "0" * 64, inventory(self.inv))
        self.version = 1
        self.world = World()
        # The model: open cause keys, the licence baseline per repository (the first licence
        # observed for any revision of it) and the sources reporting the dataset licence change.
        self.open: set[str] = set()
        self.baseline: dict[str, str] = {}
        self.reporting: set[str] = set()
        # Start from a run in which every source answers and every modelled cause is present, so
        # each sequence begins with open alerts to carry, clear, withdraw or fix.
        self.world.disabled[REPO] = True
        self.world.datacite_licence = self.world.figshare_licence = "MIT"
        self.check(**ALL_OK)

    def teardown(self) -> None:
        self.store.close()
        shutil.rmtree(self.root, ignore_errors=True)

    # -- reading the store --

    def _alerts(self) -> dict[int, dict[str, Any]]:
        return {alert["alert_id"]: alert for alert in self.store.alerts_for(MODEL)}

    def _max_evidence(self) -> int:
        row = self.store.conn.execute("SELECT max(evidence_id) FROM evidence").fetchone()
        return int(row[0] or 0)

    def _closes(
        self, before: dict[int, dict[str, Any]], newest_evidence: int
    ) -> list[tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]]:
        """Each alert open before the step and closed by it, with the evidence linked in it."""
        closes = []
        for alert_id, alert in self._alerts().items():
            earlier = before.get(alert_id)
            if earlier is None or earlier["state"] != "open" or alert["state"] == "open":
                continue
            linked = self.store.alert_evidence(alert_id)
            fresh = [e for e in linked if e["evidence_id"] > newest_evidence]
            closes.append((earlier, alert, fresh))
        return closes

    # -- steps --

    @rule(
        package=st.sampled_from(PACKAGE_STATES),
        base=st.sampled_from(BASE_STATES),
        doi_r=st.booleans(),
        doi_l=st.booleans(),
        hub=st.sampled_from(HUB_STATES),
        tied=st.booleans(),
    )
    def register(
        self,
        package: str,
        base: tuple[str, str | None] | None,
        doi_r: bool,
        doi_l: bool,
        hub: str | None = SHA_A,
        tied: bool = True,
    ) -> None:
        new = Inventory(package, base, doi_r, doi_l, hub, tied)
        before = self._alerts()
        newest = self._max_evidence()
        self.store.add_version(MODEL, {}, "0" * 64, inventory(new))
        self.version += 1
        result = reevaluate_version(self.store, MODEL, self.version)

        expected_fixed: set[str] = set()
        for key in self.open:
            if key == PACKAGE_KEY:
                gone = package in ("13.0.0", "absent")
            elif key == HUB_REMOVED_KEY:
                gone = new.hub is None
            elif key == PAPER_KEY:
                gone = new.hub is None or not new.tied
            elif key in (RETRACTED_KEY, DATASET_LICENCE_KEY):
                gone = not (doi_r if key == RETRACTED_KEY else doi_l)
            else:
                repo = key.rsplit("pkg:huggingface/", 1)[1]
                gone = not new.base_pinned_in(repo) and not new.base_gap_in(repo)
            if gone:
                expected_fixed.add(key)

        for earlier, alert, fresh in self._closes(before, newest):
            key = earlier["cause_key"]
            assert alert["state"] == "fixed", f"registration closed {key} as {alert['state']}"
            # (b) a gap never yields fixed
            if key == PACKAGE_KEY:
                assert package != "gap", f"a package gap fixed {key}"
            if key == HUB_REMOVED_KEY or (key == PAPER_KEY and new.tied):
                assert new.hub != "gap", f"a gap for {DATA_REPO} fixed {key}"
                assert not new.hub_pinned, f"{key} fixed while {DATA_REPO} is still pinned"
            if key.startswith(("base_model_", "licence_changed:pkg:")):
                repo = key.rsplit("pkg:huggingface/", 1)[1]
                assert not new.base_gap_in(repo), f"a gap for {repo} fixed {key}"
                # (c) a repository-scoped cause is not fixed while the repository is depended on
                assert not new.base_pinned_in(repo), f"{key} fixed while {repo} is still pinned"
            # (e) the new inventory is linked as the evidence of the fix
            assert any(e["source"] == "inventory" for e in fresh), f"{key} fixed without evidence"
            assert alert["alert_id"] in result["fixed"]

        closed_keys = {earlier["cause_key"] for earlier, _, _ in self._closes(before, newest)}
        assert closed_keys == expected_fixed
        self.open -= expected_fixed
        if DATASET_LICENCE_KEY in expected_fixed:
            self.reporting = set()
        self.inv = new

    @rule(listed=st.booleans(), withdrawn=st.booleans())
    def osv_answer(self, listed: bool, withdrawn: bool) -> None:
        self.world.osv_listed, self.world.osv_withdrawn = listed, withdrawn

    @rule(repo=st.sampled_from(REPOS), disabled=st.booleans())
    def hub_disabled(self, repo: str, disabled: bool) -> None:
        self.world.disabled[repo] = disabled

    @rule(repo=st.sampled_from(REPOS), licence=st.sampled_from(HUB_LICENCES))
    def hub_licence(self, repo: str, licence: str) -> None:
        self.world.hub_licence[repo] = licence

    @rule(retracted=st.booleans(), paper=st.booleans())
    def crossref_answer(self, retracted: bool, paper: bool = True) -> None:
        self.world.retracted, self.world.paper_retracted = retracted, paper

    @rule(disabled=st.booleans())
    def hub_dataset_answer(self, disabled: bool) -> None:
        self.world.hub_dataset_disabled = disabled

    @rule(datacite=st.sampled_from(DATASET_LICENCES), figshare=st.sampled_from(DATASET_LICENCES))
    def dataset_licences(self, datacite: str, figshare: str) -> None:
        self.world.datacite_licence, self.world.figshare_licence = datacite, figshare

    @rule(
        osv=CHECK_SOURCE,
        hf=CHECK_SOURCE,
        crossref=CROSSREF_STATE,
        datacite=CHECK_SOURCE,
        figshare=CHECK_SOURCE,
    )
    def check(self, osv: str, hf: str, crossref: str, datacite: str, figshare: str) -> None:
        chosen = {"osv": osv, "hf-hub": hf, "crossref": crossref}
        chosen |= {"datacite": datacite, "figshare": figshare}
        selected = [source for source in SOURCES if chosen[source] != "not selected"]
        failed = {source for source in SOURCES if chosen[source] == "failed"}
        fetcher = WorldFetcher(self.world, failed, malformed=crossref == "malformed")
        before = self._alerts()
        newest = self._max_evidence()
        outcome = run_check(self.store, fetcher, [MODEL], selected)

        ok = {source for source in selected if outcome.sources[source] == "ok"}
        for source in fetcher.asked:  # a source with nothing to read in the run is ``ok``
            if chosen[source] in ("failed", "malformed"):
                assert outcome.sources[source].startswith("failed"), (source, outcome.sources)
        assert fetcher.asked <= set(selected), f"asked {fetcher.asked}, selected {selected}"

        expected = self._expected_after_check(ok)
        for earlier, alert, fresh in self._closes(before, newest):
            key, state = earlier["cause_key"], alert["state"]
            assert state in ("cleared", "withdrawn"), f"a check closed {key} as {state}"
            owners = self._owners(earlier)
            # (a) the owning source answered in this run
            assert owners <= ok, f"{key} closed as {state}; owners {owners}, ok {ok}"
            # (e) evidence from the owning source, linked in this step
            wanted = {EVIDENCE_SOURCE[owner] for owner in owners}
            assert wanted <= {e["source"] for e in fresh}, f"{key} closed without evidence"
            # (f) withdrawn only on an OSV record that says so
            if state == "withdrawn":
                assert key == PACKAGE_KEY and self.world.osv_withdrawn
                assert any((e["detail"] or {}).get("withdrawn") for e in fresh)

        open_keys = [a["cause_key"] for a in self.store.alerts_for(MODEL, ["open"])]
        assert sorted(open_keys) == sorted(expected), (
            f"open {sorted(open_keys)}, expected {sorted(expected)}; sources {outcome.sources}"
        )
        self.open = expected

    def _owners(self, alert: dict[str, Any]) -> set[str]:
        key = alert["cause_key"]
        if key == PACKAGE_KEY:
            return {"osv"}
        if key in (RETRACTED_KEY, PAPER_KEY):
            return {"crossref"}
        if key == DATASET_LICENCE_KEY:
            return set(alert["cause"].get("sources") or [alert["cause"]["source"]])
        return {"hf-hub"}

    def _expected_after_check(self, ok: set[str]) -> set[str]:
        """The model of the identity and clearance table: the open cause keys after a check."""
        inv, world = self.inv, self.world
        expected = set(self.open)
        if "osv" in ok:
            if world.osv_withdrawn:
                expected.discard(PACKAGE_KEY)
            elif inv.package == "12.3.0" and world.osv_listed:
                expected.add(PACKAGE_KEY)
        if "hf-hub" in ok:
            for repo in REPOS:
                if not inv.base_pinned_in(repo):
                    continue
                if world.disabled[repo]:
                    expected.add(disabled_key(repo))
                else:
                    expected.discard(disabled_key(repo))
                licence = world.hub_licence[repo]
                baseline = self.baseline.setdefault(repo, licence)
                if licence != baseline:
                    expected.add(licence_key(repo))
                else:
                    expected.discard(licence_key(repo))
        if "hf-hub" in ok and inv.hub_pinned and world.hub_dataset_disabled:
            expected.add(HUB_REMOVED_KEY)  # never cleared: only a new version without it fixes it
        if "crossref" in ok and inv.hub_pinned and inv.tied:
            if world.paper_retracted:
                expected.add(PAPER_KEY)
            else:
                expected.discard(PAPER_KEY)
        if "crossref" in ok and inv.doi_r:
            if world.retracted:
                expected.add(RETRACTED_KEY)
            else:
                expected.discard(RETRACTED_KEY)
        if inv.doi_l:
            licences = {"datacite": world.datacite_licence, "figshare": world.figshare_licence}
            answered = [source for source in ("datacite", "figshare") if source in ok]
            changed = {source for source in answered if licences[source] != RECORDED_LICENCE}
            same = {source for source in answered if licences[source] == RECORDED_LICENCE}
            self.reporting = (self.reporting - same) | changed
            if self.reporting:
                expected.add(DATASET_LICENCE_KEY)
            else:
                expected.discard(DATASET_LICENCE_KEY)
        return expected

    # -- invariants after every step --

    @invariant()
    def one_open_alert_per_cause(self) -> None:
        # (d)
        keys = [a["cause_key"] for a in self.store.alerts_for(MODEL, ["open"])]
        assert len(keys) == len(set(keys)), keys

    @invariant()
    def every_alert_has_evidence(self) -> None:
        for alert in self.store.alerts_for(MODEL):
            assert self.store.alert_evidence(alert["alert_id"]), alert["cause_key"]


EXPLORE = os.environ.get("MODEL_DEPENDABOT_PROPERTY_EXAMPLES")
AlertLifecycle.TestCase.settings = settings(
    # 200 sequences is the fewest at which this machine caught both defects planted to test it
    # (a gap fixing a repository-wide alert; one licence source clearing for another).
    max_examples=int(EXPLORE or "200"),
    stateful_step_count=30,
    deadline=None,
    derandomize=EXPLORE is None,
    database=None,
    suppress_health_check=[HealthCheck.too_slow],
)
TestAlertLifecycle = AlertLifecycle.TestCase


def test_the_machine_opens_and_closes_every_modelled_kind() -> None:
    """The world above does open each modelled alert and close it by each route, so the
    properties are not satisfied vacuously by a machine in which nothing ever opens."""
    machine = AlertLifecycle()
    try:
        all_ok = ALL_OK
        machine.hub_licence(repo=REPO, licence="apache-2.0")
        machine.check(**all_ok)
        assert machine.open == {
            PACKAGE_KEY,
            disabled_key(REPO),
            licence_key(REPO),
            RETRACTED_KEY,
            DATASET_LICENCE_KEY,
            HUB_REMOVED_KEY,
            PAPER_KEY,
        }
        machine.osv_answer(listed=False, withdrawn=True)
        machine.hub_disabled(repo=REPO, disabled=False)
        machine.crossref_answer(retracted=False, paper=False)
        machine.dataset_licences(datacite="CC-BY-4.0", figshare="MIT")
        machine.check(**all_ok)
        assert machine.open == {licence_key(REPO), DATASET_LICENCE_KEY, HUB_REMOVED_KEY}
        states = {a["cause_key"]: a["state"] for a in machine.store.alerts_for(MODEL)}
        assert states[PACKAGE_KEY] == "withdrawn"
        assert states[RETRACTED_KEY] == states[PAPER_KEY] == "cleared"
        machine.register(package="12.3.0", base=(OTHER, SHA_A), doi_r=True, doi_l=False, hub=None)
        assert machine.open == set()
        assert {a["state"] for a in machine.store.alerts_for(MODEL)} == {
            "withdrawn",
            "cleared",
            "fixed",
        }
    finally:
        machine.teardown()

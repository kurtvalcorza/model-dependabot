"""A code-free claim that format-check contradicts is scanned as the pickle it is (review F3).

PR #15 round 1, R1: an imported inventory claims ``claimed.safetensors`` cannot run code; the file
beside it is a pickle naming ``os.system``. One check with both sources contradicts the claim and
picklescan, which now runs after format-check and selects files as their bytes showed them,
raises its own alert for the file in the same run. Nothing in the pickle is ever run.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from model_dependabot.lifecycle import WEIGHT_SCAN_ALERT, run_check
from model_dependabot.store import Store

NOW = datetime(2026, 11, 13, 9, 0, tzinfo=UTC)
PICKLE_0 = b"cos\nsystem\n(S'echo hi'\ntR."  # read as data only, never loaded


class NoNetwork:
    def get(self, url: str, **kwargs: Any) -> Any:
        raise AssertionError(f"unexpected request: {url}")

    get_range = post = get


def test_picklescan_scans_a_contradicted_claim_in_the_same_run(tmp_path: Path) -> None:
    (tmp_path / "bom").mkdir()
    (tmp_path / "bom" / "claimed.safetensors").write_bytes(PICKLE_0)
    entry = {
        "kind": "weight_file",
        "identifier": "sha256:" + hashlib.sha256(PICKLE_0).hexdigest(),
        "pinned": True,
        "location": "claimed.safetensors",
        "format": "safetensors",
        "can_run_code": False,
        "format_origin": "import",
    }
    with Store(tmp_path / "db" / "md.db", now=lambda: NOW) as store:
        store.add_model("m")
        store.add_version("m", {}, "f" * 64, [entry], base_dir=tmp_path / "bom", origin="import")
        outcome = run_check(store, NoNetwork(), ["m"], ["picklescan", "format-check"])
        assert list(outcome.sources) == ["picklescan", "format-check"]  # the order asked for
        [check] = [c for c in store.claim_checks("m", 1) if c["claim"] == "code_free"]
        assert (check["outcome"], check["measured_format"]) == ("contradicted", "pickle")
        kinds = {alert["kind"] for alert in store.alerts_for("m", ["open"])}
        assert WEIGHT_SCAN_ALERT in kinds

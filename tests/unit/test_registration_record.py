"""Registration record helpers and the store column for record-registered versions (feature 005)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from model_dependabot.inventory.record import (
    RECORD_SCHEMA_VERSION,
    manifest_sha256,
    record_sha256,
    verdict,
)
from model_dependabot.sources.pickle_scan import Finding, ScanReport
from model_dependabot.store import WATCH_KINDS, Store


def test_record_sha256_is_over_the_canonical_body() -> None:
    body = {"schema_version": RECORD_SCHEMA_VERSION, "model_id": "m", "weights": []}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    assert record_sha256(body) == hashlib.sha256(canonical).hexdigest()
    assert record_sha256({**body, "record_sha256": "x" * 64}) == record_sha256(body)
    assert record_sha256(dict(reversed(list(body.items())))) == record_sha256(body)


def test_manifest_sha256_reads_crlf_as_lf() -> None:
    assert manifest_sha256(b"[model]\r\nid = 'm'\r\n") == manifest_sha256(b"[model]\nid = 'm'\n")
    assert manifest_sha256(b"[model]\n") != manifest_sha256(b"[model] \n")


def test_verdict_order_and_incomplete_is_never_clean() -> None:
    os_system = Finding("os", "system", "dangerous")
    getattr_ = Finding("builtins", "getattr", "suspicious")
    assert verdict(ScanReport("a.pkl", 1, (os_system, getattr_))) == "dangerous"
    assert verdict(ScanReport("a.pkl", 1, (getattr_,), complete=False)) == "suspicious"
    assert verdict(ScanReport("a.pkl", 1, complete=False)) == "incomplete"
    assert verdict(ScanReport("a.pkl", 1)) == "clean"


def test_an_older_database_gains_the_record_column(tmp_path: Path) -> None:
    path = tmp_path / "md.db"
    with Store(path) as store:
        store.conn.execute("ALTER TABLE model_versions DROP COLUMN registration_record_sha256")
        assert "registration_record_sha256" not in store.columns("model_versions")
    with Store(path) as store:
        assert "registration_record_sha256" in store.columns("model_versions")
        store.add_model("m")
        store.add_version("m", {}, "0" * 64, [], registration_record_sha256="a" * 64)
        assert store.get_version("m", 1)["registration_record_sha256"] == "a" * 64
    assert "weight_file_absent" in WATCH_KINDS

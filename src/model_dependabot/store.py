"""SQLite storage and the content-addressed evidence store (data-model.md, research R6).

One SQLite file holds models, versions, inventory entries, advisories, check runs, evidence, alerts
and watch events. Raw source responses are kept as files in ``evidence/`` beside the database, each
named by its SHA-256 and referenced from evidence records by ``body_sha256``. The database itself
enforces the rules that must never break: a recorded model version and its entries cannot change
(FR-005), and a model has at most one open alert per cause (FR-010).
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from collections.abc import Callable, Iterable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from types import TracebackType
from typing import Any

ENTRY_KINDS = ("weight_file", "package", "base_model", "dataset")
ALERT_KINDS = ("package_advisory", "weight_file_scan", "hub_scan", "format_policy")
ALERT_STATES = ("open", "fixed", "dismissed", "withdrawn", "cleared")
DISMISSAL_REASONS = ("not_used_at_runtime", "risk_accepted", "false_positive", "fix_not_available")
WATCH_KINDS = (
    "pickle_format",
    "scan_suspicious",
    "scan_incomplete",
    "hub_scan_unknown",
    "advisory_unmatched",
    "hash_mismatch",
)


def _in(values: tuple[str, ...]) -> str:
    return "(" + ", ".join(f"'{value}'" for value in values) + ")"


SCHEMA = f"""
CREATE TABLE IF NOT EXISTS models (
    model_id TEXT PRIMARY KEY,
    name TEXT,
    owner TEXT,
    format_policy TEXT NOT NULL DEFAULT 'default' CHECK (format_policy IN ('default', 'strict')),
    format_policy_set_by TEXT,
    format_policy_set_at TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS model_versions (
    model_id TEXT NOT NULL REFERENCES models (model_id),
    version INTEGER NOT NULL CHECK (version >= 1),
    registered_at TEXT NOT NULL,
    manifest_sha256 TEXT NOT NULL,
    inventory TEXT NOT NULL,
    PRIMARY KEY (model_id, version)
);

CREATE TABLE IF NOT EXISTS inventory_entries (
    entry_id INTEGER PRIMARY KEY,
    model_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN {_in(ENTRY_KINDS)}),
    identifier TEXT,
    pinned INTEGER NOT NULL CHECK (pinned IN (0, 1)),
    gap_reason TEXT,
    location TEXT,
    size INTEGER,
    format TEXT,
    can_run_code INTEGER CHECK (can_run_code IN (0, 1)),
    hub_repo TEXT,
    hub_revision TEXT,
    hub_file TEXT,
    name TEXT,
    package_version TEXT,
    hashes TEXT,
    FOREIGN KEY (model_id, version) REFERENCES model_versions (model_id, version),
    CHECK (pinned = 1 OR gap_reason IS NOT NULL),
    CHECK (pinned = 0 OR identifier IS NOT NULL)
);

CREATE TABLE IF NOT EXISTS check_runs (
    run_id INTEGER PRIMARY KEY,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    scope TEXT NOT NULL,
    sources TEXT
);

CREATE TABLE IF NOT EXISTS evidence (
    evidence_id INTEGER PRIMARY KEY,
    source TEXT NOT NULL,
    url TEXT NOT NULL,
    retrieved_at TEXT NOT NULL,
    matched_identifier TEXT NOT NULL,
    body_sha256 TEXT NOT NULL CHECK (length(body_sha256) = 64),
    detail TEXT,
    run_id INTEGER REFERENCES check_runs (run_id)
);

CREATE TABLE IF NOT EXISTS advisories (
    source TEXT NOT NULL,
    advisory_id TEXT NOT NULL,
    aliases TEXT,
    modified TEXT,
    withdrawn TEXT,
    severity TEXT,
    severity_origin TEXT,
    affected TEXT,
    evidence_id INTEGER REFERENCES evidence (evidence_id),
    PRIMARY KEY (source, advisory_id)
);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id INTEGER PRIMARY KEY,
    model_id TEXT NOT NULL REFERENCES models (model_id),
    opened_in_version INTEGER NOT NULL,
    current_version INTEGER NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN {_in(ALERT_KINDS)}),
    cause_key TEXT NOT NULL,
    cause TEXT NOT NULL,
    severity TEXT NOT NULL,
    severity_origin TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'open' CHECK (state IN {_in(ALERT_STATES)}),
    opened_at TEXT NOT NULL,
    closed_at TEXT,
    closed_by_version INTEGER,
    dismissal_reason TEXT CHECK (dismissal_reason IS NULL OR dismissal_reason IN
        {_in(DISMISSAL_REASONS)}),
    dismissed_by TEXT,
    note TEXT,
    CHECK (state != 'dismissed' OR (dismissal_reason IS NOT NULL AND dismissed_by IS NOT NULL))
);

-- FR-010: at most one open alert per model and cause.
CREATE UNIQUE INDEX IF NOT EXISTS one_open_alert_per_cause
    ON alerts (model_id, cause_key) WHERE state = 'open';

CREATE TABLE IF NOT EXISTS alert_evidence (
    alert_id INTEGER NOT NULL REFERENCES alerts (alert_id),
    evidence_id INTEGER NOT NULL REFERENCES evidence (evidence_id),
    PRIMARY KEY (alert_id, evidence_id)
);

CREATE TABLE IF NOT EXISTS watch_events (
    watch_event_id INTEGER PRIMARY KEY,
    model_id TEXT NOT NULL REFERENCES models (model_id),
    version INTEGER NOT NULL,
    entry_identifier TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN {_in(WATCH_KINDS)}),
    detail TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    UNIQUE (model_id, version, entry_identifier, kind)
);

CREATE TABLE IF NOT EXISTS watch_event_evidence (
    watch_event_id INTEGER NOT NULL REFERENCES watch_events (watch_event_id),
    evidence_id INTEGER NOT NULL REFERENCES evidence (evidence_id),
    PRIMARY KEY (watch_event_id, evidence_id)
);

-- FR-005: a recorded model version and its inventory never change.
CREATE TRIGGER IF NOT EXISTS model_versions_no_update BEFORE UPDATE ON model_versions
BEGIN SELECT RAISE(ABORT, 'a recorded model version is immutable (FR-005)'); END;
CREATE TRIGGER IF NOT EXISTS model_versions_no_delete BEFORE DELETE ON model_versions
BEGIN SELECT RAISE(ABORT, 'a recorded model version is immutable (FR-005)'); END;
CREATE TRIGGER IF NOT EXISTS inventory_entries_no_update BEFORE UPDATE ON inventory_entries
BEGIN SELECT RAISE(ABORT, 'a recorded inventory entry is immutable (FR-005)'); END;
CREATE TRIGGER IF NOT EXISTS inventory_entries_no_delete BEFORE DELETE ON inventory_entries
BEGIN SELECT RAISE(ABORT, 'a recorded inventory entry is immutable (FR-005)'); END;
"""

ENTRY_FIELDS = (
    "kind",
    "identifier",
    "pinned",
    "gap_reason",
    "location",
    "size",
    "format",
    "can_run_code",
    "hub_repo",
    "hub_revision",
    "hub_file",
    "name",
    "version",
    "hashes",
)


def utc_text(moment: datetime) -> str:
    """A UTC timestamp as stored: ``YYYY-MM-DDTHH:MM:SSZ``."""
    if moment.tzinfo is None:
        raise ValueError("timestamps must carry a time zone")
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _bool(value: Any) -> bool | None:
    return None if value is None else bool(value)


def _loads(text: str | None) -> Any:
    return None if text is None else json.loads(text)


class Store:
    """The service's database and evidence store, opened from a database path."""

    def __init__(self, path: Path | str, *, now: Callable[[], datetime] | None = None) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.evidence_dir = self.path.parent / "evidence"
        self._now = now or (lambda: datetime.now(UTC))
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.executescript(SCHEMA)

    def __enter__(self) -> Store:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        self.conn.close()

    def _stamp(self) -> str:
        return utc_text(self._now())

    # --- schema --------------------------------------------------------------------------------

    def tables(self) -> set[str]:
        rows = self.conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        return {row["name"] for row in rows}

    def columns(self, table: str) -> set[str]:
        if table not in self.tables():
            raise KeyError(table)
        return {row["name"] for row in self.conn.execute(f"PRAGMA table_info({table})")}

    # --- models and versions -------------------------------------------------------------------

    def add_model(
        self, model_id: str, *, name: str | None = None, owner: str | None = None
    ) -> None:
        with self.conn:
            self.conn.execute(
                "INSERT INTO models (model_id, name, owner, created_at) VALUES (?, ?, ?, ?)",
                (model_id, name, owner, self._stamp()),
            )

    def get_model(self, model_id: str) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM models WHERE model_id = ?", (model_id,)).fetchone()
        return None if row is None else dict(row)

    def latest_version(self, model_id: str) -> int | None:
        row = self.conn.execute(
            "SELECT max(version) AS v FROM model_versions WHERE model_id = ?", (model_id,)
        ).fetchone()
        return row["v"]

    def add_version(
        self,
        model_id: str,
        inventory: Mapping[str, Any],
        manifest_sha256: str,
        entries: Iterable[Mapping[str, Any]],
    ) -> int:
        """Record the next version of a model with its inventory and entries, all or nothing."""
        with self.conn:
            version = (self.latest_version(model_id) or 0) + 1
            self.conn.execute(
                "INSERT INTO model_versions (model_id, version, registered_at, manifest_sha256,"
                " inventory) VALUES (?, ?, ?, ?, ?)",
                (model_id, version, self._stamp(), manifest_sha256, json.dumps(inventory)),
            )
            for entry in entries:
                self._insert_entry(model_id, version, entry)
        return version

    def _insert_entry(self, model_id: str, version: int, entry: Mapping[str, Any]) -> None:
        unknown = set(entry) - set(ENTRY_FIELDS)
        if unknown:
            raise ValueError(f"unknown inventory entry fields: {sorted(unknown)}")
        hashes = entry.get("hashes")
        can_run_code = entry.get("can_run_code")
        self.conn.execute(
            "INSERT INTO inventory_entries (model_id, version, kind, identifier, pinned,"
            " gap_reason, location, size, format, can_run_code, hub_repo, hub_revision,"
            " hub_file, name, package_version, hashes)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                model_id,
                version,
                entry.get("kind"),
                entry.get("identifier"),
                int(bool(entry.get("pinned"))),
                entry.get("gap_reason"),
                entry.get("location"),
                entry.get("size"),
                entry.get("format"),
                None if can_run_code is None else int(bool(can_run_code)),
                entry.get("hub_repo"),
                entry.get("hub_revision"),
                entry.get("hub_file"),
                entry.get("name"),
                entry.get("version"),
                None if hashes is None else json.dumps(list(hashes)),
            ),
        )

    def get_version(self, model_id: str, version: int) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM model_versions WHERE model_id = ? AND version = ?", (model_id, version)
        ).fetchone()
        if row is None:
            return None
        record = dict(row)
        record["inventory"] = json.loads(record["inventory"])
        return record

    def entries(self, model_id: str, version: int) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM inventory_entries WHERE model_id = ? AND version = ? ORDER BY entry_id",
            (model_id, version),
        )
        result = []
        for row in rows:
            record = {name: row[name] for name in ENTRY_FIELDS if name != "version"}
            record["version"] = row["package_version"]
            record["pinned"] = bool(row["pinned"])
            record["can_run_code"] = _bool(row["can_run_code"])
            record["hashes"] = _loads(row["hashes"])
            result.append(record)
        return result

    # --- evidence ------------------------------------------------------------------------------

    def put_body(self, body: bytes) -> str:
        """Store a raw response body once, as a file named by its SHA-256; return the hash."""
        digest = hashlib.sha256(body).hexdigest()
        path = self.evidence_dir / digest
        if not path.exists():
            self.evidence_dir.mkdir(parents=True, exist_ok=True)
            partial = path.with_name(f"{digest}.{os.getpid()}.partial")
            partial.write_bytes(body)
            os.replace(partial, path)
        return digest

    def read_body(self, digest: str) -> bytes:
        body = (self.evidence_dir / digest).read_bytes()
        if hashlib.sha256(body).hexdigest() != digest:
            raise ValueError(f"evidence body {digest} no longer matches its SHA-256")
        return body

    def add_evidence(
        self,
        *,
        source: str,
        url: str,
        retrieved_at: datetime,
        matched_identifier: str,
        body: bytes,
        detail: Mapping[str, Any] | None = None,
        run_id: int | None = None,
    ) -> int:
        digest = self.put_body(body)
        with self.conn:
            cursor = self.conn.execute(
                "INSERT INTO evidence (source, url, retrieved_at, matched_identifier, body_sha256,"
                " detail, run_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    source,
                    url,
                    utc_text(retrieved_at),
                    matched_identifier,
                    digest,
                    None if detail is None else json.dumps(detail),
                    run_id,
                ),
            )
        return int(cursor.lastrowid)

    def get_evidence(self, evidence_id: int) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM evidence WHERE evidence_id = ?", (evidence_id,)
        ).fetchone()
        if row is None:
            return None
        record = dict(row)
        record["detail"] = _loads(record["detail"])
        return record

    # --- alerts --------------------------------------------------------------------------------

    def insert_alert(
        self,
        *,
        model_id: str,
        kind: str,
        cause_key: str,
        cause: Mapping[str, Any],
        severity: str,
        severity_origin: str,
        opened_in_version: int,
        evidence_ids: Iterable[int],
    ) -> int:
        """Open an alert; the database refuses a second open alert for the same cause."""
        with self.conn:
            cursor = self.conn.execute(
                "INSERT INTO alerts (model_id, opened_in_version, current_version, kind, cause_key,"
                " cause, severity, severity_origin, state, opened_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'open', ?)",
                (
                    model_id,
                    opened_in_version,
                    opened_in_version,
                    kind,
                    cause_key,
                    json.dumps(cause),
                    severity,
                    severity_origin,
                    self._stamp(),
                ),
            )
            alert_id = int(cursor.lastrowid)
            self.conn.executemany(
                "INSERT INTO alert_evidence (alert_id, evidence_id) VALUES (?, ?)",
                [(alert_id, evidence_id) for evidence_id in evidence_ids],
            )
        return alert_id

    def close_alert(
        self,
        alert_id: int,
        *,
        state: str,
        closed_by_version: int | None = None,
        dismissal_reason: str | None = None,
        dismissed_by: str | None = None,
        note: str | None = None,
    ) -> None:
        if state == "open":
            raise ValueError("closing an alert needs a closed state")
        with self.conn:
            cursor = self.conn.execute(
                "UPDATE alerts SET state = ?, closed_at = ?, closed_by_version = ?,"
                " dismissal_reason = ?, dismissed_by = ?, note = ?"
                " WHERE alert_id = ? AND state = 'open'",
                (
                    state,
                    self._stamp(),
                    closed_by_version,
                    dismissal_reason,
                    dismissed_by,
                    note,
                    alert_id,
                ),
            )
        if cursor.rowcount != 1:
            raise ValueError(f"alert {alert_id} is not open")

    def get_alert(self, alert_id: int) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
        if row is None:
            return None
        record = dict(row)
        record["cause"] = json.loads(record["cause"])
        record["evidence_ids"] = [
            link["evidence_id"]
            for link in self.conn.execute(
                "SELECT evidence_id FROM alert_evidence WHERE alert_id = ? ORDER BY evidence_id",
                (alert_id,),
            )
        ]
        return record

    # --- check runs ----------------------------------------------------------------------------

    def start_check_run(self, *, scope: str) -> int:
        with self.conn:
            cursor = self.conn.execute(
                "INSERT INTO check_runs (started_at, scope) VALUES (?, ?)", (self._stamp(), scope)
            )
        return int(cursor.lastrowid)

    def finish_check_run(self, run_id: int, sources: Mapping[str, str]) -> None:
        with self.conn:
            self.conn.execute(
                "UPDATE check_runs SET finished_at = ?, sources = ? WHERE run_id = ?",
                (self._stamp(), json.dumps(dict(sources)), run_id),
            )

    def get_check_run(self, run_id: int) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM check_runs WHERE run_id = ?", (run_id,)).fetchone()
        if row is None:
            return None
        record = dict(row)
        record["sources"] = _loads(record["sources"])
        return record

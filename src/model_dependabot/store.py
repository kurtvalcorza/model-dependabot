"""SQLite storage and the content-addressed evidence store (data-model.md, research R6).

One SQLite file holds models, versions, inventory entries, advisories, check runs, evidence, alerts
and watch events. Raw source responses are kept as files in ``evidence/`` beside the database, each
named by its SHA-256 and referenced from evidence records by ``body_sha256``. The database itself
enforces the rules that must never break: a recorded model version and its entries cannot change
(FR-005), and a model has at most one open alert per cause (FR-010).

Feature 002 adds upstream observations, the DOI routing cache and the takedown log (which has no
``requesting_entity`` column), the check run's ``trigger``, and the evidence fields
``original_sha256`` and ``redacted_fields`` (research U10). Tables are created with
``CREATE TABLE IF NOT EXISTS``, so a fresh database has them; a database created by feature 001
is not migrated. The ETag cache (``etag_cache``, read through ``EtagCache``) is created the same
way, so an existing database gains it when opened; its ``used_at`` column, added after the table,
is added to an older table on open. One data migration runs on open: open repository-wide alerts
written with a revision in their cause key are rekeyed by repository (``_rekey_repository_alerts``).

Feature 006 adds the evidence field ``canonical_sha256``: for a body that is JSON, the SHA-256 of
its canonical form (``canonical_sha256``), so two responses from the same source and URL that
differ only in key order or whitespace count as the same evidence (``same_evidence``). The raw
bytes are still the stored body. A database without the column gains it on open, and its rows get
the hash from their stored bodies where the body is still there and is JSON.

Feature 004 adds global exceptions (``global_exceptions``, never deleted, only revoked), what each
applied scan saw (``file_scans``), the check overview (``check_run_overview``), the globals policy
columns on ``models`` and ``alerts.excepted_at``. An older database gains them on open, one
transaction per step; ``alerts`` is rebuilt once, keeping every row and id, so its kind check
accepts ``globals_policy``.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import sqlite3
from collections.abc import Callable, Iterable, Iterator, Mapping, MutableMapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import TracebackType
from typing import Any

from model_dependabot.sources.fetcher import Headers, Response

ENTRY_KINDS = ("weight_file", "package", "base_model", "dataset")
# A hub dataset's paper retraction keyed by revision (before 003): repository, revision, paper DOI.
_PAPER_KEY = re.compile(r"^(?P<repo>paper_retracted:hf-dataset:[^@:]+)@[^:]+(?P<paper>:.+)$")
ALERT_KINDS = (
    "package_advisory",
    "weight_file_scan",
    "hub_scan",
    "format_policy",
    # feature 002 (data-model.md, Alert)
    "dataset_retracted",
    "paper_retracted",
    "dataset_removed",
    "dataset_not_findable",
    "licence_changed",
    "base_model_disabled",
    "base_model_unavailable",
    # feature 004 (data-model.md, Alert)
    "globals_policy",
)
ALERT_STATES = ("open", "fixed", "dismissed", "withdrawn", "cleared")
FORMAT_POLICIES = ("default", "strict")
GLOBALS_POLICIES = ("default", "strict")
OVERVIEW_STATES = ("passed", "alerted", "incomplete", "failed")
DISMISSAL_REASONS = ("not_used_at_runtime", "risk_accepted", "false_positive", "fix_not_available")
WATCH_KINDS = (
    "pickle_format",
    "scan_suspicious",
    "scan_incomplete",
    "hub_scan_unknown",
    "advisory_unmatched",
    "hash_mismatch",
    # feature 002 (data-model.md, Watch event)
    "base_model_new_revision",
    "base_model_new_version_pointer",
    "gating_changed",
    "card_changed",
    "base_model_refused",
    "base_model_unrecognised",
    "base_model_moved",
    "dataset_new_version",
    "dataset_replaced",
    "dataset_moved",
    "dataset_unreachable",
    "paper_not_found",
    "licence_unrecognised",
    "licence_missing",
    "upstream_notice",
    # feature 005 (contracts/registration-record.md)
    "weight_file_absent",
    # review F1, amended 2026-10-31: OSV answered 404 for a record fetched by its id
    "advisory_gone",
    # feature 003 (data-model.md, Watch event): an imported code-free claim checked
    "format_claim_contradicted",
    "format_claim_unreadable",
)
# Feature 003 (data-model.md): how a version was registered and where a weight file's format
# claim came from; which claim a claim check confirmed and how it came out.
VERSION_ORIGINS = ("manifest", "record", "import")
FORMAT_ORIGINS = ("bytes", "name", "record", "import")
CLAIMS = ("code_free", "identity")
CLAIM_OUTCOMES = ("confirmed", "contradicted", "unreadable")
TRIGGERS = ("scheduled", "on_demand")
# The scope ``check --all`` records; here so that the store and the reports share it.
SCOPE_ALL = "all"
OUTCOMES = ("reachable", "refused", "not_found", "removed", "redirected")
LICENCE_FORMS = ("spdx", "expression", "unrecognised", "none")
REPOSITORIES = ("zenodo", "figshare", "other")
TAKEDOWN_FIELDS = ("date", "reported_content")
# Research U13: ``check`` drops ETag cache entries no run has looked up for this many days. A
# quarter is longer than any schedule the service is run on, so only URLs that have left every
# model's scope (a re-pinned file, a dropped dataset) age out.
ETAG_CACHE_MAX_AGE_DAYS = 90


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
    created_at TEXT NOT NULL,
    globals_policy TEXT NOT NULL DEFAULT 'default' CHECK (globals_policy IN ('default', 'strict')),
    globals_policy_set_by TEXT,
    globals_policy_set_at TEXT
);

CREATE TABLE IF NOT EXISTS model_versions (
    model_id TEXT NOT NULL REFERENCES models (model_id),
    version INTEGER NOT NULL CHECK (version >= 1),
    registered_at TEXT NOT NULL,
    manifest_sha256 TEXT NOT NULL,
    inventory TEXT NOT NULL,
    base_dir TEXT,
    registration_record_sha256 TEXT,
    origin TEXT CHECK (origin IS NULL OR origin IN {_in(VERSION_ORIGINS)}),
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
    recorded_licence TEXT,
    licence_form TEXT CHECK (licence_form IS NULL OR licence_form IN {_in(LICENCE_FORMS)}),
    paper_dois TEXT,
    format_origin TEXT CHECK (format_origin IS NULL OR format_origin IN {_in(FORMAT_ORIGINS)}),
    FOREIGN KEY (model_id, version) REFERENCES model_versions (model_id, version),
    CHECK (pinned = 1 OR gap_reason IS NOT NULL),
    CHECK (pinned = 0 OR identifier IS NOT NULL)
);

CREATE TABLE IF NOT EXISTS check_runs (
    run_id INTEGER PRIMARY KEY,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    scope TEXT NOT NULL,
    sources TEXT,
    trigger TEXT NOT NULL DEFAULT 'on_demand' CHECK (trigger IN {_in(TRIGGERS)})
);

CREATE TABLE IF NOT EXISTS evidence (
    evidence_id INTEGER PRIMARY KEY,
    source TEXT NOT NULL,
    url TEXT NOT NULL,
    retrieved_at TEXT NOT NULL,
    matched_identifier TEXT NOT NULL,
    body_sha256 TEXT NOT NULL CHECK (length(body_sha256) = 64),
    detail TEXT,
    run_id INTEGER REFERENCES check_runs (run_id),
    original_sha256 TEXT NOT NULL CHECK (length(original_sha256) = 64),
    redacted_fields TEXT NOT NULL DEFAULT '[]',
    canonical_sha256 TEXT CHECK (canonical_sha256 IS NULL OR length(canonical_sha256) = 64)
);

CREATE TABLE IF NOT EXISTS upstream_observations (
    observation_id INTEGER PRIMARY KEY,
    run_id INTEGER NOT NULL REFERENCES check_runs (run_id),
    source TEXT NOT NULL,
    item TEXT NOT NULL,
    http_status INTEGER NOT NULL,
    redirected_to TEXT,
    outcome TEXT NOT NULL CHECK (outcome IN {_in(OUTCOMES)}),
    disabled INTEGER CHECK (disabled IS NULL OR disabled IN (0, 1)),
    gated TEXT,
    head_revision TEXT,
    declared_licence TEXT,
    licence_form TEXT CHECK (licence_form IS NULL OR licence_form IN {_in(LICENCE_FORMS)}),
    card_hash TEXT,
    new_version_pointer TEXT,
    updates TEXT,
    removal TEXT,
    evidence_ref INTEGER REFERENCES evidence (evidence_id),
    observed_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS upstream_observations_by_item
    ON upstream_observations (item, source, observation_id);

CREATE TABLE IF NOT EXISTS doi_routing (
    doi TEXT PRIMARY KEY CHECK (doi = lower(doi)),
    agency TEXT,
    repository TEXT CHECK (repository IS NULL OR repository IN {_in(REPOSITORIES)}),
    repository_id TEXT,
    looked_up_at TEXT NOT NULL
);

-- FR-005, research U10: the requesting party of a takedown is never stored, nor the notice's file
-- name, which can name it; evidence points to the log by its URL and the notice date.
CREATE TABLE IF NOT EXISTS takedown_notices (
    notice_id INTEGER PRIMARY KEY,
    date TEXT NOT NULL,
    reported_content TEXT NOT NULL
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
    excepted_at TEXT,
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

-- Feature 003 (data-model.md, Claim check): one confirmation attempt of one entry's claim in one
-- check run (``run_id``) or at import (``run_id`` null). The latest row per claim decides.
CREATE TABLE IF NOT EXISTS claim_checks (
    claim_check_id INTEGER PRIMARY KEY,
    model_id TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version >= 1),
    entry_identifier TEXT NOT NULL,
    claim TEXT NOT NULL CHECK (claim IN {_in(CLAIMS)}),
    run_id INTEGER REFERENCES check_runs (run_id),
    outcome TEXT NOT NULL CHECK (outcome IN {_in(CLAIM_OUTCOMES)}),
    measured_format TEXT,
    measured_can_run_code INTEGER CHECK (measured_can_run_code IN (0, 1)),
    reason TEXT,
    evidence_id INTEGER NOT NULL REFERENCES evidence (evidence_id),
    checked_at TEXT NOT NULL,
    FOREIGN KEY (model_id, version) REFERENCES model_versions (model_id, version)
);

CREATE INDEX IF NOT EXISTS claim_checks_by_entry
    ON claim_checks (model_id, version, entry_identifier, claim, claim_check_id);

-- PR #15 round 2, G1: the version each check run checked of each model, so the audit credits a
-- run to exactly that version. Runs written before this table have no rows here.
CREATE TABLE IF NOT EXISTS check_run_targets (
    run_id INTEGER NOT NULL REFERENCES check_runs (run_id),
    model_id TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version >= 1),
    PRIMARY KEY (run_id, model_id),
    FOREIGN KEY (model_id, version) REFERENCES model_versions (model_id, version)
);

-- PR #15 round 3, T3: facts about the database itself; ``first_linked_run`` is the first run
-- that records its targets, so a run before it is legacy.
CREATE TABLE IF NOT EXISTS store_marks (
    name TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Review C2, research U13: the ETag cache, kept across runs so a later run revalidates with
-- If-None-Match. One row per URL; the body is the redacted one, kept in the evidence store.
CREATE TABLE IF NOT EXISTS etag_cache (
    url TEXT PRIMARY KEY,
    etag TEXT NOT NULL,
    status INTEGER NOT NULL,
    headers TEXT NOT NULL,
    body_sha256 TEXT NOT NULL,
    original_sha256 TEXT NOT NULL,
    redacted_fields TEXT NOT NULL,
    retrieved_at TEXT NOT NULL,
    used_at TEXT
);

-- Feature 004 (data-model.md, Global exception): an owner's acceptance of one global in the file
-- with this SHA-256, wherever it is registered. Never deleted; only its revocation can be set,
-- once.
CREATE TABLE IF NOT EXISTS global_exceptions (
    exception_id INTEGER PRIMARY KEY,
    module TEXT NOT NULL CHECK (module != '' AND instr(module, '*') = 0
        AND instr(module, 'unknown') = 0),
    name TEXT NOT NULL CHECK (name != '' AND instr(name, '*') = 0 AND instr(name, 'unknown') = 0),
    sha256 TEXT NOT NULL CHECK (length(sha256) = 64 AND sha256 NOT GLOB '*[^0-9a-f]*'),
    reason TEXT NOT NULL CHECK (length(trim(reason)) > 0),
    accepted_by TEXT NOT NULL CHECK (length(trim(accepted_by)) > 0),
    recorded_at TEXT NOT NULL,
    expires_on TEXT CHECK (expires_on IS NULL
        OR expires_on GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'),
    revoked_at TEXT,
    revoked_by TEXT CHECK (revoked_by IS NULL OR length(trim(revoked_by)) > 0),
    revoke_reason TEXT CHECK (revoke_reason IS NULL OR length(trim(revoke_reason)) > 0),
    evidence_id INTEGER NOT NULL REFERENCES evidence (evidence_id),
    CHECK ((revoked_at IS NULL) = (revoked_by IS NULL)
        AND (revoked_at IS NULL) = (revoke_reason IS NULL))
);

CREATE INDEX IF NOT EXISTS global_exceptions_by_file ON global_exceptions (sha256, module, name);

-- Feature 004 (data-model.md, File scan): what one applied static scan of a file's bytes saw, in a
-- check run (``run_id``) or recorded at registration (``run_id`` null). The latest row per hash
-- decides.
CREATE TABLE IF NOT EXISTS file_scans (
    file_scan_id INTEGER PRIMARY KEY,
    sha256 TEXT NOT NULL CHECK (length(sha256) = 64 AND sha256 NOT GLOB '*[^0-9a-f]*'),
    scanner TEXT NOT NULL,
    scanner_version TEXT NOT NULL,
    complete INTEGER NOT NULL CHECK (complete IN (0, 1)),
    globals TEXT NOT NULL,
    scanned_at TEXT NOT NULL,
    run_id INTEGER REFERENCES check_runs (run_id),
    evidence_id INTEGER NOT NULL REFERENCES evidence (evidence_id)
);

CREATE INDEX IF NOT EXISTS file_scans_by_hash ON file_scans (sha256, file_scan_id);

-- Feature 004 (data-model.md, Check overview): one row per run, model and source, plus one row per
-- source for the run as a whole, stored with ``model_id = ''`` so the key holds for it too.
CREATE TABLE IF NOT EXISTS check_run_overview (
    run_id INTEGER NOT NULL REFERENCES check_runs (run_id),
    model_id TEXT NOT NULL,
    version INTEGER,
    source TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN {_in(OVERVIEW_STATES)}),
    reason TEXT,
    entries INTEGER,
    incomplete INTEGER,
    alerts_open INTEGER,
    alerts_excepted INTEGER,
    watch_events INTEGER,
    dismissals_held INTEGER,
    PRIMARY KEY (run_id, model_id, source)
);

CREATE TRIGGER IF NOT EXISTS global_exceptions_no_delete BEFORE DELETE ON global_exceptions
BEGIN SELECT RAISE(ABORT, 'a recorded exception is never deleted'); END;
CREATE TRIGGER IF NOT EXISTS global_exceptions_revoke_only BEFORE UPDATE ON global_exceptions
WHEN NOT (
    OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL AND NEW.revoked_by IS NOT NULL
    AND NEW.revoke_reason IS NOT NULL
    AND NEW.exception_id = OLD.exception_id AND NEW.module = OLD.module
    AND NEW.name = OLD.name AND NEW.sha256 = OLD.sha256 AND NEW.reason = OLD.reason
    AND NEW.accepted_by = OLD.accepted_by AND NEW.recorded_at = OLD.recorded_at
    AND NEW.expires_on IS OLD.expires_on AND NEW.evidence_id = OLD.evidence_id
)
BEGIN SELECT RAISE(ABORT, 'only the revocation of an exception can be set, once'); END;

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
    "recorded_licence",
    "licence_form",
    "paper_dois",
    "format_origin",
)
_OBSERVATION_FIELDS = (
    "http_status",
    "redirected_to",
    "outcome",
    "disabled",
    "gated",
    "head_revision",
    "declared_licence",
    "licence_form",
    "card_hash",
    "new_version_pointer",
    "updates",
    "removal",
    "evidence_ref",
)
_OBSERVATION_JSON = ("updates", "removal")


def utc_text(moment: datetime) -> str:
    """A UTC timestamp as stored: ``YYYY-MM-DDTHH:MM:SSZ``."""
    if moment.tzinfo is None:
        raise ValueError("timestamps must carry a time zone")
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _bool(value: Any) -> bool | None:
    return None if value is None else bool(value)


def _loads(text: str | None) -> Any:
    return None if text is None else json.loads(text)


EXCEPTION_SOURCE = "exception"


def _canonical_json(record: Mapping[str, Any]) -> bytes:
    return json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")


_MODEL_DEFAULTS = {
    "globals_policy": "default",
    "globals_policy_set_by": None,
    "globals_policy_set_at": None,
}


def exception_state(record: Mapping[str, Any], at: datetime) -> str:
    """``active``, ``expired`` or ``revoked`` at ``at`` (data-model.md, Global exception).

    An exception expiring on a date covers that whole day in UTC: it is expired from 00:00Z on the
    next day.
    """
    if record.get("revoked_at"):
        return "revoked"
    expires = record.get("expires_on")
    if expires:
        end = datetime.fromisoformat(expires).replace(tzinfo=UTC) + timedelta(days=1)
        if at >= end:
            return "expired"
    return "active"


def canonical_sha256(body: bytes) -> str | None:
    """The SHA-256 of a JSON body in canonical form, or ``None`` for a body that is not JSON.

    The canonical form is the parsed value written with sorted keys, no insignificant whitespace
    and UTF-8 without escaping, so it changes only when the content does (feature 006, E1).
    """
    try:
        value = json.loads(body.decode("utf-8"))
    except ValueError:  # UnicodeDecodeError and JSONDecodeError are both ValueErrors
        return None
    text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def content_key(evidence: Mapping[str, Any]) -> str:
    """What makes two evidence bodies the same: the canonical hash for JSON, else the raw hash."""
    return str(evidence.get("canonical_sha256") or evidence["body_sha256"])


def same_evidence(evidence: Mapping[str, Any], source: str, url: str, body: bytes) -> bool:
    """Whether ``body`` from ``source`` at ``url`` is the content ``evidence`` already holds."""
    if evidence["source"] != source or evidence["url"] != url:
        return False
    return content_key(evidence) == (canonical_sha256(body) or hashlib.sha256(body).hexdigest())


class OutdatedDatabaseError(ValueError):
    """A database too old to read without upgrading it (feature 003, research A12)."""


class Store:
    """The service's database and evidence store, opened from a database path."""

    read_only = False

    @classmethod
    def open_read_only(
        cls, path: Path | str, *, now: Callable[[], datetime] | None = None
    ) -> Store:
        """Open an existing database for reading only (feature 003, FR-013).

        SQLite opens it with ``mode=ro``: no schema is created, nothing is migrated or
        back-filled and no timestamp is written, so the file stays byte-identical. A column or
        table a later feature adds and the file lacks reads as its default (an origin of null, no
        claim checks). A missing file raises ``FileNotFoundError``; a schema older than feature
        002 raises ``OutdatedDatabaseError``.
        """
        store = cls.__new__(cls)
        store.path = Path(path)
        if not store.path.is_file():
            raise FileNotFoundError(f"no database at {store.path}")
        store.evidence_dir = store.path.parent / "evidence"
        store._now = now or (lambda: datetime.now(UTC))
        store.read_only = True
        uri = store.path.resolve().as_uri() + "?mode=ro"
        store.conn = sqlite3.connect(uri, uri=True)
        store.conn.row_factory = sqlite3.Row
        tables = store.tables()
        if (
            "upstream_observations" not in tables
            or "check_runs" not in tables
            or "trigger" not in store.columns("check_runs")
        ):
            store.conn.close()
            raise OutdatedDatabaseError("run any check once to upgrade this database")
        return store

    def __init__(self, path: Path | str, *, now: Callable[[], datetime] | None = None) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.evidence_dir = self.path.parent / "evidence"
        self._now = now or (lambda: datetime.now(UTC))
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        had_targets = "check_run_targets" in self.tables()
        self.conn.executescript(SCHEMA)
        self._mark_first_linked_run(had_targets)
        if "used_at" not in self.columns("etag_cache"):
            with self.conn:
                self.conn.execute("ALTER TABLE etag_cache ADD COLUMN used_at TEXT")
        if "registration_record_sha256" not in self.columns("model_versions"):
            with self.conn:
                self.conn.execute(
                    "ALTER TABLE model_versions ADD COLUMN registration_record_sha256 TEXT"
                )
        if "canonical_sha256" not in self.columns("evidence"):
            self._add_canonical_hashes()
        self._add_origins()
        self._widen_watch_kinds()
        self._widen_alert_kinds()
        self._add_globals_columns()
        self._rekey_repository_alerts()

    def _mark_first_linked_run(self, had_targets: bool) -> None:
        """Record the first run that records its targets, once (PR #15 round 3, T3).

        Runs before it were written before ``check_run_targets`` existed: they are legacy, and the
        audit falls back to their start time. A run from this mark on that has no target row for a
        model did not check it. A database that gains the table now marks the next run; one that
        already had the table without a mark (written by an earlier build of this feature) marks
        its first linked run, or the next run if it has none.
        """
        if self.conn.execute(
            "SELECT 1 FROM store_marks WHERE name = 'first_linked_run'"
        ).fetchone():
            return
        first = None
        if had_targets:
            first = self.conn.execute("SELECT min(run_id) FROM check_run_targets").fetchone()[0]
        if first is None:
            first = self.conn.execute(
                "SELECT coalesce(max(run_id), 0) + 1 FROM check_runs"
            ).fetchone()[0]
        with self.conn:
            self.conn.execute(
                "INSERT OR IGNORE INTO store_marks (name, value) VALUES ('first_linked_run', ?)",
                (str(first),),
            )

    def first_linked_run(self) -> int | None:
        """The first run that records its targets, or ``None`` when every run is legacy (an older
        database opened read-only, without the table)."""
        tables = self.tables()
        if "store_marks" in tables:
            row = self.conn.execute(
                "SELECT value FROM store_marks WHERE name = 'first_linked_run'"
            ).fetchone()
            if row is not None:
                return int(row["value"])
        if "check_run_targets" in tables:
            first = self.conn.execute("SELECT min(run_id) FROM check_run_targets").fetchone()[0]
            return None if first is None else int(first)
        return None

    @contextlib.contextmanager
    def _atomic(self) -> Iterator[None]:
        """One explicit transaction, committed at the end or rolled back on any error.

        ``sqlite3`` opens a transaction implicitly only before a data statement, so a schema
        statement (``ALTER``, ``CREATE``, ``DROP``) would otherwise commit on its own and leave a
        migration half done if the open were interrupted (review F5).
        """
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            self.conn.rollback()
            raise
        self.conn.commit()

    def _add_origins(self) -> None:
        """Add feature 003's ``origin`` and ``format_origin`` to an older database (research A2).

        A version registered from a registration record is back-filled as ``record``; every other
        old version keeps a null origin (legacy) and every old entry a null ``format_origin``.
        The versions stay immutable: the trigger that guards them is lifted for the back-fill
        only, inside the one transaction that adds the columns, and put back. Every version
        registered since this feature has an origin, so a record-registered version without one
        can only be left by an interrupted upgrade, and it is back-filled on the next open.
        """
        added = "origin" not in self.columns("model_versions")
        if not added and "format_origin" in self.columns("inventory_entries"):  # a cheap first look
            pending = self.conn.execute(
                "SELECT 1 FROM model_versions WHERE origin IS NULL"
                " AND registration_record_sha256 IS NOT NULL LIMIT 1"
            ).fetchone()
            if pending is None:
                return
        with self._atomic():
            # Read again under the write lock: another process may have upgraded the database
            # while this one waited for it (PR #15 round 2, G4).
            trigger = self.conn.execute(
                "SELECT sql FROM sqlite_master WHERE type = 'trigger'"
                " AND name = 'model_versions_no_update'"
            ).fetchone()
            if "format_origin" not in self.columns("inventory_entries"):
                self.conn.execute(
                    "ALTER TABLE inventory_entries ADD COLUMN format_origin TEXT CHECK"
                    f" (format_origin IS NULL OR format_origin IN {_in(FORMAT_ORIGINS)})"
                )
            if "origin" not in self.columns("model_versions"):
                self.conn.execute(
                    "ALTER TABLE model_versions ADD COLUMN origin TEXT CHECK"
                    f" (origin IS NULL OR origin IN {_in(VERSION_ORIGINS)})"
                )
            self.conn.execute("DROP TRIGGER IF EXISTS model_versions_no_update")
            self.conn.execute(
                "UPDATE model_versions SET origin = 'record'"
                " WHERE registration_record_sha256 IS NOT NULL AND origin IS NULL"
            )
            if trigger is not None:
                self.conn.execute(trigger["sql"])

    def _add_canonical_hashes(self) -> None:
        """Add ``evidence.canonical_sha256`` to an older database and fill it where it can (006).

        A row whose body is no longer in the evidence store, or is not JSON, keeps an empty value
        and is compared by its raw hash, as before.
        """
        with self.conn:
            self.conn.execute(
                "ALTER TABLE evidence ADD COLUMN canonical_sha256 TEXT"
                " CHECK (canonical_sha256 IS NULL OR length(canonical_sha256) = 64)"
            )
            digests = [
                row["body_sha256"]
                for row in self.conn.execute("SELECT DISTINCT body_sha256 FROM evidence")
            ]
            for digest in digests:
                try:
                    canonical = canonical_sha256(self.read_body(digest))
                except (OSError, ValueError):
                    continue
                if canonical is not None:
                    self.conn.execute(
                        "UPDATE evidence SET canonical_sha256 = ? WHERE body_sha256 = ?",
                        (canonical, digest),
                    )

    def _widen_watch_kinds(self) -> None:
        """Rebuild ``watch_events`` when its ``kind`` check predates a kind in ``WATCH_KINDS``.

        A database written before a watch kind was added (``base_model_moved``, held-out scoring
        2026-10-25) has its table rebuilt with the current schema (``_rebuild_for_kinds``).
        """
        self._resolve_interrupted_widening()
        self._rebuild_for_kinds("watch_events", WATCH_KINDS, "watch_events_widened")

    def _widen_alert_kinds(self) -> None:
        """Rebuild ``alerts`` when its ``kind`` check predates ``globals_policy`` (research S2).

        The rebuilt table also has ``excepted_at``. Dropping the old table drops the partial unique
        index ``one_open_alert_per_cause``, so it is recreated in the same transaction.
        """
        self._rebuild_for_kinds("alerts", ALERT_KINDS, "alerts_rebuilt")

    def _rebuild_for_kinds(self, table: str, kinds: tuple[str, ...], copy: str) -> None:
        """Rebuild ``table`` with the current schema when its ``kind`` check lacks one of ``kinds``.

        SQLite cannot change a CHECK constraint in place, so the table is rebuilt by the SQLite
        twelve-step procedure: every row and id is kept, copied by explicit column list (the
        columns the old table has), and every index ``SCHEMA`` defines on the table is recreated.
        The rebuild is one transaction (``_atomic``), so an interrupted open leaves the old table
        and its indexes as they were.
        """
        sql = "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?"
        row = self.conn.execute(sql, (table,)).fetchone()
        if row is None or all(f"'{kind}'" in row["sql"] for kind in kinds):
            return
        start = SCHEMA.index(f"CREATE TABLE IF NOT EXISTS {table} (")
        ddl = SCHEMA[start : SCHEMA.index(");", start) + 2]
        ddl = ddl.replace(f"IF NOT EXISTS {table} (", f"{copy} (", 1)
        indexes = re.findall(
            rf"CREATE (?:UNIQUE )?INDEX IF NOT EXISTS \w+\s+ON {table} [^;]*;", SCHEMA
        )
        self.conn.execute("PRAGMA foreign_keys = OFF")
        try:
            with self._atomic():
                row = self.conn.execute(sql, (table,)).fetchone()
                if all(f"'{kind}'" in row["sql"] for kind in kinds):
                    return  # another process rebuilt it while this one waited (G4)
                self.conn.execute(ddl)
                names = ", ".join(sorted(self.columns(table) & self.columns(copy)))
                self.conn.execute(f"INSERT INTO {copy} ({names}) SELECT {names} FROM {table}")
                self.conn.execute(f"DROP TABLE {table}")
                self.conn.execute(f"ALTER TABLE {copy} RENAME TO {table}")
                for index in indexes:
                    self.conn.execute(index)
                if self.conn.execute("PRAGMA foreign_key_check").fetchone() is not None:
                    raise sqlite3.IntegrityError(f"{table} rebuild broke a foreign key")
        finally:
            self.conn.execute("PRAGMA foreign_keys = ON")

    def _add_globals_columns(self) -> None:
        """Add feature 004's globals policy columns and ``alerts.excepted_at`` to an older database.

        Every existing model reads policy ``default`` and every existing alert reads not excepted
        (FR-007). One transaction, which decides what to add under the write lock (G4).
        """
        wanted = {
            "models": (
                "globals_policy TEXT NOT NULL DEFAULT 'default'"
                f" CHECK (globals_policy IN {_in(GLOBALS_POLICIES)})",
                "globals_policy_set_by TEXT",
                "globals_policy_set_at TEXT",
            ),
            "alerts": ("excepted_at TEXT",),
        }

        def missing() -> list[tuple[str, str]]:
            return [
                (table, column)
                for table, columns in wanted.items()
                for column in columns
                if column.split()[0] not in self.columns(table)
            ]

        if not missing():
            return
        with self._atomic():
            for table, column in missing():
                self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {column}")

    def _resolve_interrupted_widening(self) -> None:
        """Settle a ``watch_events_widened`` left by a rebuild an earlier release did not finish.

        That release committed each schema statement on its own. If it had dropped the old table,
        the open recreates ``watch_events`` empty and the leftover copy holds the rows, so the copy
        takes its place; otherwise the old table still holds them and the copy is dropped.
        """
        if "watch_events_widened" not in self.tables():
            return
        rows = self.conn.execute("SELECT count(*) FROM watch_events").fetchone()[0]
        self.conn.execute("PRAGMA foreign_keys = OFF")
        try:
            with self._atomic():
                if rows == 0:
                    self.conn.execute("DROP TABLE watch_events")
                    self.conn.execute("ALTER TABLE watch_events_widened RENAME TO watch_events")
                else:
                    self.conn.execute("DROP TABLE watch_events_widened")
        finally:
            self.conn.execute("PRAGMA foreign_keys = ON")

    def _rekey_repository_alerts(self) -> None:
        """Key open repository-wide alerts by repository, not revision (003, identity table).

        Before 003, ``base_model_disabled``, ``base_model_unavailable`` and a hub dataset's
        ``dataset_removed`` were keyed by the pinned revision (``...@<commit>``), as were
        ``licence_changed`` for a base model or hub dataset and ``paper_retracted`` for a hub
        dataset. Their cause is a state or observation of the whole repository, so they are now
        keyed without it. An open alert with an
        old key is rekeyed when the database is opened; nothing else about it changes. Should
        another open alert already hold the new key (two revisions of one repository open at
        once), the old one is left as it is rather than merged.
        """
        rows = self.conn.execute(
            "SELECT alert_id, model_id, cause_key FROM alerts WHERE state = 'open' AND ("
            " kind IN ('base_model_disabled', 'base_model_unavailable')"
            " OR (kind = 'dataset_removed' AND cause_key LIKE 'dataset_removed:hf-dataset:%')"
            " OR (kind = 'licence_changed' AND (cause_key LIKE 'licence_changed:hf-dataset:%'"
            "  OR cause_key LIKE 'licence_changed:pkg:huggingface/%'))"
            " OR (kind = 'paper_retracted' AND cause_key LIKE 'paper_retracted:hf-dataset:%'))"
            " AND cause_key LIKE '%@%'"
        ).fetchall()
        for row in rows:
            if row["cause_key"].startswith("paper_retracted:"):
                # paper_retracted:hf-dataset:owner/name@<revision>:<paper DOI>
                match = _PAPER_KEY.match(row["cause_key"])
                if match is None:
                    continue
                new_key = match["repo"] + match["paper"]
            else:
                new_key = row["cause_key"].rsplit("@", 1)[0]
            with self.conn:
                taken = self.conn.execute(
                    "SELECT 1 FROM alerts WHERE model_id = ? AND cause_key = ? AND state = 'open'",
                    (row["model_id"], new_key),
                ).fetchone()
                if taken is None:
                    self.conn.execute(
                        "UPDATE alerts SET cause_key = ? WHERE alert_id = ?",
                        (new_key, row["alert_id"]),
                    )

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

    def now(self) -> datetime:
        """The store's clock (a fixed time in tests)."""
        return self._now()

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
        if row is None:
            return None
        # A database older than feature 004, opened read-only, reads the default globals policy.
        return {**_MODEL_DEFAULTS, **dict(row)}

    def set_format_policy(self, model_id: str, policy: str, *, set_by: str) -> dict[str, Any]:
        """Record the model's format policy, who set it and when (FR-021, constitution I)."""
        if policy not in FORMAT_POLICIES:
            raise ValueError(f"format policy must be one of {FORMAT_POLICIES}, got {policy!r}")
        if not set_by.strip():
            raise ValueError("a format policy needs the name of who set it")
        with self.conn:
            cursor = self.conn.execute(
                "UPDATE models SET format_policy = ?, format_policy_set_by = ?,"
                " format_policy_set_at = ? WHERE model_id = ?",
                (policy, set_by, self._stamp(), model_id),
            )
        if cursor.rowcount != 1:
            raise KeyError(model_id)
        model = self.get_model(model_id)
        assert model is not None
        return model

    def set_globals_policy(self, model_id: str, policy: str, *, set_by: str) -> dict[str, Any]:
        """Record the model's globals policy, who set it and when (feature 004, FR-006).

        Separate from the format policy; takes effect at the next check that asks a weight source.
        """
        if policy not in GLOBALS_POLICIES:
            raise ValueError(f"globals policy must be one of {GLOBALS_POLICIES}, got {policy!r}")
        if not set_by.strip():
            raise ValueError("a globals policy needs the name of who set it")
        with self.conn:
            cursor = self.conn.execute(
                "UPDATE models SET globals_policy = ?, globals_policy_set_by = ?,"
                " globals_policy_set_at = ? WHERE model_id = ?",
                (policy, set_by.strip(), self._stamp(), model_id),
            )
        if cursor.rowcount != 1:
            raise KeyError(model_id)
        model = self.get_model(model_id)
        assert model is not None
        return model

    # --- feature 004: file scans, exceptions and the check overview ----------------------------

    def add_file_scan(
        self,
        *,
        sha256: str,
        scanner: str,
        scanner_version: str,
        complete: bool,
        globals: Iterable[Mapping[str, str]],
        scanned_at: datetime | str,
        run_id: int | None,
        evidence_id: int,
    ) -> int:
        """Record what one applied scan of the bytes with this SHA-256 saw (data-model.md)."""
        items = [{"module": g["module"], "name": g["name"], "safety": g["safety"]} for g in globals]
        stamp = scanned_at if isinstance(scanned_at, str) else utc_text(scanned_at)
        with self.conn:
            cursor = self.conn.execute(
                "INSERT INTO file_scans (sha256, scanner, scanner_version, complete, globals,"
                " scanned_at, run_id, evidence_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    sha256,
                    scanner,
                    scanner_version,
                    int(bool(complete)),
                    json.dumps(items),
                    stamp,
                    run_id,
                    evidence_id,
                ),
            )
        return int(cursor.lastrowid)

    def latest_file_scan(self, sha256: str) -> dict[str, Any] | None:
        """The latest scan of the bytes with this SHA-256 (by ``file_scan_id``), or ``None``."""
        if "file_scans" not in self.tables():
            return None  # a database older than feature 004, opened read-only
        row = self.conn.execute(
            "SELECT * FROM file_scans WHERE sha256 = ? ORDER BY file_scan_id DESC LIMIT 1",
            (sha256,),
        ).fetchone()
        if row is None:
            return None
        record = dict(row)
        record["complete"] = bool(record["complete"])
        record["globals"] = json.loads(record["globals"])
        return record

    def exceptions(
        self, sha256: str | None = None, *, include_inactive: bool = False
    ) -> list[dict[str, Any]]:
        """Global exceptions, oldest first, each with its ``state`` at the store's clock.

        Only active ones unless ``include_inactive``; only those for ``sha256`` when it is given.
        """
        if "global_exceptions" not in self.tables():
            return []  # a database older than feature 004, opened read-only
        query = "SELECT * FROM global_exceptions"
        params: tuple[Any, ...] = ()
        if sha256 is not None:
            query += " WHERE sha256 = ?"
            params = (sha256,)
        rows = self.conn.execute(query + " ORDER BY exception_id", params).fetchall()
        now = self.now()
        records = []
        for row in rows:
            record = dict(row)
            record["state"] = exception_state(record, now)
            if include_inactive or record["state"] == "active":
                records.append(record)
        return records

    def add_exception(
        self,
        *,
        module: str,
        name: str,
        sha256: str,
        reason: str,
        accepted_by: str,
        expires_on: str | None = None,
    ) -> dict[str, Any]:
        """Record an exception with its evidence row, in one transaction (data-model.md).

        The evidence (source ``exception``, URL ``exception:<id>``) is the record as canonical
        JSON. A second exception for the same global and hash is refused while one is active.
        """
        now = self.now()
        recorded_at = utc_text(now)
        with self._atomic():
            for row in self.conn.execute(
                "SELECT * FROM global_exceptions WHERE sha256 = ? AND module = ? AND name = ?",
                (sha256, module, name),
            ).fetchall():
                if exception_state(dict(row), now) == "active":
                    raise ValueError(
                        f"an active exception ({row['exception_id']}) already covers"
                        f" {module}.{name} in {sha256}"
                    )
            exception_id = self.conn.execute(
                "SELECT coalesce(max(exception_id), 0) + 1 FROM global_exceptions"
            ).fetchone()[0]
            record = {
                "exception_id": exception_id,
                "module": module,
                "name": name,
                "global": f"{module}.{name}",
                "sha256": sha256,
                "reason": reason,
                "accepted_by": accepted_by,
                "recorded_at": recorded_at,
                "expires_on": expires_on,
            }
            evidence_id = self._insert_evidence(
                source=EXCEPTION_SOURCE,
                url=f"{EXCEPTION_SOURCE}:{exception_id}",
                retrieved_at=now,
                matched_identifier=f"sha256:{sha256}",
                body=_canonical_json(record),
            )
            self.conn.execute(
                "INSERT INTO global_exceptions (exception_id, module, name, sha256, reason,"
                " accepted_by, recorded_at, expires_on, evidence_id)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    exception_id,
                    module,
                    name,
                    sha256,
                    reason,
                    accepted_by,
                    recorded_at,
                    expires_on,
                    evidence_id,
                ),
            )
        made = self.get_exception(exception_id)
        assert made is not None
        return made

    def get_exception(self, exception_id: int) -> dict[str, Any] | None:
        if "global_exceptions" not in self.tables():
            return None
        row = self.conn.execute(
            "SELECT * FROM global_exceptions WHERE exception_id = ?", (exception_id,)
        ).fetchone()
        if row is None:
            return None
        record = dict(row)
        record["state"] = exception_state(record, self.now())
        return record

    def revoke_exception(self, exception_id: int, *, by: str, reason: str) -> dict[str, Any]:
        """Revoke an active exception, recording who, when and why, with the revocation as a
        second evidence row of the exception (source ``exception``, URL ``exception:<id>``)."""
        if not by.strip():
            raise ValueError("a revocation needs the name of who revoked it")
        if not reason.strip():
            raise ValueError("a revocation needs a reason")
        now = self.now()
        with self._atomic():
            row = self.conn.execute(
                "SELECT * FROM global_exceptions WHERE exception_id = ?", (exception_id,)
            ).fetchone()
            if row is None:
                raise ValueError(f"no exception {exception_id}")
            state = exception_state(dict(row), now)
            if state != "active":
                raise ValueError(f"exception {exception_id} is not active (it is {state})")
            record = {
                "exception_id": exception_id,
                "global": f"{row['module']}.{row['name']}",
                "sha256": row["sha256"],
                "revoked_at": utc_text(now),
                "revoked_by": by.strip(),
                "revoke_reason": reason.strip(),
            }
            self._insert_evidence(
                source=EXCEPTION_SOURCE,
                url=f"{EXCEPTION_SOURCE}:{exception_id}",
                retrieved_at=now,
                matched_identifier=f"sha256:{row['sha256']}",
                body=_canonical_json(record),
            )
            self.conn.execute(
                "UPDATE global_exceptions SET revoked_at = ?, revoked_by = ?, revoke_reason = ?"
                " WHERE exception_id = ?",
                (record["revoked_at"], record["revoked_by"], record["revoke_reason"], exception_id),
            )
        revoked = self.get_exception(exception_id)
        assert revoked is not None
        return revoked

    def exception_evidence(self, exception_id: int) -> list[int]:
        """The exception's evidence rows, oldest first: its record, then any revocation."""
        rows = self.conn.execute(
            "SELECT evidence_id FROM evidence WHERE source = ? AND url = ? ORDER BY evidence_id",
            (EXCEPTION_SOURCE, f"{EXCEPTION_SOURCE}:{exception_id}"),
        )
        return [int(row["evidence_id"]) for row in rows]

    def set_alert_exception(
        self, alert_id: int, *, excepted_at: str | None, cause: Mapping[str, Any]
    ) -> None:
        """Mark an open alert excepted (``excepted_at`` set) or not, with its cause (S4, S8)."""
        with self.conn:
            cursor = self.conn.execute(
                "UPDATE alerts SET excepted_at = ?, cause = ?"
                " WHERE alert_id = ? AND state = 'open'",
                (excepted_at, json.dumps(cause), alert_id),
            )
        if cursor.rowcount != 1:
            raise ValueError(f"alert {alert_id} is not open")

    def pinned_to(self, sha256: str) -> list[dict[str, Any]]:
        """The model versions with a pinned weight entry for these bytes, and where it is."""
        rows = self.conn.execute(
            "SELECT model_id, version, location, hub_repo, hub_file FROM inventory_entries"
            " WHERE kind = 'weight_file' AND pinned = 1 AND identifier = ?"
            " ORDER BY model_id, version, entry_id",
            (f"sha256:{sha256}",),
        )
        return [
            {
                "model_id": row["model_id"],
                "version": row["version"],
                "location": row["location"] or f"hf:{row['hub_repo']}/{row['hub_file']}",
            }
            for row in rows
        ]

    def add_overview_rows(self, run_id: int, rows: Iterable[Mapping[str, Any]]) -> None:
        """Store a run's overview; a run-wide row (``model_id`` ``None``) is stored as ``''``."""
        columns = (
            "version", "source", "state", "reason", "entries", "incomplete", "alerts_open",
            "alerts_excepted", "watch_events", "dismissals_held",
        )  # fmt: skip
        with self.conn:
            self.conn.executemany(
                "INSERT OR REPLACE INTO check_run_overview (run_id, model_id,"
                f" {', '.join(columns)}) VALUES (?, ?, {', '.join('?' for _ in columns)})",
                [
                    (run_id, row["model_id"] or "", *(row.get(key) for key in columns))
                    for row in rows
                ],
            )

    def check_run_target_versions(self, run_id: int) -> list[tuple[str, int]]:
        """The models and versions a run checked, in model order."""
        rows = self.conn.execute(
            "SELECT model_id, version FROM check_run_targets WHERE run_id = ? ORDER BY model_id",
            (run_id,),
        )
        return [(row["model_id"], int(row["version"])) for row in rows]

    def check_run_source_order(self, run_id: int) -> list[str]:
        """The sources a run asked, in the order asked, then ``policy``."""
        run = self.get_check_run(run_id)
        sources = list((run or {}).get("sources") or {})
        return [*sources, "policy"]

    def check_run_overview(self, run_id: int) -> list[dict[str, Any]]:
        """The overview rows of a run; the run-wide rows read ``model_id`` as ``None``."""
        if "check_run_overview" not in self.tables():
            return []  # a database older than feature 004, opened read-only
        rows = self.conn.execute(
            "SELECT * FROM check_run_overview WHERE run_id = ? ORDER BY model_id, source",
            (run_id,),
        ).fetchall()
        return [{**dict(row), "model_id": row["model_id"] or None} for row in rows]

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
        *,
        base_dir: Path | str | None = None,
        registration_record_sha256: str | None = None,
        origin: str | None = None,
    ) -> int:
        """Record the next version of a model with its inventory and entries, all or nothing.

        ``base_dir`` is the directory that local weight-file locations are relative to (the
        manifest's or the imported inventory's), so a check can find the files to scan.
        ``registration_record_sha256`` is set when the local weight files were registered from a
        registration record, without their bytes (feature 005). ``origin`` is how the version was
        registered: ``manifest``, ``record`` or ``import`` (feature 003).
        """
        with self.conn:
            version = (self.latest_version(model_id) or 0) + 1
            self.conn.execute(
                "INSERT INTO model_versions (model_id, version, registered_at, manifest_sha256,"
                " inventory, base_dir, registration_record_sha256, origin)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    model_id,
                    version,
                    self._stamp(),
                    manifest_sha256,
                    json.dumps(inventory),
                    None if base_dir is None else str(Path(base_dir).resolve()),
                    registration_record_sha256,
                    origin,
                ),
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
        paper_dois = entry.get("paper_dois")
        self.conn.execute(
            "INSERT INTO inventory_entries (model_id, version, kind, identifier, pinned,"
            " gap_reason, location, size, format, can_run_code, hub_repo, hub_revision,"
            " hub_file, name, package_version, hashes, recorded_licence, licence_form,"
            " paper_dois, format_origin)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
                entry.get("recorded_licence"),
                entry.get("licence_form"),
                None if paper_dois is None else json.dumps(list(paper_dois)),
                entry.get("format_origin"),
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
            present = set(row.keys())  # a database read-only from before 003 lacks format_origin
            record = {
                name: row[name] if name in present else None
                for name in ENTRY_FIELDS
                if name != "version"
            }
            record["version"] = row["package_version"]
            record["pinned"] = bool(row["pinned"])
            record["can_run_code"] = _bool(row["can_run_code"])
            record["hashes"] = _loads(row["hashes"])
            record["paper_dois"] = _loads(row["paper_dois"])
            result.append(record)
        return result

    # --- claim checks (feature 003, data-model.md) ----------------------------------------------

    def add_claim_check(
        self,
        *,
        model_id: str,
        version: int,
        entry_identifier: str,
        claim: str,
        run_id: int | None,
        outcome: str,
        measured_format: str | None,
        measured_can_run_code: bool | None,
        reason: str | None,
        evidence_id: int,
    ) -> int:
        """Record one confirmation attempt of one entry's claim (``code_free`` or ``identity``)."""
        with self.conn:
            cursor = self.conn.execute(
                "INSERT INTO claim_checks (model_id, version, entry_identifier, claim, run_id,"
                " outcome, measured_format, measured_can_run_code, reason, evidence_id,"
                " checked_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    model_id,
                    version,
                    entry_identifier,
                    claim,
                    run_id,
                    outcome,
                    measured_format,
                    None if measured_can_run_code is None else int(bool(measured_can_run_code)),
                    reason,
                    evidence_id,
                    self._stamp(),
                ),
            )
        return int(cursor.lastrowid)

    @staticmethod
    def _claim_check(row: sqlite3.Row) -> dict[str, Any]:
        record = dict(row)
        record["measured_can_run_code"] = _bool(record["measured_can_run_code"])
        return record

    def latest_claim_check(
        self, model_id: str, version: int, identifier: str, *, claim: str = "code_free"
    ) -> dict[str, Any] | None:
        """The latest check of one entry's ``claim`` in a version, which decides its state."""
        if self.read_only and "claim_checks" not in self.tables():
            return None
        row = self.conn.execute(
            "SELECT * FROM claim_checks WHERE model_id = ? AND version = ?"
            " AND entry_identifier = ? AND claim = ? ORDER BY claim_check_id DESC LIMIT 1",
            (model_id, version, identifier, claim),
        ).fetchone()
        return None if row is None else self._claim_check(row)

    def claim_checks(self, model_id: str, version: int) -> list[dict[str, Any]]:
        """Every claim check of a version, oldest first."""
        if self.read_only and "claim_checks" not in self.tables():
            return []  # a database from before 003, read without upgrading it
        rows = self.conn.execute(
            "SELECT * FROM claim_checks WHERE model_id = ? AND version = ? ORDER BY claim_check_id",
            (model_id, version),
        ).fetchall()
        return [self._claim_check(row) for row in rows]

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

    def discard_body(self, digest: str) -> bool:
        """Delete a stored body that no evidence record and no ETag cache entry refers to.

        A body an evidence record refers to is never deleted (Principle I). Returns whether a file
        was deleted; a body already gone is not an error, so this is safe to repeat.
        """
        referenced = self.conn.execute(
            "SELECT 1 FROM evidence WHERE body_sha256 = ?"
            " UNION ALL SELECT 1 FROM etag_cache WHERE body_sha256 = ? LIMIT 1",
            (digest, digest),
        ).fetchone()
        if referenced is not None:
            return False
        try:
            (self.evidence_dir / digest).unlink()
        except FileNotFoundError:
            return False
        return True

    def prune_etag_cache(self, max_age_days: int = ETAG_CACHE_MAX_AGE_DAYS) -> int:
        """Drop ETag cache entries unused for ``max_age_days`` and their unreferenced bodies.

        An entry is used when it is stored or looked up; one stored before use times were kept
        ages from its retrieval. Returns how many entries were dropped.
        """
        cutoff = utc_text(self._now() - timedelta(days=max_age_days))
        with self.conn:
            rows = self.conn.execute(
                "SELECT url, body_sha256 FROM etag_cache WHERE COALESCE(used_at, retrieved_at) < ?",
                (cutoff,),
            ).fetchall()
            self.conn.executemany(
                "DELETE FROM etag_cache WHERE url = ?", [(row["url"],) for row in rows]
            )
        for digest in {row["body_sha256"] for row in rows}:
            self.discard_body(digest)
        return len(rows)

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
        original_sha256: str | None = None,
        redacted_fields: Iterable[str] = (),
    ) -> int:
        """Store ``body`` (already redacted where research U10 applies) and its evidence record.

        ``original_sha256`` is the hash of the response as received; it defaults to the stored
        body's hash, which is right for every source with nothing to redact. A JSON body also gets
        its ``canonical_sha256`` (feature 006).
        """
        with self.conn:
            return self._insert_evidence(
                source=source,
                url=url,
                retrieved_at=retrieved_at,
                matched_identifier=matched_identifier,
                body=body,
                detail=detail,
                run_id=run_id,
                original_sha256=original_sha256,
                redacted_fields=redacted_fields,
            )

    def _insert_evidence(
        self,
        *,
        source: str,
        url: str,
        retrieved_at: datetime,
        matched_identifier: str,
        body: bytes,
        detail: Mapping[str, Any] | None = None,
        run_id: int | None = None,
        original_sha256: str | None = None,
        redacted_fields: Iterable[str] = (),
    ) -> int:
        """The evidence insert of ``add_evidence``, inside the caller's transaction."""
        digest = self.put_body(body)
        cursor = self.conn.execute(
            "INSERT INTO evidence (source, url, retrieved_at, matched_identifier, body_sha256,"
            " detail, run_id, original_sha256, redacted_fields, canonical_sha256)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                source,
                url,
                utc_text(retrieved_at),
                matched_identifier,
                digest,
                None if detail is None else json.dumps(detail),
                run_id,
                original_sha256 or digest,
                json.dumps(sorted(redacted_fields)),
                canonical_sha256(body),
            ),
        )
        return int(cursor.lastrowid)

    def add_response_evidence(
        self,
        response: Any,
        *,
        source: str,
        matched_identifier: str,
        detail: Mapping[str, Any] | None = None,
        run_id: int | None = None,
    ) -> int:
        """Evidence for a fetcher ``Response``, keeping its original hash and redacted fields."""
        return self.add_evidence(
            source=source,
            url=response.url,
            retrieved_at=response.retrieved_at,
            matched_identifier=matched_identifier,
            body=response.body,
            detail=detail,
            run_id=run_id,
            original_sha256=response.original_sha256,
            redacted_fields=response.redacted_fields,
        )

    def get_evidence(self, evidence_id: int) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM evidence WHERE evidence_id = ?", (evidence_id,)
        ).fetchone()
        if row is None:
            return None
        record = dict(row)
        record["detail"] = _loads(record["detail"])
        record["redacted_fields"] = _loads(record["redacted_fields"])
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
        record = {"excepted_at": None, **dict(row)}  # null before feature 004 (read-only)
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

    def start_check_run(self, *, scope: str, trigger: str = "on_demand") -> int:
        """Start a run; ``trigger`` is ``scheduled`` only for ``check --all --scheduled`` (U7)."""
        with self.conn:
            cursor = self.conn.execute(
                "INSERT INTO check_runs (started_at, scope, trigger) VALUES (?, ?, ?)",
                (self._stamp(), scope, trigger),
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

    def latest_check_run(self, scopes: Iterable[str] | None = None) -> dict[str, Any] | None:
        """The latest check run, or the latest whose scope is one of ``scopes``."""
        query, params = "SELECT max(run_id) AS r FROM check_runs", tuple(scopes or ())
        if scopes is not None:
            query += " WHERE scope IN (" + ", ".join("?" for _ in params) + ")"
        row = self.conn.execute(query, params).fetchone()
        return None if row["r"] is None else self.get_check_run(row["r"])

    def check_runs_for(
        self, model_id: str, since: str, until: str | None = None
    ) -> list[dict[str, Any]]:
        """Finished runs started at or after ``since`` (and before ``until``, if given) whose scope
        covered the model, newest first. Each has ``version``: the version of the model it
        checked, or ``None`` when it has no target row for it, and ``legacy``: whether the run
        was recorded before runs recorded their targets (``first_linked_run``).

        A run covers the model when its scope is ``all`` or names it (``check ID`` records the
        id; a run over several models records them joined by commas).
        """
        query = "SELECT * FROM check_runs WHERE finished_at IS NOT NULL AND started_at >= ?"
        params: tuple[str, ...] = (since,)
        if until is not None:
            query += " AND started_at < ?"
            params += (until,)
        rows = self.conn.execute(query + " ORDER BY run_id DESC", params).fetchall()
        linked: dict[int, int] = {}
        if "check_run_targets" in self.tables():  # absent from a read-only older database
            linked = {
                int(row["run_id"]): int(row["version"])
                for row in self.conn.execute(
                    "SELECT run_id, version FROM check_run_targets WHERE model_id = ?",
                    (model_id,),
                )
            }
        first = self.first_linked_run()
        runs = []
        for row in rows:
            if row["scope"] != SCOPE_ALL and model_id not in str(row["scope"]).split(","):
                continue
            record = dict(row)
            record["sources"] = _loads(record["sources"]) or {}
            record["version"] = linked.get(record["run_id"])
            record["legacy"] = first is None or record["run_id"] < first
            runs.append(record)
        return runs

    def add_check_run_target(self, run_id: int, model_id: str, version: int) -> None:
        """Record that run ``run_id`` checked ``version`` of ``model_id`` (G1)."""
        with self.conn:
            self.conn.execute(
                "INSERT OR IGNORE INTO check_run_targets (run_id, model_id, version)"
                " VALUES (?, ?, ?)",
                (run_id, model_id, version),
            )

    def registered_at(self, model_id: str, version: int) -> str | None:
        row = self.conn.execute(
            "SELECT registered_at FROM model_versions WHERE model_id = ? AND version = ?",
            (model_id, version),
        ).fetchone()
        return None if row is None else str(row["registered_at"])

    # --- models, alerts and watch events as the checks use them -------------------------------

    def model_ids(self) -> list[str]:
        return [
            row["model_id"]
            for row in self.conn.execute("SELECT model_id FROM models ORDER BY model_id")
        ]

    def latest_alert(self, model_id: str, cause_key: str) -> dict[str, Any] | None:
        """The most recent alert for the model and cause, in any state (FR-020, research S13)."""
        row = self.conn.execute(
            "SELECT max(alert_id) AS alert_id FROM alerts WHERE model_id = ? AND cause_key = ?",
            (model_id, cause_key),
        ).fetchone()
        return None if row["alert_id"] is None else self.get_alert(row["alert_id"])

    def find_open_alert(self, model_id: str, cause_key: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT alert_id FROM alerts WHERE model_id = ? AND cause_key = ? AND state = 'open'",
            (model_id, cause_key),
        ).fetchone()
        return None if row is None else self.get_alert(row["alert_id"])

    def update_open_alert(
        self,
        alert_id: int,
        *,
        current_version: int,
        severity: str,
        severity_origin: str,
        cause: Mapping[str, Any],
        cause_key: str | None = None,
    ) -> None:
        """Carry an open alert forward with the source's current values (FR-010).

        ``cause_key`` rekeys it, as when an alias group's primary id changes (feature 006).
        """
        with self.conn:
            cursor = self.conn.execute(
                "UPDATE alerts SET current_version = ?, severity = ?, severity_origin = ?,"
                " cause = ?, cause_key = COALESCE(?, cause_key)"
                " WHERE alert_id = ? AND state = 'open'",
                (
                    current_version,
                    severity,
                    severity_origin,
                    json.dumps(cause),
                    cause_key,
                    alert_id,
                ),
            )
        if cursor.rowcount != 1:
            raise ValueError(f"alert {alert_id} is not open")

    def link_alert_evidence(self, alert_id: int, evidence_id: int) -> None:
        with self.conn:
            self.conn.execute(
                "INSERT OR IGNORE INTO alert_evidence (alert_id, evidence_id) VALUES (?, ?)",
                (alert_id, evidence_id),
            )

    def alerts_for(
        self, model_id: str, states: Iterable[str] | None = None
    ) -> list[dict[str, Any]]:
        wanted = None if states is None else set(states)
        rows = self.conn.execute(
            "SELECT alert_id, state FROM alerts WHERE model_id = ? ORDER BY alert_id", (model_id,)
        )
        ids = [row["alert_id"] for row in rows if wanted is None or row["state"] in wanted]
        return [alert for alert in (self.get_alert(alert_id) for alert_id in ids) if alert]

    def alert_evidence(self, alert_id: int) -> list[dict[str, Any]]:
        alert = self.get_alert(alert_id)
        if alert is None:
            return []
        return [record for record in map(self.get_evidence, alert["evidence_ids"]) if record]

    # --- advisories ----------------------------------------------------------------------------

    def upsert_advisory(
        self,
        *,
        source: str,
        advisory_id: str,
        aliases: Iterable[str],
        modified: str | None,
        withdrawn: str | None,
        severity: str,
        severity_origin: str,
        affected: Any,
        evidence_id: int,
    ) -> None:
        """Keep the latest copy of a published record (data-model.md, Advisory)."""
        with self.conn:
            self.conn.execute(
                "INSERT INTO advisories (source, advisory_id, aliases, modified, withdrawn,"
                " severity, severity_origin, affected, evidence_id)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
                " ON CONFLICT (source, advisory_id) DO UPDATE SET aliases = excluded.aliases,"
                " modified = excluded.modified, withdrawn = excluded.withdrawn,"
                " severity = excluded.severity, severity_origin = excluded.severity_origin,"
                " affected = excluded.affected, evidence_id = excluded.evidence_id",
                (
                    source,
                    advisory_id,
                    json.dumps(list(aliases)),
                    modified,
                    withdrawn,
                    severity,
                    severity_origin,
                    json.dumps(affected),
                    evidence_id,
                ),
            )

    def get_advisory(self, source: str, advisory_id: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM advisories WHERE source = ? AND advisory_id = ?", (source, advisory_id)
        ).fetchone()
        if row is None:
            return None
        record = dict(row)
        record["aliases"] = _loads(record["aliases"])
        record["affected"] = _loads(record["affected"])
        return record

    # --- watch events --------------------------------------------------------------------------

    def get_watch_event(
        self, model_id: str, version: int, entry_identifier: str, kind: str
    ) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM watch_events WHERE model_id = ? AND version = ?"
            " AND entry_identifier = ? AND kind = ?",
            (model_id, version, entry_identifier, kind),
        ).fetchone()
        return None if row is None else self._watch_event(row)

    def _watch_event(self, row: sqlite3.Row) -> dict[str, Any]:
        record = dict(row)
        record["detail"] = _loads(record["detail"])
        links = self.conn.execute(
            "SELECT evidence_id FROM watch_event_evidence WHERE watch_event_id = ?"
            " ORDER BY evidence_id",
            (record["watch_event_id"],),
        )
        record["evidence"] = [self.get_evidence(link["evidence_id"]) for link in links]
        return record

    def record_watch_event(
        self,
        *,
        model_id: str,
        version: int,
        entry_identifier: str,
        kind: str,
        detail: Mapping[str, Any],
        evidence_ids: Iterable[int],
    ) -> int:
        """One record per model version, entry and kind; a repeat updates it (data-model.md)."""
        stamp = self._stamp()
        with self.conn:
            self.conn.execute(
                "INSERT INTO watch_events (model_id, version, entry_identifier, kind, detail,"
                " first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?)"
                " ON CONFLICT (model_id, version, entry_identifier, kind) DO UPDATE SET"
                " detail = excluded.detail, last_seen = excluded.last_seen",
                (model_id, version, entry_identifier, kind, json.dumps(detail), stamp, stamp),
            )
            row = self.conn.execute(
                "SELECT watch_event_id FROM watch_events WHERE model_id = ? AND version = ?"
                " AND entry_identifier = ? AND kind = ?",
                (model_id, version, entry_identifier, kind),
            ).fetchone()
            watch_event_id = int(row["watch_event_id"])
            self.conn.executemany(
                "INSERT OR IGNORE INTO watch_event_evidence (watch_event_id, evidence_id)"
                " VALUES (?, ?)",
                [(watch_event_id, evidence_id) for evidence_id in evidence_ids],
            )
        return watch_event_id

    def watch_events(self, model_id: str, version: int | None = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM watch_events WHERE model_id = ?"
        params: tuple[Any, ...] = (model_id,)
        if version is not None:
            query += " AND version = ?"
            params += (version,)
        rows = self.conn.execute(query + " ORDER BY watch_event_id", params).fetchall()
        return [self._watch_event(row) for row in rows]

    # --- upstream observations (feature 002, data-model.md) -------------------------------------

    def add_observation(self, *, run_id: int, source: str, item: str, **fields: Any) -> int:
        """Record what one run saw for one upstream item from one source."""
        unknown = set(fields) - set(_OBSERVATION_FIELDS)
        if unknown:
            raise ValueError(f"unknown observation fields: {sorted(unknown)}")
        values = dict.fromkeys(_OBSERVATION_FIELDS) | fields
        for name in _OBSERVATION_JSON:
            if values[name] is not None:
                values[name] = json.dumps(values[name])
        if values["disabled"] is not None:
            values["disabled"] = int(bool(values["disabled"]))
        columns = ("run_id", "source", "item", *_OBSERVATION_FIELDS, "observed_at")
        params = (run_id, source, item, *(values[name] for name in _OBSERVATION_FIELDS))
        with self.conn:
            cursor = self.conn.execute(
                f"INSERT INTO upstream_observations ({', '.join(columns)})"
                f" VALUES ({', '.join('?' for _ in columns)})",
                (*params, self._stamp()),
            )
        return int(cursor.lastrowid)

    def _observation(self, row: sqlite3.Row) -> dict[str, Any]:
        record = dict(row)
        for name in _OBSERVATION_JSON:
            record[name] = _loads(record[name])
        record["disabled"] = _bool(record["disabled"])
        return record

    _OBSERVATION_QUERY = (
        "SELECT o.*, r.trigger AS trigger FROM upstream_observations o"
        " JOIN check_runs r ON r.run_id = o.run_id"
    )

    def get_observation(self, observation_id: int) -> dict[str, Any] | None:
        row = self.conn.execute(
            self._OBSERVATION_QUERY + " WHERE o.observation_id = ?", (observation_id,)
        ).fetchone()
        return None if row is None else self._observation(row)

    def observations(self, item: str, source: str | None = None) -> list[dict[str, Any]]:
        """Observations of ``item`` (from ``source`` if given), oldest first."""
        query, params = self._OBSERVATION_QUERY + " WHERE o.item = ?", (item,)
        if source is not None:
            query, params = query + " AND o.source = ?", (*params, source)
        rows = self.conn.execute(query + " ORDER BY o.observation_id", params).fetchall()
        return [self._observation(row) for row in rows]

    def observations_in_repository(self, repository: str) -> list[dict[str, Any]]:
        """Observations of every revision of a hub repository (``repository@<revision>`` items,
        or the repository itself), oldest first."""
        prefix = f"{repository}@"
        rows = self.conn.execute(
            self._OBSERVATION_QUERY + " WHERE o.item = ? OR substr(o.item, 1, ?) = ?"
            " ORDER BY o.observation_id",
            (repository, len(prefix), prefix),
        ).fetchall()
        return [self._observation(row) for row in rows]

    def previous_observation(self, item: str, source: str, before: int) -> dict[str, Any] | None:
        """The latest observation of ``item`` from ``source`` older than observation ``before``."""
        row = self.conn.execute(
            self._OBSERVATION_QUERY + " WHERE o.item = ? AND o.source = ? AND o.observation_id < ?"
            " ORDER BY o.observation_id DESC LIMIT 1",
            (item, source, before),
        ).fetchone()
        return None if row is None else self._observation(row)

    # --- DOI routing (research U1) --------------------------------------------------------------

    def get_routing(self, doi: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM doi_routing WHERE doi = ?", (doi.lower(),)
        ).fetchone()
        return None if row is None else dict(row)

    _UNSET: Any = object()

    def set_routing(
        self,
        doi: str,
        *,
        agency: Any = _UNSET,
        repository: Any = _UNSET,
        repository_id: Any = _UNSET,
    ) -> None:
        """Create or update a DOI's routing; fields not given keep their stored value."""
        doi = doi.lower()
        current = self.get_routing(doi) or {
            "agency": None,
            "repository": None,
            "repository_id": None,
        }
        given = {"agency": agency, "repository": repository, "repository_id": repository_id}
        values = {k: (current[k] if v is self._UNSET else v) for k, v in given.items()}
        with self.conn:
            self.conn.execute(
                "INSERT INTO doi_routing (doi, agency, repository, repository_id, looked_up_at)"
                " VALUES (?, ?, ?, ?, ?) ON CONFLICT (doi) DO UPDATE SET agency = excluded.agency,"
                " repository = excluded.repository, repository_id = excluded.repository_id,"
                " looked_up_at = excluded.looked_up_at",
                (
                    doi,
                    values["agency"],
                    values["repository"],
                    values["repository_id"],
                    self._stamp(),
                ),
            )

    # --- takedown log (research U5) -------------------------------------------------------------

    def replace_takedown_notices(self, rows: Iterable[Mapping[str, Any]]) -> None:
        """Replace the cached takedown log; a row with any other column is refused."""
        rows = list(rows)
        for row in rows:
            unknown = set(row) - set(TAKEDOWN_FIELDS)
            if unknown:
                raise ValueError(
                    f"takedown notices keep only {TAKEDOWN_FIELDS}; got {sorted(unknown)}"
                )
        with self.conn:
            self.conn.execute("DELETE FROM takedown_notices")
            self.conn.executemany(
                "INSERT INTO takedown_notices (date, reported_content) VALUES (?, ?)",
                [(row["date"], row["reported_content"]) for row in rows],
            )

    def takedown_notices(self) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT date, reported_content FROM takedown_notices ORDER BY notice_id"
        )
        return [dict(row) for row in rows]


# Headers that are never kept in the ETag cache: they belong to one exchange, not to the body.
_UNCACHED_HEADERS = frozenset({"set-cookie", "set-cookie2", "date", "age"})


class EtagCache(MutableMapping[str, Response]):
    """The fetcher's ETag cache kept in the store, so it lasts across runs (research U13).

    ``UrlFetcher`` stores a ``2xx`` response that carries an ETag, after its body has passed
    through the source's redaction rule, and later sends that ETag in ``If-None-Match``; a
    ``304`` then serves the cached response with the new retrieval time. The body is written to
    the evidence store by its SHA-256, so only the redacted body is ever kept. A row whose body is
    missing or no longer matches its hash is a miss, and the next request is unconditional.

    A lookup that finds a body marks the entry used, so ``Store.prune_etag_cache`` drops only
    entries no run has needed for ``ETAG_CACHE_MAX_AGE_DAYS``. Replacing or deleting an entry
    deletes its previous body unless evidence or another entry refers to it.
    """

    def __init__(self, store: Store) -> None:
        self._store = store

    def __getitem__(self, url: str) -> Response:
        row = self._store.conn.execute("SELECT * FROM etag_cache WHERE url = ?", (url,)).fetchone()
        if row is None:
            raise KeyError(url)
        try:
            body = self._store.read_body(row["body_sha256"])
        except (OSError, ValueError):
            raise KeyError(url) from None
        with self._store.conn:
            self._store.conn.execute(
                "UPDATE etag_cache SET used_at = ? WHERE url = ?", (self._store._stamp(), url)
            )
        return Response(
            status=row["status"],
            body=body,
            url=row["url"],
            retrieved_at=datetime.strptime(row["retrieved_at"], "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=UTC
            ),
            headers=Headers(json.loads(row["headers"])),
            original_sha256=row["original_sha256"],
            redacted_fields=tuple(json.loads(row["redacted_fields"])),
        )

    def __setitem__(self, url: str, response: Response) -> None:
        etag = response.headers.get("ETag")
        if not etag:
            raise ValueError("only a response with an ETag can be cached")
        headers = {k: v for k, v in response.headers.items() if k not in _UNCACHED_HEADERS}
        digest = self._store.put_body(response.body)
        previous = self._body_of(url)
        with self._store.conn:
            self._store.conn.execute(
                "INSERT OR REPLACE INTO etag_cache (url, etag, status, headers, body_sha256,"
                " original_sha256, redacted_fields, retrieved_at, used_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    url,
                    etag,
                    response.status,
                    json.dumps(headers, sort_keys=True),
                    digest,
                    response.original_sha256,
                    json.dumps(list(response.redacted_fields)),
                    utc_text(response.retrieved_at),
                    self._store._stamp(),
                ),
            )
        if previous is not None and previous != digest:
            self._store.discard_body(previous)

    def _body_of(self, url: str) -> str | None:
        row = self._store.conn.execute(
            "SELECT body_sha256 FROM etag_cache WHERE url = ?", (url,)
        ).fetchone()
        return None if row is None else str(row["body_sha256"])

    def __delitem__(self, url: str) -> None:
        previous = self._body_of(url)
        with self._store.conn:
            deleted = self._store.conn.execute("DELETE FROM etag_cache WHERE url = ?", (url,))
        if deleted.rowcount == 0:
            raise KeyError(url)
        if previous is not None:
            self._store.discard_body(previous)

    def __iter__(self) -> Iterator[str]:
        rows = self._store.conn.execute("SELECT url FROM etag_cache ORDER BY url").fetchall()
        return iter([row["url"] for row in rows])

    def __len__(self) -> int:
        return int(self._store.conn.execute("SELECT COUNT(*) FROM etag_cache").fetchone()[0])

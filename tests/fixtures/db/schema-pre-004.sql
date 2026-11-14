-- The store schema of main at c07c14d, before feature 004, with a few rows (tests/fixtures/db/NOTES.md).
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
    base_dir TEXT,
    registration_record_sha256 TEXT,
    origin TEXT CHECK (origin IS NULL OR origin IN ('manifest', 'record', 'import')),
    PRIMARY KEY (model_id, version)
);

CREATE TABLE IF NOT EXISTS inventory_entries (
    entry_id INTEGER PRIMARY KEY,
    model_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('weight_file', 'package', 'base_model', 'dataset')),
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
    licence_form TEXT CHECK (licence_form IS NULL OR licence_form IN ('spdx', 'expression', 'unrecognised', 'none')),
    paper_dois TEXT,
    format_origin TEXT CHECK (format_origin IS NULL OR format_origin IN ('bytes', 'name', 'record', 'import')),
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
    trigger TEXT NOT NULL DEFAULT 'on_demand' CHECK (trigger IN ('scheduled', 'on_demand'))
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
    outcome TEXT NOT NULL CHECK (outcome IN ('reachable', 'refused', 'not_found', 'removed', 'redirected')),
    disabled INTEGER CHECK (disabled IS NULL OR disabled IN (0, 1)),
    gated TEXT,
    head_revision TEXT,
    declared_licence TEXT,
    licence_form TEXT CHECK (licence_form IS NULL OR licence_form IN ('spdx', 'expression', 'unrecognised', 'none')),
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
    repository TEXT CHECK (repository IS NULL OR repository IN ('zenodo', 'figshare', 'other')),
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
    kind TEXT NOT NULL CHECK (kind IN ('package_advisory', 'weight_file_scan', 'hub_scan', 'format_policy', 'dataset_retracted', 'paper_retracted', 'dataset_removed', 'dataset_not_findable', 'licence_changed', 'base_model_disabled', 'base_model_unavailable')),
    cause_key TEXT NOT NULL,
    cause TEXT NOT NULL,
    severity TEXT NOT NULL,
    severity_origin TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'open' CHECK (state IN ('open', 'fixed', 'dismissed', 'withdrawn', 'cleared')),
    opened_at TEXT NOT NULL,
    closed_at TEXT,
    closed_by_version INTEGER,
    dismissal_reason TEXT CHECK (dismissal_reason IS NULL OR dismissal_reason IN
        ('not_used_at_runtime', 'risk_accepted', 'false_positive', 'fix_not_available')),
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
    kind TEXT NOT NULL CHECK (kind IN ('pickle_format', 'scan_suspicious', 'scan_incomplete', 'hub_scan_unknown', 'advisory_unmatched', 'hash_mismatch', 'base_model_new_revision', 'base_model_new_version_pointer', 'gating_changed', 'card_changed', 'base_model_refused', 'base_model_unrecognised', 'base_model_moved', 'dataset_new_version', 'dataset_replaced', 'dataset_moved', 'dataset_unreachable', 'paper_not_found', 'licence_unrecognised', 'licence_missing', 'upstream_notice', 'weight_file_absent', 'advisory_gone', 'format_claim_contradicted', 'format_claim_unreadable')),
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
    claim TEXT NOT NULL CHECK (claim IN ('code_free', 'identity')),
    run_id INTEGER REFERENCES check_runs (run_id),
    outcome TEXT NOT NULL CHECK (outcome IN ('confirmed', 'contradicted', 'unreadable')),
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

-- FR-005: a recorded model version and its inventory never change.
CREATE TRIGGER IF NOT EXISTS model_versions_no_update BEFORE UPDATE ON model_versions
BEGIN SELECT RAISE(ABORT, 'a recorded model version is immutable (FR-005)'); END;
CREATE TRIGGER IF NOT EXISTS model_versions_no_delete BEFORE DELETE ON model_versions
BEGIN SELECT RAISE(ABORT, 'a recorded model version is immutable (FR-005)'); END;
CREATE TRIGGER IF NOT EXISTS inventory_entries_no_update BEFORE UPDATE ON inventory_entries
BEGIN SELECT RAISE(ABORT, 'a recorded inventory entry is immutable (FR-005)'); END;
CREATE TRIGGER IF NOT EXISTS inventory_entries_no_delete BEFORE DELETE ON inventory_entries
BEGIN SELECT RAISE(ABORT, 'a recorded inventory entry is immutable (FR-005)'); END;

-- Rows written by the tool before feature 004 (tests/fixtures/db/NOTES.md).
INSERT INTO models (model_id, name, owner, created_at) VALUES ('legacy', 'Legacy model', 'Owner', '2026-11-01T00:00:00Z');
INSERT INTO model_versions (model_id, version, registered_at, manifest_sha256, inventory, origin) VALUES ('legacy', 1, '2026-11-01T00:00:00Z', 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', '{}', 'manifest');
INSERT INTO inventory_entries (model_id, version, kind, identifier, pinned, location, format, can_run_code, format_origin) VALUES ('legacy', 1, 'weight_file', 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 1, 'weights/model.pt', 'pytorch-zip', 1, 'bytes');
INSERT INTO check_runs (run_id, started_at, finished_at, scope, sources, trigger) VALUES (1, '2026-11-02T00:00:00Z', '2026-11-02T00:01:00Z', 'legacy', '{"picklescan": "ok"}', 'on_demand');
INSERT INTO check_run_targets (run_id, model_id, version) VALUES (1, 'legacy', 1);
INSERT INTO evidence (evidence_id, source, url, retrieved_at, matched_identifier, body_sha256, detail, run_id, original_sha256, redacted_fields, canonical_sha256) VALUES (1, 'picklescan', 'file:///weights/model.pt', '2026-11-02T00:00:30Z', 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc', '{"dangerous": ["os.system"]}', 1, 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc', '[]', 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd');
INSERT INTO alerts (alert_id, model_id, opened_in_version, current_version, kind, cause_key, cause, severity, severity_origin, state, opened_at) VALUES (1, 'legacy', 1, 1, 'weight_file_scan', 'weight_file_scan:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', '{"identifier": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "dangerous": ["os.system"]}', 'HIGH', 'policy', 'open', '2026-11-02T00:00:40Z');
INSERT INTO alert_evidence (alert_id, evidence_id) VALUES (1, 1);
INSERT INTO alerts (alert_id, model_id, opened_in_version, current_version, kind, cause_key, cause, severity, severity_origin, state, opened_at, closed_at, dismissal_reason, dismissed_by, note) VALUES (2, 'legacy', 1, 1, 'format_policy', 'format_policy:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', '{"identifier": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "policy": "strict"}', 'MODERATE', 'policy', 'dismissed', '2026-11-02T00:00:40Z', '2026-11-03T00:00:00Z', 'risk_accepted', 'Owner', 'reviewed');
INSERT INTO alert_evidence (alert_id, evidence_id) VALUES (2, 1);

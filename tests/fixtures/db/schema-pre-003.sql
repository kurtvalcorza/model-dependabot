-- The store schema of main at 308e323, before feature 003 (tests/fixtures/db/NOTES.md).
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
    kind TEXT NOT NULL CHECK (kind IN ('pickle_format', 'scan_suspicious', 'scan_incomplete', 'hub_scan_unknown', 'advisory_unmatched', 'hash_mismatch', 'base_model_new_revision', 'base_model_new_version_pointer', 'gating_changed', 'card_changed', 'base_model_refused', 'base_model_unrecognised', 'base_model_moved', 'dataset_new_version', 'dataset_replaced', 'dataset_moved', 'dataset_unreachable', 'paper_not_found', 'licence_unrecognised', 'licence_missing', 'upstream_notice', 'weight_file_absent', 'advisory_gone')),
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

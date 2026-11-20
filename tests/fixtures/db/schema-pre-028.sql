-- The store schema of main at 0c2a5ee, before issue #28 (lock markers), with a few rows (tests/fixtures/db/NOTES.md).
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
    kind TEXT NOT NULL CHECK (kind IN ('package_advisory', 'weight_file_scan', 'hub_scan', 'format_policy', 'dataset_retracted', 'paper_retracted', 'dataset_removed', 'dataset_not_findable', 'licence_changed', 'base_model_disabled', 'base_model_unavailable', 'globals_policy')),
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
    kind TEXT NOT NULL CHECK (kind IN ('pickle_format', 'scan_suspicious', 'scan_incomplete', 'hub_scan_unknown', 'advisory_unmatched', 'hash_mismatch', 'base_model_new_revision', 'base_model_new_version_pointer', 'gating_changed', 'card_changed', 'base_model_refused', 'base_model_unrecognised', 'base_model_moved', 'dataset_new_version', 'dataset_replaced', 'dataset_moved', 'dataset_unreachable', 'paper_not_found', 'licence_unrecognised', 'licence_missing', 'upstream_notice', 'weight_file_absent', 'advisory_gone', 'format_claim_contradicted', 'format_claim_unreadable', 'lineage_inherited')),
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

-- Issue #18: the latest ``globals-snapshot`` row of a model's file (``latest_globals_snapshot``).
-- Created on open like every index here, so an existing database gains it without a migration.
CREATE INDEX IF NOT EXISTS evidence_by_source_url_match
    ON evidence (source, url, matched_identifier);

-- Feature 004 (data-model.md, Check overview): one row per run, model and source, plus one row per
-- source for the run as a whole, stored with ``model_id = ''`` so the key holds for it too.
CREATE TABLE IF NOT EXISTS check_run_overview (
    run_id INTEGER NOT NULL REFERENCES check_runs (run_id),
    model_id TEXT NOT NULL,
    version INTEGER,
    source TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('passed', 'alerted', 'incomplete', 'failed')),
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

-- Feature 011 (data-model.md, Lineage edge): one row per edge identity of a model version.
CREATE TABLE IF NOT EXISTS lineage_edges (
    edge_id INTEGER PRIMARY KEY,
    model_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    position INTEGER NOT NULL CHECK (position >= 0),
    parent_kind TEXT NOT NULL CHECK (parent_kind IN ('hub', 'model')),
    parent_repo TEXT,
    parent_revision TEXT,
    parent_model_id TEXT,
    parent_version INTEGER CHECK (parent_version IS NULL OR parent_version >= 1),
    relationship TEXT NOT NULL CHECK (relationship IN ('fine-tuned-from', 'adapter-for', 'merged-from', 'quantized-from', 'unspecified')),
    relationship_recorded TEXT,
    origin TEXT NOT NULL CHECK (origin IN ('manifest', 'record', 'import')),
    claimed_origin TEXT,
    source_file TEXT,
    source_sha256 TEXT,
    source_key TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('owner', 'unverified')),
    gap_reason TEXT,
    entry_identifier TEXT,
    declared_count INTEGER NOT NULL DEFAULT 1 CHECK (declared_count >= 1),
    FOREIGN KEY (model_id, version) REFERENCES model_versions (model_id, version),
    UNIQUE (model_id, version, position),
    CHECK (parent_kind = 'model' OR (parent_model_id IS NULL AND parent_version IS NULL)),
    CHECK (parent_kind = 'hub' OR (parent_model_id IS NOT NULL AND parent_repo IS NULL
        AND parent_revision IS NULL))
);

-- FR-023: edge identity. An edge without a parent identity is keyed by its source key (review R2).
CREATE UNIQUE INDEX IF NOT EXISTS lineage_edge_identity ON lineage_edges (
    model_id, version, parent_kind, COALESCE(lower(parent_repo), ''),
    COALESCE(parent_revision, ''), COALESCE(parent_model_id, ''), COALESCE(parent_version, 0),
    relationship,
    CASE WHEN parent_repo IS NULL AND parent_model_id IS NULL THEN source_key ELSE '' END
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
CREATE TRIGGER IF NOT EXISTS lineage_edges_no_update BEFORE UPDATE ON lineage_edges
BEGIN SELECT RAISE(ABORT, 'a recorded lineage edge is immutable (FR-005)'); END;
CREATE TRIGGER IF NOT EXISTS lineage_edges_no_delete BEFORE DELETE ON lineage_edges
BEGIN SELECT RAISE(ABORT, 'a recorded lineage edge is immutable (FR-005)'); END;
-- Rows written by the tool before issue #28 (tests/fixtures/db/NOTES.md).
INSERT INTO models (model_id, name, owner, created_at) VALUES ('legacy', 'Legacy model', 'Owner', '2026-11-01T00:00:00Z');
INSERT INTO model_versions (model_id, version, registered_at, manifest_sha256, inventory, origin) VALUES ('legacy', 1, '2026-11-01T00:00:00Z', 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', '{}', 'import');
INSERT INTO inventory_entries (model_id, version, kind, identifier, pinned, name, package_version, hashes) VALUES ('legacy', 1, 'package', 'pkg:pypi/pillow@9.0.0', 1, 'pillow', '9.0.0', '["sha256:3b8182a766685eaa002637e28b4ec8d6b18819a0c71f579bf0dbaa5830297cce"]');
INSERT INTO model_versions (model_id, version, registered_at, manifest_sha256, inventory, origin) VALUES ('legacy', 2, '2026-11-02T00:00:00Z', 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee', '{}', 'manifest');
INSERT INTO inventory_entries (model_id, version, kind, identifier, pinned, name, package_version, hashes) VALUES ('legacy', 2, 'package', 'pkg:pypi/pillow@9.0.0', 1, 'pillow', '9.0.0', '["sha256:3b8182a766685eaa002637e28b4ec8d6b18819a0c71f579bf0dbaa5830297cce"]');
INSERT INTO check_runs (run_id, started_at, finished_at, scope, sources, trigger) VALUES (1, '2026-11-03T00:00:00Z', '2026-11-03T00:01:00Z', 'legacy', '{"osv.dev": "ok"}', 'on_demand');
INSERT INTO check_run_targets (run_id, model_id, version) VALUES (1, 'legacy', 2);
INSERT INTO evidence (evidence_id, source, url, retrieved_at, matched_identifier, body_sha256, detail, run_id, original_sha256, redacted_fields, canonical_sha256) VALUES (1, 'osv.dev', 'https://api.osv.dev/v1/vulns/GHSA-cp9v-662q-vvx9', '2026-11-03T00:00:30Z', 'pkg:pypi/pillow@9.0.0', 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc', '{}', 1, 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc', '[]', 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd');
INSERT INTO alerts (alert_id, model_id, opened_in_version, current_version, kind, cause_key, cause, severity, severity_origin, state, opened_at) VALUES (1, 'legacy', 1, 2, 'package_advisory', 'package_advisory:GHSA-cp9v-662q-vvx9:pillow', '{"advisory_id": "GHSA-cp9v-662q-vvx9", "advisory_ids": ["GHSA-cp9v-662q-vvx9"], "aliases": [], "source": "osv.dev", "package": "pillow", "version": "9.0.0", "identifier": "pkg:pypi/pillow@9.0.0", "affected": [], "fixed": ["9.0.1"]}', 'HIGH', 'database_specific', 'open', '2026-11-03T00:00:40Z');
INSERT INTO alert_evidence (alert_id, evidence_id) VALUES (1, 1);

-- ============================================================================
-- schema_migration_v43.sql
--
-- adaudit.py 0.10.0: pushing evaluation runs to the FortifyData AD audit
-- ingest API (adaudit_push.py).
--
--   * control_evidence_run gains a lifecycle (status 'running' / 'complete'
--     / 'aborted', completed_at), is_filtered, and push state (run_uuid,
--     push_status, push attempts and errors, the API's own run id). Until
--     now a run row was committed when the run started and each plugin's
--     results committed separately, so an interrupted run looked the same
--     as a finished one.
--   * control_evidence_run_plugin: the per-run plugin roster (each finding
--     plugin's result: pass / warn / fail / error / not_assessed). The API
--     closes a finding as remediated only when its plugin is in the roster
--     with a clean result, so the roster must be stored to push (and later
--     replay) a run honestly. Until now it existed only in memory.
--   * push_catalogue_state: which plugin catalogue (plugin_id + version
--     set) was last sent to each API server, so it is re-sent only when it
--     changes.
--
-- Runs recorded before this migration have no roster, so they cannot be
-- pushed accurately: they are marked push_status 'legacy' and never pushed.
-- The first run after the upgrade is pushed with every open finding as NEW.
-- ============================================================================

BEGIN;

ALTER TABLE ad_intel.control_evidence_run
    ADD COLUMN IF NOT EXISTS status text,
    ADD COLUMN IF NOT EXISTS completed_at timestamptz,
    ADD COLUMN IF NOT EXISTS is_filtered boolean NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS run_uuid uuid,
    ADD COLUMN IF NOT EXISTS push_status text,
    ADD COLUMN IF NOT EXISTS push_attempts integer NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS last_push_attempt_at timestamptz,
    ADD COLUMN IF NOT EXISTS last_push_error text,
    ADD COLUMN IF NOT EXISTS pushed_at timestamptz,
    ADD COLUMN IF NOT EXISTS push_server_run_id bigint;

-- Existing runs: they ran to whatever end they reached, and predate rosters.
UPDATE ad_intel.control_evidence_run
   SET status = 'complete', completed_at = COALESCE(completed_at, executed_at)
 WHERE status IS NULL;
UPDATE ad_intel.control_evidence_run
   SET push_status = 'legacy'
 WHERE push_status IS NULL;

ALTER TABLE ad_intel.control_evidence_run
    ALTER COLUMN status SET DEFAULT 'running',
    ALTER COLUMN status SET NOT NULL,
    ALTER COLUMN push_status SET DEFAULT 'pending',
    ALTER COLUMN push_status SET NOT NULL;

ALTER TABLE ad_intel.control_evidence_run
    DROP CONSTRAINT IF EXISTS control_evidence_run_status_check;
ALTER TABLE ad_intel.control_evidence_run
    ADD CONSTRAINT control_evidence_run_status_check
    CHECK (status IN ('running', 'complete', 'aborted'));
ALTER TABLE ad_intel.control_evidence_run
    DROP CONSTRAINT IF EXISTS control_evidence_run_push_status_check;
ALTER TABLE ad_intel.control_evidence_run
    ADD CONSTRAINT control_evidence_run_push_status_check
    CHECK (push_status IN ('pending', 'pushed', 'partial', 'skipped', 'expired', 'legacy'));

CREATE UNIQUE INDEX IF NOT EXISTS control_evidence_run_run_uuid_uidx
    ON ad_intel.control_evidence_run (run_uuid) WHERE run_uuid IS NOT NULL;
CREATE INDEX IF NOT EXISTS control_evidence_run_push_idx
    ON ad_intel.control_evidence_run (client_id, push_status, evidence_run_id);
-- The push reconstructs a run's finding set from history by run id.
CREATE INDEX IF NOT EXISTS idx_cef_client_run_from
    ON ad_intel.control_evidence_fact (client_id, evidence_run_id_valid_from);
CREATE INDEX IF NOT EXISTS idx_cef_client_run_to
    ON ad_intel.control_evidence_fact (client_id, evidence_run_id_valid_to);

COMMENT ON COLUMN ad_intel.control_evidence_run.status IS
    '''running'' from the moment adaudit.py starts evaluating; ''complete'' once every selected '
    'plugin has run and its results, the roster, and retired / stale-plugin closures are '
    'recorded (a run in which some plugins errored is still complete -- the roster says which); '
    '''aborted'' when the run was interrupted or failed before that. A run left ''running'' by a '
    'crash is never pushed. (schema v43)';
COMMENT ON COLUMN ad_intel.control_evidence_run.is_filtered IS
    'TRUE for a diagnostic run limited by --plugin-id / --category / --framework. Since '
    'adaudit.py 0.10.0 such runs do not write to control_evidence_fact and are never pushed. (schema v43)';
COMMENT ON COLUMN ad_intel.control_evidence_run.run_uuid IS
    'The run''s identity in the FortifyData API: UUIDv5 of client_id and evidence_run_id, set when '
    'the run is created and never regenerated, so every retry (or a re-push after a database '
    'restore) re-sends the same run. NULL for legacy runs. (schema v43)';
COMMENT ON COLUMN ad_intel.control_evidence_run.push_status IS
    '''pending'' (not yet accepted by the API), ''pushed'' (the API accepted the run as COMPLETE), '
    '''partial'' (the API closed it PARTIAL: declared and received counts disagreed; re-sent under '
    'the same run_uuid on the next push), ''skipped'' (never pushed: filtered or aborted run, or '
    'skipped by hand with --push-skip), ''expired'' (older than the API''s retention window when '
    'its turn came), ''legacy'' (recorded before schema v43, no roster). (schema v43)';
COMMENT ON COLUMN ad_intel.control_evidence_run.push_server_run_id IS
    'The API''s own run id for this run (RunResponse.run_id), for cross-referencing. (schema v43)';

CREATE TABLE IF NOT EXISTS ad_intel.control_evidence_run_plugin (
    evidence_run_id  bigint NOT NULL REFERENCES ad_intel.control_evidence_run (evidence_run_id)
                     ON DELETE CASCADE,
    plugin_id        integer NOT NULL,
    plugin_version   text,
    rollup           text NOT NULL,
    finding_count    integer NOT NULL DEFAULT 0,
    error_message    text,
    PRIMARY KEY (evidence_run_id, plugin_id),
    CONSTRAINT control_evidence_run_plugin_rollup_check
        CHECK (rollup IN ('pass', 'warn', 'fail', 'error', 'not_assessed'))
);
COMMENT ON TABLE ad_intel.control_evidence_run_plugin IS
    'The plugin roster of each evaluation run: one row per finding plugin that ran (or failed to '
    'load), with its result. ''error'': the query or evidence write failed, or the file failed to '
    'load -- its earlier findings stay open, unconfirmed. ''not_assessed'': the plugin''s source '
    'data was not collected for the client (no Entra / SYSVOL data, or a required Entra source not '
    'readable) -- its earlier findings stay open. finding_count = rows the plugin returned. '
    'Inventory plugins are not in the roster. (schema v43)';

CREATE TABLE IF NOT EXISTS ad_intel.push_catalogue_state (
    api_base_url  text PRIMARY KEY,
    fingerprint   text NOT NULL,
    plugin_count  integer NOT NULL,
    pushed_at     timestamptz NOT NULL
);
COMMENT ON TABLE ad_intel.push_catalogue_state IS
    'The plugin catalogue last accepted by each API server: fingerprint = sha256 of the sorted '
    'plugin_id:version list. adaudit.py re-sends the catalogue only when it differs. (schema v43)';

INSERT INTO ad_intel.schema_migration_history (version_number, description)
VALUES (43, 'adaudit push: evaluation run lifecycle and push state, per-run plugin roster, '
            'catalogue sync state')
ON CONFLICT (version_number) DO NOTHING;

COMMIT;

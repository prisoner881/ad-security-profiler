-- ============================================================================
-- schema_migration_v35.sql
--
-- Adds 'retired' to control_evidence_fact.change_status.
--
-- When a plugin is retired because another plugin now covers the same
-- issue (adaudit.py: a plugins/ file whose PLUGIN dict has "retired": True
-- and "superseded_by": <plugin_id>), its open findings have to be closed.
-- The only closing status so far was 'remediated', which would claim the
-- underlying issue had been fixed when it hadn't -- the superseding plugin
-- reports the same issue under its own identity from now on. 'retired'
-- records the closure honestly.
-- ============================================================================

BEGIN;

ALTER TABLE ad_intel.control_evidence_fact
    DROP CONSTRAINT IF EXISTS control_evidence_fact_change_status_check;

ALTER TABLE ad_intel.control_evidence_fact
    ADD CONSTRAINT control_evidence_fact_change_status_check
    CHECK (change_status = ANY (ARRAY['new'::text, 'changed'::text,
                                      'remediated'::text, 'retired'::text]));

COMMENT ON COLUMN ad_intel.control_evidence_fact.change_status IS
    '''new'' -- first version ever seen for this (test, finding) pair. '
    '''changed'' -- same identity, but severity/status/content differs from '
    'the version it replaced. ''remediated'' -- set on a version when it gets '
    'closed with no successor this run (the finding is no longer present, for '
    'any reason -- object deleted, setting fixed, etc). ''retired'' -- closed '
    'because the plugin that produced it was retired in favour of another '
    'plugin that now reports the same issue (schema v35). A row with '
    'change_status left NULL/unchanged from a prior run and valid_to IS NULL '
    'simply means nothing happened to it this run.';

INSERT INTO ad_intel.schema_migration_history (version_number, description)
VALUES (35, 'Allow change_status ''retired'' on control_evidence_fact '
            '(findings of plugins retired in favour of another plugin)')
ON CONFLICT (version_number) DO NOTHING;

COMMIT;

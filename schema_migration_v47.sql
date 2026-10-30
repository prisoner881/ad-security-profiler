-- ============================================================================
-- schema_migration_v47.sql
--
-- Domain controller identity per collection run (adprofiler.py 1.0.3):
--
--   * sync_run.dc_invocation_id: invocationId of the domain controller the
--     run read (from its NTDS Settings object). Update sequence numbers --
--     the watermark adprofiler uses to find deleted objects -- are local to
--     one DC and restart under a new invocationId after a restore, so a
--     watermark is only valid against the same invocationId. A run whose DC
--     differs from the previous run's checks every deleted object instead.
--   * sync_run.dc_dns_hostname: that DC's DNS name (RootDSE dnsHostName),
--     which can differ from dc_queried (what --dc-host named, e.g. the
--     domain name).
--
-- Existing rows keep NULL (unknown): the first adprofiler 1.0.3 run checks
-- every deleted object once. No rescan needed.
-- ============================================================================

BEGIN;

ALTER TABLE ad_intel.sync_run
    ADD COLUMN IF NOT EXISTS dc_invocation_id uuid,
    ADD COLUMN IF NOT EXISTS dc_dns_hostname text;

COMMENT ON COLUMN ad_intel.sync_run.dc_invocation_id IS
    'invocationId of the domain controller this run read (its NTDS Settings object). The '
    'deleted-object USN watermark of a previous run is used only when this matches; otherwise '
    'every deleted object is checked. NULL = not read or collected before adprofiler 1.0.3. '
    '(schema v47)';
COMMENT ON COLUMN ad_intel.sync_run.dc_dns_hostname IS
    'DNS name of the domain controller this run read (RootDSE dnsHostName); dc_queried is what '
    '--dc-host named. NULL = not read or collected before adprofiler 1.0.3. (schema v47)';

INSERT INTO ad_intel.schema_migration_history (version_number, description)
VALUES (47, 'Domain controller identity per collection run (sync_run.dc_invocation_id, '
            'dc_dns_hostname; adprofiler 1.0.3)')
ON CONFLICT (version_number) DO NOTHING;

COMMIT;

-- ============================================================================
-- schema_migration_v40.sql
--
-- ad_domain.tombstone_lifetime_source (adprofiler.py 0.7.1, plugin 4011).
-- Until now an unreadable Directory Service object and one with neither
-- lifetime attribute set both produced "assumed 60 days"
-- (tombstone_lifetime_is_default = TRUE), so plugin 4011 couldn't tell a
-- real 60-day lifetime from a value nobody read. The source is now
-- recorded, and an unreadable value is stored as NULL instead of 60.
-- ============================================================================

BEGIN;

ALTER TABLE ad_intel.ad_domain
    ADD COLUMN IF NOT EXISTS tombstone_lifetime_source text;
ALTER TABLE ad_intel.ad_domain
    DROP CONSTRAINT IF EXISTS ad_domain_tombstone_lifetime_source_check;
ALTER TABLE ad_intel.ad_domain
    ADD CONSTRAINT ad_domain_tombstone_lifetime_source_check CHECK (
        tombstone_lifetime_source IS NULL OR tombstone_lifetime_source IN
        ('msDS-DeletedObjectLifetime', 'tombstoneLifetime', 'not_set', 'unreadable'));
COMMENT ON COLUMN ad_intel.ad_domain.tombstone_lifetime_source IS
    'Where tombstone_lifetime_days came from: ''msDS-DeletedObjectLifetime'' or '
    '''tombstoneLifetime'' (read from CN=Directory Service); ''not_set'' (the object was read but '
    'neither attribute is set -- MS-ADTS then specifies 60 days, typical of forests created before '
    'Windows Server 2003 SP1); ''unreadable'' (the object could not be read; '
    'tombstone_lifetime_days is NULL). NULL = collected before schema v40. (schema v40)';
COMMENT ON COLUMN ad_intel.ad_domain.tombstone_lifetime_is_default IS
    'TRUE if tombstone_lifetime_days is not an explicitly configured value: neither '
    'msDS-DeletedObjectLifetime nor tombstoneLifetime was set (60-day MS-ADTS default) or, before '
    'schema v40, the value could not be read either. See tombstone_lifetime_source.';

INSERT INTO ad_intel.schema_migration_history (version_number, description)
VALUES (40, 'ad_domain.tombstone_lifetime_source: tell an unreadable lifetime from an unset one')
ON CONFLICT (version_number) DO NOTHING;

COMMIT;

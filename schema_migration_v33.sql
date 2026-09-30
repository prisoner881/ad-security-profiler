-- ============================================================================
-- schema_migration_v33.sql
--
-- Adds ad_domain.dsheuristics_uniqueness, the parsed value of character 21 of
-- the forest-wide dSHeuristics attribute on
--   CN=Directory Service,CN=Windows NT,CN=Services,<Configuration NC>
--
-- That character is a three-bit mask controlling the UPN, SPN and SPN-alias
-- uniqueness verifications introduced by CVE-2021-42282 (KB5008382):
--
--   bit 0 (value 1) -- UPN uniqueness verification disabled
--   bit 1 (value 2) -- SPN uniqueness verification disabled
--   bit 2 (value 4) -- SPN alias uniqueness verification disabled
--
-- so 0 means all three are enforced (the default) and 7 means all three are
-- off. These checks are the guardrail that KerberLoss (CVE-2026-25177) and
-- ResetNightmare (CVE-2026-27912) had to work around using invisible Unicode;
-- where they are switched off, the same duplicate SPNs and UPNs can simply be
-- created directly, on a fully patched domain.
--
-- adprofiler.py already reads dSHeuristics to evaluate character 7 (anonymous
-- LDAP access, plugin 4015). This migration exists because it parsed that one
-- character and discarded the rest of the string.
--
-- Supports plugin 4030.
--
-- NULL means the value could not be determined -- typically the Directory
-- Service object was unreadable with the collecting account's rights. It does
-- NOT mean "enforced"; 0 means enforced. Plugin 4030 treats NULL as unknown
-- and does not report on it, so a failed read produces a false negative rather
-- than a false positive.
-- ============================================================================

BEGIN;

ALTER TABLE ad_intel.ad_domain
    ADD COLUMN IF NOT EXISTS dsheuristics_uniqueness smallint;

COMMENT ON COLUMN ad_intel.ad_domain.dsheuristics_uniqueness IS
    'Character 21 of the forest-wide dSHeuristics attribute, parsed as an '
    'integer bitmask: bit 0 disables UPN uniqueness verification, bit 1 '
    'disables SPN uniqueness verification, bit 2 disables SPN alias '
    'uniqueness verification (CVE-2021-42282 / KB5008382). 0 = all enforced '
    '(default). NULL = not determined, which is not the same as enforced.';

ALTER TABLE ad_intel.ad_domain
    ADD CONSTRAINT ad_domain_dsheuristics_uniqueness_check
    CHECK (dsheuristics_uniqueness IS NULL
           OR (dsheuristics_uniqueness >= 0 AND dsheuristics_uniqueness <= 7));

INSERT INTO ad_intel.schema_migration_history (version_number, description)
VALUES (33, 'Add ad_domain.dsheuristics_uniqueness (dSHeuristics char 21, '
            'UPN/SPN/SPN-alias uniqueness verification state) for plugin 4030')
ON CONFLICT (version_number) DO NOTHING;

COMMIT;

-- ----------------------------------------------------------------------------
-- After applying this migration, run adprofiler.py with --full-rescan once.
-- The new column is only populated when the domain object is written, and the
-- change-detection path only rewrites typed columns when a raw AD attribute
-- actually differs -- so without a rescan the column stays NULL on an already
-- baselined domain and plugin 4030 will report nothing.
-- ----------------------------------------------------------------------------

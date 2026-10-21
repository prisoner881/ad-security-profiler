-- ============================================================================
-- schema_migration_v45.sql
--
-- adprofiler.py 0.9.0: data for three more PingCastle-equivalent checks.
--
--   * ad_computer.creator_sid: mS-DS-CreatorSID, the account that joined
--     the computer through MachineAccountQuota (plugins 2044, 11001).
--     directory_object.owner_sid is now filled for every computer, not
--     only DCs and protected objects (plugin 2044: A-LAPS-Joined-Computers).
--   * ad_computer.sysvol_subscription_found / sysvol_read_only /
--     sysvol_replication_enabled: each DC's DFS Replication SYSVOL
--     subscription (plugins 2045: P-RODCSYSVOLWrite, and 2046).
--   * ad_user.java_attributes: which RFC 2713 Java attributes an account
--     carries (plugin 4021: S-JavaSchema).
--
-- No rescan is needed: the new values reach exactly the objects that have
-- them, which get one new version on the first 0.9.0 run.
-- ============================================================================

BEGIN;

ALTER TABLE ad_intel.ad_computer
    ADD COLUMN IF NOT EXISTS creator_sid ad_intel.sid_text,
    ADD COLUMN IF NOT EXISTS sysvol_subscription_found boolean,
    ADD COLUMN IF NOT EXISTS sysvol_read_only boolean,
    ADD COLUMN IF NOT EXISTS sysvol_replication_enabled boolean;
COMMENT ON COLUMN ad_intel.ad_computer.creator_sid IS
    'mS-DS-CreatorSID: the account that created the computer through MachineAccountQuota. '
    'Set by AD only for computers an account without the Create Computer Objects right joined '
    'to the domain; NULL otherwise (or collected before adprofiler 0.9.0). (schema v45)';
COMMENT ON COLUMN ad_intel.ad_computer.sysvol_subscription_found IS
    'Domain controllers only: whether the DC has a DFS Replication SYSVOL subscription '
    '(CN=SYSVOL Subscription,CN=Domain System Volume,CN=DFSR-LocalSettings,<DC>). FALSE is '
    'expected while SYSVOL replicates with FRS. NULL = not a DC, or not collected (adprofiler '
    'before 0.9.0, or the subscriptions could not be read). (schema v45)';
COMMENT ON COLUMN ad_intel.ad_computer.sysvol_read_only IS
    'msDFSR-ReadOnly of the DC''s SYSVOL subscription: TRUE on a correctly configured read-only '
    'DC. NULL = attribute absent (which means writable) or not collected. (schema v45)';
COMMENT ON COLUMN ad_intel.ad_computer.sysvol_replication_enabled IS
    'msDFSR-Enabled of the DC''s SYSVOL subscription: FALSE = SYSVOL replication is turned off '
    'on this DC. NULL = attribute absent or not collected. (schema v45)';

ALTER TABLE ad_intel.ad_user
    ADD COLUMN IF NOT EXISTS java_attributes text[];
COMMENT ON COLUMN ad_intel.ad_user.java_attributes IS
    'Names of the RFC 2713 Java attributes set on the account (javaClassName, javaCodeBase, '
    'javaFactory, javaSerializedData, javaRemoteLocation); values are never stored. NULL = none, '
    'the forest schema has no Java extension, or collected before adprofiler 0.9.0. (schema v45)';

COMMENT ON COLUMN ad_intel.directory_object.owner_sid IS
    'Owner SID from the object''s security descriptor, when this project has collected one for '
    'it: the domain root, AdminSDHolder, OUs, PKI objects, AdminSDHolder-protected objects, and '
    'from schema v45 (adprofiler 0.9.0) every computer. NULL means "not collected", not "no '
    'owner". (schema v45)';

INSERT INTO ad_intel.schema_migration_history (version_number, description)
VALUES (45, 'ad_computer creator SID and SYSVOL subscription columns; ad_user.java_attributes; '
            'owners of every computer')
ON CONFLICT (version_number) DO NOTHING;

COMMIT;

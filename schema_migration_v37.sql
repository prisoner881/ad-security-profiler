-- ============================================================================
-- schema_migration_v37.sql
--
-- Storage for data adprofiler.py 0.5.16 and entra_graph_collector.py 0.6.0
-- now collect. Run adprofiler.py once with --full-rescan after applying it so
-- existing objects get the new columns (and correctly decoded sIDHistory).
--
--   ad_user.key_credentials / ad_computer.key_credentials
--       Parsed msDS-KeyCredentialLink entries (key id, device id, usage,
--       source, creation time, flags) -- tells a device's own key from one
--       added by an attacker (shadow credentials; plugins 2013/2029/1022).
--   ad_domain.dsheuristics_admin_sd_ex_mask
--       dSHeuristics character 16 (dwAdminSDExMask): operator groups
--       excluded from SDProp (1 Account, 2 Server, 4 Print, 8 Backup
--       Operators). NULL = unknown, 0 = none excluded (plugins 3005/3021).
--   ad_domain.spn_mappings
--       The forest's sPNMappings as {alias: target class}; NULL = attribute
--       absent/unreadable, defaults apply (plugins 2034/4029).
--   rbcd_unresolved_trustee_edge
--       RBCD trustees whose SID is not a collected object (well-known SIDs
--       such as Authenticated Users, foreign or orphaned SIDs), previously
--       dropped (plugins 2022/2027/11005).
--   entra_directory_role_member.assignment_type / via_group_id /
--   via_group_display_name / directory_scope_id
--       PIM-eligible assignments and members of role-holding groups
--       (plugins 10002/10003/10006). The primary key becomes a unique index
--       that includes these.
--   entra_security_posture.role_eligibility_status / group_expansion_status
--       'ok', or why Graph couldn't be read (e.g. no Entra ID P2 licence).
-- ============================================================================

BEGIN;

ALTER TABLE ad_intel.ad_user     ADD COLUMN IF NOT EXISTS key_credentials jsonb;
ALTER TABLE ad_intel.ad_computer ADD COLUMN IF NOT EXISTS key_credentials jsonb;
COMMENT ON COLUMN ad_intel.ad_user.key_credentials IS
    'Parsed msDS-KeyCredentialLink entries: [{key_id, device_id, usage (NGC, FIDO, ...), '
    'source (AD/AzureAD), creation_time, approximate_last_logon, custom_flags, parse_error}]. '
    'Key material is not stored. (schema v37)';
COMMENT ON COLUMN ad_intel.ad_computer.key_credentials IS
    'Parsed msDS-KeyCredentialLink entries; see ad_user.key_credentials. (schema v37)';

ALTER TABLE ad_intel.ad_domain
    ADD COLUMN IF NOT EXISTS dsheuristics_admin_sd_ex_mask smallint,
    ADD COLUMN IF NOT EXISTS spn_mappings jsonb;

CREATE TABLE IF NOT EXISTS ad_intel.rbcd_unresolved_trustee_edge (
    edge_id             BIGINT GENERATED ALWAYS AS IDENTITY,
    client_id           UUID NOT NULL,
    trustee_sid         TEXT NOT NULL,
    target_guid         UUID NOT NULL,
    valid_from          TIMESTAMPTZ NOT NULL,
    valid_to            TIMESTAMPTZ,
    run_id_valid_from   BIGINT NOT NULL,
    run_id_valid_to     BIGINT,
    PRIMARY KEY (edge_id, valid_from),
    CHECK (valid_to IS NULL OR valid_to > valid_from),
    FOREIGN KEY (target_guid, client_id) REFERENCES ad_intel.directory_object(object_guid, client_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id_valid_from, client_id) REFERENCES ad_intel.sync_run(run_id, client_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id_valid_to, client_id) REFERENCES ad_intel.sync_run(run_id, client_id) ON DELETE RESTRICT
);
COMMENT ON TABLE ad_intel.rbcd_unresolved_trustee_edge IS
    'An RBCD trustee (msDS-AllowedToActOnBehalfOfOtherIdentity allow ACE) on '
    'target_guid whose SID is not a collected object -- a well-known SID such '
    'as Everyone/Authenticated Users, a principal from another domain, or an '
    'orphaned SID. Resolved trustees are in delegation_edge. (schema v37)';
CREATE INDEX IF NOT EXISTS idx_rbcd_unresolved_trustee_edge_open
    ON ad_intel.rbcd_unresolved_trustee_edge (client_id, target_guid) WHERE valid_to IS NULL;

ALTER TABLE ad_intel.entra_directory_role_member
    ADD COLUMN IF NOT EXISTS assignment_type text DEFAULT 'active' NOT NULL,
    ADD COLUMN IF NOT EXISTS via_group_id uuid,
    ADD COLUMN IF NOT EXISTS via_group_display_name text,
    ADD COLUMN IF NOT EXISTS directory_scope_id text DEFAULT '/' NOT NULL;
ALTER TABLE ad_intel.entra_directory_role_member
    DROP CONSTRAINT IF EXISTS entra_directory_role_member_pkey;
CREATE UNIQUE INDEX IF NOT EXISTS entra_directory_role_member_key
    ON ad_intel.entra_directory_role_member
       (client_id, role_id, member_id, assignment_type,
        COALESCE(via_group_id, '00000000-0000-0000-0000-000000000000'::uuid), directory_scope_id);
COMMENT ON COLUMN ad_intel.entra_directory_role_member.assignment_type IS
    '''active'' (current member, from /directoryRoles) or ''eligible'' (PIM-eligible: can '
    'activate the role on demand). (schema v37)';
COMMENT ON COLUMN ad_intel.entra_directory_role_member.via_group_id IS
    'Set when the member holds the role through membership of this group '
    '(role-assignable group); NULL for a direct assignment. (schema v37)';

ALTER TABLE ad_intel.entra_security_posture
    ADD COLUMN IF NOT EXISTS role_eligibility_status text,
    ADD COLUMN IF NOT EXISTS group_expansion_status text;

INSERT INTO ad_intel.schema_migration_history (version_number, description)
VALUES (37, 'KeyCredential parsing, dwAdminSDExMask, sPNMappings, unresolved RBCD '
            'trustees, PIM-eligible and group-held Entra role membership')
ON CONFLICT (version_number) DO NOTHING;

COMMIT;

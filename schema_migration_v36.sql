-- ============================================================================
-- schema_migration_v36.sql
--
-- Columns for data adprofiler.py 0.5.15 now collects, and a refinement of
-- v_privileged_principal. All additions are nullable or defaulted, so
-- existing rows stay valid; run adprofiler.py with --full-rescan once after
-- applying this so existing objects get the new columns filled in.
--
--   ad_computer.is_read_only_dc        RODCs (PARTIAL_SECRETS_ACCOUNT). They
--                                       now also count as is_domain_controller.
--   ad_computer.user_principal_name    computers and gMSAs can carry a UPN.
--   ad_cert_template.ra_signature_count msPKI-RA-Signature (authorized
--                                       signatures required -- ESC1/2/15).
--   ad_cert_template.template_oid      msPKI-Cert-Template-OID.
--   ad_cert_oid.policy_oid             msPKI-Cert-Template-OID of an issuance
--                                       policy object -- the dotted OID that
--                                       templates' msPKI-Certificate-Policy
--                                       references (ESC13).
--   ad_cert_oid.display_name           the policy's displayName.
--   group_member_edge.is_primary_group membership through primaryGroupID,
--                                       which AD never lists in member.
--
-- v_privileged_principal: an inherit-only ACE on the domain root (or an OU
-- above a DC) that is inherited by computer objects now counts as Tier 0
-- control whenever a DC in the collection is not AdminSDHolder-protected
-- (adminCount <> 1), because it then lands on that DC's computer object.
-- ============================================================================

BEGIN;

ALTER TABLE ad_intel.ad_computer
    ADD COLUMN IF NOT EXISTS is_read_only_dc boolean DEFAULT false NOT NULL,
    ADD COLUMN IF NOT EXISTS user_principal_name text;

ALTER TABLE ad_intel.ad_cert_template
    ADD COLUMN IF NOT EXISTS ra_signature_count integer,
    ADD COLUMN IF NOT EXISTS template_oid text;

ALTER TABLE ad_intel.ad_cert_oid
    ADD COLUMN IF NOT EXISTS policy_oid text,
    ADD COLUMN IF NOT EXISTS display_name text;

ALTER TABLE ad_intel.group_member_edge
    ADD COLUMN IF NOT EXISTS is_primary_group boolean DEFAULT false NOT NULL;

COMMENT ON COLUMN ad_intel.group_member_edge.is_primary_group IS
    'TRUE when the membership comes from the member''s primaryGroupID (e.g. '
    'Domain Users for users), which AD never lists in the group''s member '
    'attribute. Such edges are also is_direct. (schema v36)';

CREATE OR REPLACE VIEW ad_intel.v_privileged_principal AS
    WITH control_ace AS (
        SELECT a.client_id, a.trustee_sid, a.object_guid AS via_object_guid
          FROM ad_intel.acl_edge a
          JOIN ad_intel.v_tier0_object t
            ON t.object_guid = a.object_guid AND t.client_id = a.client_id
         WHERE a.valid_to IS NULL
           AND a.ace_type = 'allow'
           AND (
                 a.inherit_only IS NOT TRUE
                 -- [v36] An inherit-only ACE on the domain root or an OU
                 -- above a DC, inherited by computer objects (or by every
                 -- class), lands on the DC computer objects below it --
                 -- unless they don't inherit. SDProp turns inheritance off
                 -- on AdminSDHolder-protected objects (adminCount = 1), so
                 -- this counts as Tier 0 control exactly when some DC in
                 -- this collection is NOT protected. Decided from each
                 -- environment's own data rather than assumed either way.
                 OR (t.tier0_reason IN ('domain_root', 'domain_controller_ou')
                     AND (a.inherited_object_type_guid IS NULL
                          OR a.inherited_object_type_guid = 'bf967a86-0de6-11d0-a285-00aa003049e2')
                     AND EXISTS (SELECT 1 FROM ad_intel.ad_computer dc
                                  WHERE dc.client_id = a.client_id AND dc.valid_to IS NULL
                                    AND dc.is_domain_controller
                                    AND dc.admin_count IS DISTINCT FROM 1))
               )
           AND (
                 -- AD stores generic rights already mapped to specific ones,
                 -- so GenericAll appears as 0xF01FF and GenericWrite as
                 -- 0x20028 (READ_CONTROL | WRITE_PROP | SELF). The unmapped
                 -- GENERIC_* bits are kept too in case a source writes them.
                 (a.access_mask & 268435456) <> 0       -- GENERIC_ALL
              OR (a.access_mask & 1073741824) <> 0      -- GENERIC_WRITE
              OR (a.access_mask & 983551) = 983551      -- GenericAll, as stored
              OR (a.access_mask & 262144) <> 0          -- WRITE_DAC
              OR (a.access_mask & 524288) <> 0          -- WRITE_OWNER
              OR ((a.access_mask & 32) <> 0             -- WRITE_PROP on every
                  AND a.object_type_guid IS NULL)       --   attribute (GenericWrite)
              OR ((a.access_mask & 32) <> 0             -- write gPLink: link a GPO
                  AND a.object_type_guid = 'f30e3bbe-9ff0-11d1-b603-0000f80367c1'
                  AND t.tier0_reason IN ('domain_root', 'domain_controller_ou'))
           )
    ),
    dcsync AS (
        SELECT a.client_id, a.trustee_sid, a.object_guid AS via_object_guid
          FROM ad_intel.acl_edge a
          JOIN ad_intel.ad_domain d
            ON d.object_guid = a.object_guid AND d.client_id = a.client_id
           AND d.valid_to IS NULL
         WHERE a.valid_to IS NULL
           AND a.ace_type = 'allow'
           AND a.inherit_only IS NOT TRUE
           AND (a.access_mask & 256) <> 0               -- CONTROL_ACCESS
         GROUP BY a.client_id, a.trustee_sid, a.object_guid
        HAVING bool_or(a.object_type_guid IS NULL)      -- All Extended Rights
            OR (bool_or(a.object_type_guid = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2')   -- Get-Changes
                AND bool_or(a.object_type_guid = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2')) -- Get-Changes-All
    ),
    holder_sid AS (
        SELECT client_id, trustee_sid AS sid, 'tier0_acl_control'::text AS source, via_object_guid
          FROM control_ace
        UNION
        SELECT client_id, trustee_sid, 'dcsync', via_object_guid
          FROM dcsync
        UNION
        SELECT o.client_id, o.owner_sid, 'tier0_ownership', o.object_guid
          FROM ad_intel.directory_object o
          JOIN ad_intel.v_tier0_object t
            ON t.object_guid = o.object_guid AND t.client_id = o.client_id
         WHERE o.owner_sid IS NOT NULL AND NOT o.is_deleted
    ),
    holder AS (
        SELECT h.client_id, p.object_guid, h.source, h.via_object_guid
          FROM holder_sid h
          JOIN ad_intel.directory_object p
            ON p.object_sid = h.sid AND p.client_id = h.client_id AND NOT p.is_deleted
    )
    SELECT vem.client_id, vem.member_guid AS object_guid,
           'protected_group_member'::text AS privilege_source,
           vem.group_guid AS via_object_guid
      FROM ad_intel.v_effective_group_membership vem
      JOIN ad_intel.ad_group g
        ON g.object_guid = vem.group_guid AND g.client_id = vem.client_id
       AND g.valid_to IS NULL AND g.is_protected_group
    UNION
    SELECT client_id, object_guid, source, via_object_guid
      FROM holder
    UNION
    SELECT h.client_id, vem.member_guid, h.source || '_via_group', h.via_object_guid
      FROM holder h
      JOIN ad_intel.v_effective_group_membership vem
        ON vem.group_guid = h.object_guid AND vem.client_id = h.client_id;


INSERT INTO ad_intel.schema_migration_history (version_number, description)
VALUES (36, 'RODC flag, computer UPN, template RA signatures/OID, issuance '
            'policy OID, primary-group membership edges; v_privileged_principal '
            'counts root inherit-only ACEs reaching unprotected DCs')
ON CONFLICT (version_number) DO NOTHING;

COMMIT;

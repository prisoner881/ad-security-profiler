-- ============================================================================
-- schema_migration_v48.sql
--
-- Fixes from the code review (adprofiler.py / adaudit.py 1.0.4):
--
--   * v_gpo_dc_application: whether an OU is above a domain controller is
--     a DN suffix comparison, no longer LIKE. '_' and '%' in an OU name were
--     wildcards and a backslash (DN escapes such as '\,') was LIKE's escape
--     character, so GPOs were applied to the wrong DCs, or the DC's own OU
--     stopped matching (v_dc_effective_gpo_setting follows).
--   * v_privileged_principal: also Tier 0 -- write member / add self on a
--     protected group or AdminSDHolder; User-Force-Change-Password on
--     AdminSDHolder; an inherit-only ACE on the domain root that OUs inherit
--     (it lands on the OU holding the DCs).
--   * v_entra_tenant_capability: a licence in its grace period
--     (capabilityStatus 'Warning') still counts.
--   * ad_gpo_sysvol.first_read_run_id: the run that first read each GPO
--     folder (plugin 11021 v1.2). Existing rows: the run that last read them.
--
-- No rescan needed.
-- ============================================================================

BEGIN;

CREATE OR REPLACE VIEW ad_intel.v_gpo_dc_application AS
WITH dc AS (
    SELECT c.client_id, c.object_guid AS dc_guid, lower(d.dn_current) AS dc_dn, d.object_sid AS dc_sid
    FROM ad_intel.ad_computer c
    JOIN ad_intel.directory_object d
      ON d.object_guid = c.object_guid AND d.client_id = c.client_id AND NOT d.is_deleted
    WHERE c.valid_to IS NULL AND c.is_domain_controller
      -- [v46] not the Microsoft Entra Kerberos server object (no host, no Group Policy)
      AND NOT ad_intel.is_entra_kerberos_server(c.sam_account_name, c.krbtgt_link)
),
som AS (
    SELECT o.client_id, o.object_guid, lower(d.dn_current) AS dn,
           COALESCE(o.block_inheritance, false) AS block_inheritance, false AS is_domain
    FROM ad_intel.ad_ou o
    JOIN ad_intel.directory_object d
      ON d.object_guid = o.object_guid AND d.client_id = o.client_id AND NOT d.is_deleted
    WHERE o.valid_to IS NULL
    UNION ALL
    SELECT m.client_id, m.object_guid, lower(d.dn_current),
           COALESCE(m.block_inheritance, false), true
    FROM ad_intel.ad_domain m
    JOIN ad_intel.directory_object d
      ON d.object_guid = m.object_guid AND d.client_id = m.client_id AND NOT d.is_deleted
    WHERE m.valid_to IS NULL
),
chain AS (
    -- Domain root and every OU above the DC. depth = number of commas in the
    -- container's DN (the domain root is the shallowest).
    SELECT dc.client_id, dc.dc_guid, dc.dc_sid, s.object_guid AS container_guid, s.is_domain,
           s.block_inheritance,
           length(s.dn) - length(replace(s.dn, ',', '')) AS depth
    FROM dc
    -- [v48] DN suffix compared as text, not with LIKE: '_' and '%' in an OU
    -- name were wildcards and a backslash (DN escapes such as '\,') was
    -- LIKE's escape character, so GPOs were applied to the wrong DCs or the
    -- DC's own OU stopped matching.
    JOIN som s ON s.client_id = dc.client_id AND right(dc.dc_dn, length(s.dn) + 1) = ',' || s.dn
),
blocked AS (
    -- Block inheritance on an OU stops non-enforced links from containers above it.
    SELECT client_id, dc_guid, max(depth) AS block_depth
    FROM chain WHERE block_inheritance AND NOT is_domain
    GROUP BY client_id, dc_guid
),
links AS (
    SELECT l.client_id, l.container_guid, l.gpo_guid, l.link_enforced, l.link_enabled,
           max(l.link_order) OVER (PARTITION BY l.client_id, l.container_guid) - l.link_order + 1
               AS gpmc_link_order
    FROM ad_intel.gpo_link_edge l
    WHERE l.valid_to IS NULL
),
dc_sids AS (
    SELECT dc.client_id, dc.dc_guid, dc.dc_sid::text AS sid FROM dc WHERE dc.dc_sid IS NOT NULL
    UNION
    SELECT dc.client_id, dc.dc_guid, w.sid
    FROM dc CROSS JOIN (VALUES ('S-1-1-0'), ('S-1-5-11'), ('S-1-5-9')) AS w(sid)
    UNION
    SELECT dc.client_id, dc.dc_guid, gd.object_sid::text
    FROM dc
    JOIN ad_intel.v_effective_group_membership m
      ON m.client_id = dc.client_id AND m.member_guid = dc.dc_guid
    JOIN ad_intel.directory_object gd
      ON gd.object_guid = m.group_guid AND gd.client_id = m.client_id
    WHERE gd.object_sid IS NOT NULL
),
candidate AS (
    SELECT ch.client_id, ch.dc_guid, lk.gpo_guid, ch.container_guid, ch.is_domain, ch.depth,
           lk.link_enforced, lk.gpmc_link_order,
           (g.gpo_flags IS NULL OR (g.gpo_flags & 2) = 0) AS computer_settings_enabled,
           (
             NOT EXISTS (
               SELECT 1 FROM ad_intel.acl_edge a
               JOIN dc_sids s ON s.client_id = a.client_id AND s.dc_guid = ch.dc_guid AND s.sid = a.trustee_sid::text
               WHERE a.client_id = ch.client_id AND a.object_guid = lk.gpo_guid AND a.valid_to IS NULL
                 AND a.ace_type = 'deny' AND a.inherit_only IS NOT TRUE
                 AND (a.access_mask & 256) <> 0
                 AND (a.object_type_guid IS NULL OR a.object_type_guid = 'edacfd8f-ffb3-11d1-b41d-00a0c968f939')
             )
             AND (
               NOT EXISTS (SELECT 1 FROM ad_intel.acl_edge a
                           WHERE a.client_id = ch.client_id AND a.object_guid = lk.gpo_guid
                             AND a.valid_to IS NULL)
               OR EXISTS (
                 SELECT 1 FROM ad_intel.acl_edge a
                 JOIN dc_sids s ON s.client_id = a.client_id AND s.dc_guid = ch.dc_guid AND s.sid = a.trustee_sid::text
                 WHERE a.client_id = ch.client_id AND a.object_guid = lk.gpo_guid AND a.valid_to IS NULL
                   AND a.ace_type = 'allow' AND a.inherit_only IS NOT TRUE
                   AND ( ((a.access_mask & 256) <> 0
                          AND (a.object_type_guid IS NULL OR a.object_type_guid = 'edacfd8f-ffb3-11d1-b41d-00a0c968f939'))
                         OR (a.access_mask & 983551) = 983551
                         OR (a.access_mask & 268435456) <> 0 )
               )
             )
           ) AS security_filter_applies
    FROM chain ch
    JOIN links lk ON lk.client_id = ch.client_id AND lk.container_guid = ch.container_guid AND lk.link_enabled
    JOIN ad_intel.ad_gpo g ON g.object_guid = lk.gpo_guid AND g.client_id = lk.client_id AND g.valid_to IS NULL
    LEFT JOIN blocked b ON b.client_id = ch.client_id AND b.dc_guid = ch.dc_guid
    WHERE lk.link_enforced OR b.block_depth IS NULL OR ch.depth >= b.block_depth
)
SELECT c.client_id, c.dc_guid, c.gpo_guid, c.container_guid, c.is_domain AS linked_at_domain,
       c.depth, c.link_enforced, c.gpmc_link_order, c.computer_settings_enabled,
       c.security_filter_applies,
       CASE WHEN c.computer_settings_enabled AND c.security_filter_applies THEN
           row_number() OVER (
               PARTITION BY c.client_id, c.dc_guid
               ORDER BY (c.computer_settings_enabled AND c.security_filter_applies) DESC,
                        c.link_enforced DESC,
                        CASE WHEN c.link_enforced THEN c.depth END ASC,
                        CASE WHEN NOT c.link_enforced THEN c.depth END DESC,
                        c.gpmc_link_order ASC)
       END AS precedence
FROM candidate c;
COMMENT ON VIEW ad_intel.v_gpo_dc_application IS
    'GPOs linked (enabled link) to the domain root or an OU above each domain controller, with '
    'precedence (1 = highest; NULL = does not apply because computer settings are disabled or '
    'security filtering denies the DC the Apply Group Policy right). Order: enforced links first '
    '(higher container wins), then non-enforced links (deeper OU wins); within a container GPMC '
    'link order. Block inheritance removes non-enforced links above the blocking OU. Not '
    'evaluated: site-linked GPOs (a DC''s site is not collected), WMI filters, loopback. A GPO '
    'whose ACL was never collected is assumed to apply. (schema v39)';

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
                 -- [v48] An inherit-only ACE on the domain root inherited by
                 -- OUs (or by every class) lands on the OU that holds the DCs,
                 -- a Tier 0 object; OUs are never AdminSDHolder-protected.
                 OR (t.tier0_reason = 'domain_root'
                     AND (a.inherited_object_type_guid IS NULL
                          OR a.inherited_object_type_guid = 'bf967aa5-0de6-11d0-a285-00aa003049e2')
                     AND EXISTS (SELECT 1 FROM ad_intel.v_tier0_object x
                                  WHERE x.client_id = a.client_id
                                    AND x.tier0_reason = 'domain_controller_ou'))
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
              -- [v48] write member (WRITE_PROP) or add/remove self (validated
              -- write, SELF) on a protected group, or on AdminSDHolder, whose
              -- ACL SDProp copies onto every protected group: adds anyone to
              -- Domain Admins.
              OR ((a.access_mask & (32 | 8)) <> 0
                  AND a.object_type_guid = 'bf9679c0-0de6-11d0-a285-00aa003049e2'
                  AND t.tier0_reason IN ('protected_group', 'adminsdholder'))
              -- [v48] User-Force-Change-Password on AdminSDHolder: copied onto
              -- every protected user (reset a Domain Admin's password).
              OR ((a.access_mask & 256) <> 0
                  AND a.object_type_guid = '00299570-246d-11d0-a768-00aa006e0529'
                  AND t.tier0_reason = 'adminsdholder')
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

COMMENT ON VIEW ad_intel.v_privileged_principal IS
    'Principals that are privileged in the Tier 0 sense, one row per '
    '(principal, reason, via object). privilege_source is one of '
    'protected_group_member, tier0_acl_control, dcsync, tier0_ownership, or '
    'one of the last three suffixed _via_group (inherited through group '
    'membership). via_object_guid is the protected group or Tier 0 object the '
    'privilege comes from. AdminSDHolder-protected groups themselves are not '
    'listed unless they also qualify through one of these paths. Filter on '
    'client_id. See schema_migration_v34.sql.';

CREATE OR REPLACE VIEW ad_intel.v_entra_tenant_capability AS
SELECT s.client_id,
       s.status AS license_status,
       -- [v48] 'Warning' = past its end date, in the grace period: the
       -- features still work, so the licence still counts.
       COALESCE(bool_or(l.capability_status IN ('Enabled', 'Warning')
                        AND l.service_plans && ARRAY['AAD_PREMIUM', 'AAD_PREMIUM_P2']), FALSE) AS has_p1,
       COALESCE(bool_or(l.capability_status IN ('Enabled', 'Warning')
                        AND l.service_plans && ARRAY['AAD_PREMIUM_P2']), FALSE) AS has_p2,
       COALESCE(bool_or(l.capability_status IN ('Enabled', 'Warning')
                        AND l.service_plans && ARRAY['AAD_WRKLDID_P1', 'AAD_WRKLDID_P2']), FALSE)
           AS has_workload_id
FROM ad_intel.entra_collection_status s
LEFT JOIN ad_intel.entra_tenant_license l ON l.client_id = s.client_id
WHERE s.source = 'subscribed_skus'
GROUP BY s.client_id, s.status;
COMMENT ON VIEW ad_intel.v_entra_tenant_capability IS
    'One row per client whose Entra collection tried /subscribedSkus. has_p1 / has_p2 / '
    'has_workload_id are only meaningful when license_status = ''ok''. (schema v42)';

ALTER TABLE ad_intel.ad_gpo_sysvol
    ADD COLUMN IF NOT EXISTS first_read_run_id bigint;
COMMENT ON COLUMN ad_intel.ad_gpo_sysvol.first_read_run_id IS
    'Run that first read this GPO folder successfully (kept across runs; NULL = never read). Plugin '
    '11021 reports setting changes only for GPOs read before the run it evaluates, empty ones '
    'included. (schema v48)';
UPDATE ad_intel.ad_gpo_sysvol
   SET first_read_run_id = run_id
 WHERE first_read_run_id IS NULL AND read_status = 'ok';

INSERT INTO ad_intel.schema_migration_history (version_number, description)
VALUES (48, 'GPO-to-DC DN matching, privileged principal gaps, licence grace period, GPO first '
            'SYSVOL read (code review fixes)')
ON CONFLICT (version_number) DO NOTHING;

COMMIT;

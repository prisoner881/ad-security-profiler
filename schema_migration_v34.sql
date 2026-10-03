-- ============================================================================
-- schema_migration_v34.sql
--
-- 1. acl_edge.inherit_only / acl_edge.inherited_object_type_guid
--
--    An ACE carrying INHERIT_ONLY_ACE (0x08) grants nothing on the object it
--    is stored on -- it exists only to flow down to child objects, usually of
--    one class (InheritedObjectType). The common case is delegation set at
--    the domain root or on an OU: "Full Control over descendant Computer
--    objects" for a deployment account. Before v34 the collector discarded
--    both flags, so that ACE was indistinguishable from Full Control over the
--    domain root itself, and the account was treated as domain-privileged.
--
--    NULL means "collected before v34, not known". Queries treat NULL as
--    applying to the object (inherit_only IS NOT TRUE), so pre-v34 rows keep
--    flagging exactly what they flagged before; adprofiler.py fills both
--    columns on its next run (without opening/closing any edge, so change-
--    detection plugins don't see the backfill as new grants).
--
-- 2. v_tier0_object / v_privileged_principal
--
--    One shared definition of "privileged", replacing the subquery that was
--    copied into 18 plugins. The old definition treated a dangerous right on
--    ANY object whose ACL is collected -- every OU, every certificate
--    template -- or ownership of ANY such object as domain-level privilege,
--    so helpdesk staff with OU delegation, or whoever created an OU, were
--    reported as privileged. The new definition follows the Tier 0 model
--    (Microsoft's Enterprise Access Model / BloodHound "Tier Zero"): a
--    principal is privileged if it can take control of the domain, i.e.
--
--      - it is a member, directly or through nesting, of an
--        AdminSDHolder-protected group (adminCount = 1) -- unchanged; or
--      - it holds, on a Tier 0 OBJECT, a right that confers control of that
--        object: GenericAll, WriteDACL, WriteOwner, write-all-properties
--        (GenericWrite), or write gPLink on the domain root / an OU above a
--        DC; or
--      - it holds DCSync on the domain root (both Get-Changes and
--        Get-Changes-All, or All Extended Rights); or
--      - it OWNS a Tier 0 object (an owner can always rewrite the DACL); or
--      - it is a member, directly or through nesting, of a group that
--        qualifies under any of the above.
--
--    Tier 0 objects: the domain root, AdminSDHolder, domain controller
--    computer objects and every OU above one, AdminSDHolder-protected
--    groups, Enterprise CA objects and their host computers, the
--    NTAuthCertificates store, and the Public Key Services containers.
--    Control of any of these is a direct path to domain compromise.
--
--    Delegation on ordinary OUs and certificate templates is no longer
--    privilege by this definition. It is still recorded in acl_edge, and the
--    plugins that report on those ACLs specifically (OU delegation, ESC4
--    template ACLs, ...) still report it.
-- ============================================================================

BEGIN;

ALTER TABLE ad_intel.acl_edge
    ADD COLUMN IF NOT EXISTS inherit_only boolean,
    ADD COLUMN IF NOT EXISTS inherited_object_type_guid uuid;

COMMENT ON COLUMN ad_intel.acl_edge.inherit_only IS
    'TRUE if every ACE behind this edge carries INHERIT_ONLY_ACE (0x08): it '
    'grants nothing on this object, only on descendants (of class '
    'inherited_object_type_guid, when set). NULL = collected before schema '
    'v34; treat as applying to the object (inherit_only IS NOT TRUE).';

COMMENT ON COLUMN ad_intel.acl_edge.inherited_object_type_guid IS
    'For an object ACE with ACE_INHERITED_OBJECT_TYPE_PRESENT: the schema '
    'class GUID of the descendant objects the ACE is inherited by. NULL = '
    'all descendant classes, not an object ACE, or collected before v34.';

CREATE OR REPLACE VIEW ad_intel.v_tier0_object AS
    SELECT d.client_id, d.object_guid, 'domain_root'::text AS tier0_reason
      FROM ad_intel.ad_domain d
     WHERE d.valid_to IS NULL
    UNION
    SELECT o.client_id, o.object_guid, 'adminsdholder'
      FROM ad_intel.directory_object o
     WHERE NOT o.is_deleted
       AND o.object_class = 'container'
       AND lower(o.dn_current) LIKE 'cn=adminsdholder,cn=system,%'
    UNION
    SELECT c.client_id, c.object_guid, 'domain_controller'
      FROM ad_intel.ad_computer c
     WHERE c.valid_to IS NULL AND c.is_domain_controller
    UNION
    -- Every OU above a DC, not only its direct parent: an inheritable ACE
    -- set on any ancestor OU flows down onto the DC's computer object.
    SELECT ou.client_id, ou.object_guid, 'domain_controller_ou'
      FROM ad_intel.ad_ou o
      JOIN ad_intel.directory_object ou
        ON ou.object_guid = o.object_guid AND ou.client_id = o.client_id
      JOIN ad_intel.ad_computer c
        ON c.client_id = o.client_id AND c.valid_to IS NULL AND c.is_domain_controller
      JOIN ad_intel.directory_object cd
        ON cd.object_guid = c.object_guid AND cd.client_id = c.client_id
     WHERE o.valid_to IS NULL
       AND NOT ou.is_deleted
       AND right(lower(cd.dn_current), length(ou.dn_current) + 1) = ',' || lower(ou.dn_current)
    UNION
    SELECT g.client_id, g.object_guid, 'protected_group'
      FROM ad_intel.ad_group g
     WHERE g.valid_to IS NULL AND g.is_protected_group
    UNION
    SELECT e.client_id, e.object_guid, 'enterprise_ca'
      FROM ad_intel.ad_enrollment_service e
     WHERE e.valid_to IS NULL
    UNION
    SELECT c.client_id, c.object_guid, 'enterprise_ca_host'
      FROM ad_intel.ad_enrollment_service e
      JOIN ad_intel.ad_computer c
        ON c.client_id = e.client_id AND c.valid_to IS NULL
       AND lower(c.dns_hostname) = lower(e.dns_hostname)
     WHERE e.valid_to IS NULL
    UNION
    SELECT n.client_id, n.object_guid, 'ntauth_store'
      FROM ad_intel.ad_ntauth_store n
     WHERE n.valid_to IS NULL
    UNION
    SELECT o.client_id, o.object_guid, 'pki_container'
      FROM ad_intel.directory_object o
     WHERE NOT o.is_deleted
       AND o.object_class = 'container'
       AND lower(o.dn_current) LIKE '%cn=public key services,cn=services,cn=configuration,%';

COMMENT ON VIEW ad_intel.v_tier0_object IS
    'Objects whose control is control of the domain (Tier 0), one row per '
    '(object, reason). Used by v_privileged_principal. See '
    'schema_migration_v34.sql for the rationale behind each member.';

CREATE OR REPLACE VIEW ad_intel.v_privileged_principal AS
    WITH control_ace AS (
        SELECT a.client_id, a.trustee_sid, a.object_guid AS via_object_guid
          FROM ad_intel.acl_edge a
          JOIN ad_intel.v_tier0_object t
            ON t.object_guid = a.object_guid AND t.client_id = a.client_id
         WHERE a.valid_to IS NULL
           AND a.ace_type = 'allow'
           AND a.inherit_only IS NOT TRUE
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

COMMENT ON VIEW ad_intel.v_privileged_principal IS
    'Principals that are privileged in the Tier 0 sense, one row per '
    '(principal, reason, via object). privilege_source is one of '
    'protected_group_member, tier0_acl_control, dcsync, tier0_ownership, or '
    'one of the last three suffixed _via_group (inherited through group '
    'membership). via_object_guid is the protected group or Tier 0 object the '
    'privilege comes from. AdminSDHolder-protected groups themselves are not '
    'listed unless they also qualify through one of these paths. Filter on '
    'client_id. See schema_migration_v34.sql.';

INSERT INTO ad_intel.schema_migration_history (version_number, description)
VALUES (34, 'acl_edge.inherit_only/inherited_object_type_guid; '
            'v_tier0_object and v_privileged_principal (shared Tier 0 '
            'definition of privileged, replacing the per-plugin subquery)')
ON CONFLICT (version_number) DO NOTHING;

COMMIT;

-- ----------------------------------------------------------------------------
-- After applying this migration, run adprofiler.py normally. Its next run
-- fills inherit_only/inherited_object_type_guid on every open acl_edge row in
-- place; until then they are NULL and treated as applying to the object, so
-- results are no broader than before the migration.
-- ----------------------------------------------------------------------------

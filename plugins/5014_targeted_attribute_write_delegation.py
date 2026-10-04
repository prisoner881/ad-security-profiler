"""
Plugin 5014: Targeted Attribute-Write and Password-Reset Delegations

Detects explicit allow ACEs on the domain root and on OUs that grant a
principal outside Tier 0 one of the narrow, object-specific rights that
are each enough to take over the objects below:

  - User-Force-Change-Password extended right (CONTROL_ACCESS 0x100,
    00299570-246d-11d0-a768-00aa006e0529)        -> BloodHound ForceChangePassword
  - WRITE_PROP msDS-KeyCredentialLink (5b47d60f-...) -> AddKeyCredentialLink
    (shadow credentials)
  - WRITE_PROP msDS-AllowedToActOnBehalfOfOtherIdentity (3f78c3e5-...)
                                                   -> AddAllowedToAct (RBCD)
  - WRITE_PROP servicePrincipalName (f3a64788-...) and the Validated-SPN
    validated write (Self 0x8, same GUID)          -> WriteSPN (targeted
    Kerberoasting)
  - WRITE_PROP member (bf9679c0-...)                -> AddMember
  - WRITE_PROP userAccountControl (bf967a68-...), scriptPath
    (bf9679a8-...), altSecurityIdentities (00fbf30c-..., ESC14
    certificate mapping), and the User-Account-Restrictions property set
    (4c164200-..., which contains userAccountControl and
    msDS-AllowedToActOnBehalfOfOtherIdentity)

These are the BloodHound edges that generic-rights checks (5003, 5010,
9001) do not see. Inherited copies are ignored (an ACE is reported on the
domain root or OU where it is set). Deny ACEs are ignored.

Severity, following plugin 5010's reasoning about SDProp: SDProp
disables inheritance only on objects with adminCount = 1, so a grant on
a container reaches every object below it that is NOT adminCount-
protected.
  critical -- some grant can reach a Tier 0 object of a class the right
              applies to (user/computer for password, key credential,
              RBCD, SPN, UAC, altSecurityIdentities and account
              restrictions; user for scriptPath; group for member) that
              lies below the scope and has adminCount <> 1 (or none):
              typically a domain controller or CA host computer object
              under the domain root or the Domain Controllers OU, or a
              Tier 0 principal (v_privileged_principal, e.g. a DCSync
              account) that is not adminCount-protected;
  high     -- otherwise, a grant set at the domain root (it reaches every
              unprotected account of that class domain-wide);
  medium   -- otherwise (OU scopes reaching no Tier 0 object).
An ACE limited to one descendant class (inherited object type user /
computer / group) is only matched against objects of that exact class.
One row per trustee, listing right -> scope.

Excluded trustees: SYSTEM, Administrators, Domain Admins, Enterprise
Admins, Schema Admins, Domain Controllers, Enterprise Domain
Controllers, Key Admins and Enterprise Key Admins (Windows Server 2016+
grants them msDS-KeyCredentialLink write at the domain root by default),
Creator Owner and Self (default domain-root ACEs grant SELF the RBCD
attribute and validated writes), AdminSDHolder-protected groups and
Tier 0 principals. As in 5013, Tier 0 status derived only from ACLs on /
ownership of the domain root or an OU is not an exemption. Unresolvable
trustee SIDs are reported by SID or well-known name.

Caveats: acl_edge does not record CONTAINER_INHERIT, so an ACE that is
not inherit-only is assumed to reach descendants too. The collector
merges ACEs that differ only in inherited object type, so a class-scoped
grant may appear unscoped (and be matched against every class). A
container below the scope with inheritance disabled would stop the grant;
that is not modelled.
"""

PLUGIN = {
    "plugin_id": 5014,
    "category": "ACLs",
    "name": "Targeted Attribute-Write and Password-Reset Delegations",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "ACL-5014",
    "framework_tags": [
        "NIST-800-53-AC-3",
        "NIST-800-53-AC-6",
        "NIST-800-53-AC-6(1)",
        "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-7.2.1",
        "PCI-DSS-4.0-7.2.2",
        "CIS-CSC-8-3.3",
        "CIS-CSC-8-6.8",
        "ISO-27001-2022-A.5.15",
        "ISO-27001-2022-A.8.3",
        "SOC2-CC6.3",
        "HIPAA-164.312(a)(1)",
        "MITRE-ATTCK-T1098",
        "CISA-AA26-237A",
    ],
    "references": [
        {"title": "MITRE ATT&CK T1098: Account Manipulation",
         "url": "https://attack.mitre.org/techniques/T1098/"},
        {"title": "Microsoft: Appendix C - Protected Accounts and Groups in Active Directory (SDProp)",
         "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory"},
    ],
    "description": (
        "Flags delegations on the domain root or OUs that give a principal "
        "outside Tier 0 reset-password, shadow-credential "
        "(msDS-KeyCredentialLink), RBCD, servicePrincipalName (incl. validated "
        "SPN), group member, userAccountControl, scriptPath, "
        "altSecurityIdentities or User-Account-Restrictions write rights over "
        "the objects below. Critical when a grant reaches a Tier 0 object that "
        "is not AdminSDHolder-protected (e.g. a domain controller computer "
        "object); high when set at the domain root; medium for OU scopes. One "
        "finding per trustee."
    ),
    "remediation": (
        "Remove grants that are not needed (`dsacls \"<OU or domain DN>\" /R "
        "<trustee>` removes all of the trustee's explicit ACEs there; re-grant "
        "anything legitimate), or via Security > Advanced on the container. "
        "Scope remaining delegations (help desk password reset, group "
        "management) to OUs that hold only lower-tier objects and to the "
        "specific object class, never to the domain root or an OU above "
        "domain controllers, CA servers or Tier 0 accounts. Move Tier 0 "
        "accounts into a dedicated Tier 0 OU with no delegations, and "
        "review the targeted objects for planted key credentials, SPNs, "
        "RBCD entries and logon scripts."
    ),
    "base_severity": "critical",
    "query": """
        WITH container AS (
            SELECT d.object_guid, o.dn_current, 'domain root'::text AS label, true AS is_root
            FROM ad_domain d
            JOIN directory_object o ON o.object_guid = d.object_guid AND o.client_id = d.client_id
            WHERE d.client_id = %(client_id)s AND d.valid_to IS NULL
            UNION ALL
            SELECT u.object_guid, o.dn_current,
                   'OU "' || COALESCE(u.ou_name, o.dn_current) || '"', false
            FROM ad_ou u
            JOIN directory_object o ON o.object_guid = u.object_guid AND o.client_id = u.client_id
                                    AND NOT o.is_deleted
            WHERE u.client_id = %(client_id)s AND u.valid_to IS NULL
        ),
        t0p AS (
            SELECT DISTINCT p.object_guid
            FROM v_privileged_principal p
            WHERE p.client_id = %(client_id)s
              AND NOT (p.privilege_source IN ('tier0_acl_control', 'tier0_acl_control_via_group',
                                              'tier0_ownership', 'tier0_ownership_via_group')
                       AND p.via_object_guid IN (SELECT object_guid FROM container))
        ),
        tier0_sid AS (
            SELECT d.object_sid AS sid
            FROM t0p JOIN directory_object d
              ON d.object_guid = t0p.object_guid AND d.client_id = %(client_id)s
            WHERE d.object_sid IS NOT NULL
            UNION
            SELECT d.object_sid
            FROM ad_group g
            JOIN directory_object d ON d.object_guid = g.object_guid AND d.client_id = g.client_id
            WHERE g.client_id = %(client_id)s AND g.valid_to IS NULL
              AND g.is_protected_group AND d.object_sid IS NOT NULL
        ),
        -- Tier 0 users/computers/groups that inherit ACEs (adminCount <> 1)
        exposed_tier0 AS (
            SELECT d.object_guid, lower(d.dn_current) AS dn, d.object_class::text AS cls,
                   COALESCE(d.sam_account_name, d.dn_current) AS name
            FROM directory_object d
            LEFT JOIN ad_user u ON u.object_guid = d.object_guid AND u.client_id = d.client_id
                               AND u.valid_to IS NULL
            LEFT JOIN ad_computer c ON c.object_guid = d.object_guid AND c.client_id = d.client_id
                                   AND c.valid_to IS NULL
            LEFT JOIN ad_group g ON g.object_guid = d.object_guid AND g.client_id = d.client_id
                                AND g.valid_to IS NULL
            WHERE d.client_id = %(client_id)s
              AND NOT d.is_deleted
              AND d.object_class IN ('user', 'computer', 'group')
              AND COALESCE(u.admin_count, c.admin_count, g.admin_count) IS DISTINCT FROM 1
              AND (d.object_guid IN (SELECT object_guid FROM t0p)
                   OR d.object_guid IN (SELECT t.object_guid FROM v_tier0_object t
                                        WHERE t.client_id = %(client_id)s))
        ),
        right_def (label, bit, guid, classes) AS (
            VALUES
                ('ForceChangePassword', 256, '00299570-246d-11d0-a768-00aa006e0529'::uuid, ARRAY['user', 'computer']),
                ('Write msDS-KeyCredentialLink', 32, '5b47d60f-6090-40b2-9f37-2a4de88f3063'::uuid, ARRAY['user', 'computer']),
                ('Write msDS-AllowedToActOnBehalfOfOtherIdentity', 32, '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79'::uuid, ARRAY['user', 'computer']),
                ('Write servicePrincipalName', 32, 'f3a64788-5306-11d1-a9c5-0000f80367c1'::uuid, ARRAY['user', 'computer']),
                ('Validated write SPN', 8, 'f3a64788-5306-11d1-a9c5-0000f80367c1'::uuid, ARRAY['user', 'computer']),
                ('Write member', 32, 'bf9679c0-0de6-11d0-a285-00aa003049e2'::uuid, ARRAY['group']),
                ('Write userAccountControl', 32, 'bf967a68-0de6-11d0-a285-00aa003049e2'::uuid, ARRAY['user', 'computer']),
                ('Write scriptPath', 32, 'bf9679a8-0de6-11d0-a285-00aa003049e2'::uuid, ARRAY['user']),
                ('Write altSecurityIdentities', 32, '00fbf30c-91fe-11d1-aebc-0000f80367c1'::uuid, ARRAY['user', 'computer']),
                ('Write User-Account-Restrictions', 32, '4c164200-20c0-11d0-a768-00aa003049e2'::uuid, ARRAY['user', 'computer'])
        ),
        grants AS (
            SELECT a.trustee_sid, c.is_root, c.dn_current AS scope_dn, rd.label AS right_label,
                   c.label || CASE a.inherited_object_type_guid
                                  WHEN 'bf967aba-0de6-11d0-a285-00aa003049e2' THEN ' (user objects)'
                                  WHEN 'bf967a86-0de6-11d0-a285-00aa003049e2' THEN ' (computer objects)'
                                  WHEN 'bf967a9c-0de6-11d0-a285-00aa003049e2' THEN ' (group objects)'
                                  WHEN '4828cc14-1437-45bc-9b07-ad6f015e5f28' THEN ' (inetOrgPerson objects)'
                                  ELSE CASE WHEN a.inherited_object_type_guid IS NULL THEN ''
                                            ELSE ' (class ' || a.inherited_object_type_guid || ')' END
                              END AS scope_label,
                   -- classes the ACE can land on, after its inheritance scope
                   CASE
                       WHEN a.inherited_object_type_guid IS NULL THEN rd.classes
                       WHEN a.inherited_object_type_guid = 'bf967aba-0de6-11d0-a285-00aa003049e2'
                           THEN ARRAY(SELECT x FROM unnest(rd.classes) x WHERE x = 'user')
                       WHEN a.inherited_object_type_guid = 'bf967a86-0de6-11d0-a285-00aa003049e2'
                           THEN ARRAY(SELECT x FROM unnest(rd.classes) x WHERE x = 'computer')
                       WHEN a.inherited_object_type_guid = 'bf967a9c-0de6-11d0-a285-00aa003049e2'
                           THEN ARRAY(SELECT x FROM unnest(rd.classes) x WHERE x = 'group')
                       ELSE ARRAY[]::text[]
                   END AS target_classes
            FROM acl_edge a
            JOIN container c ON c.object_guid = a.object_guid
            JOIN right_def rd
              ON (a.access_mask & rd.bit) <> 0 AND a.object_type_guid = rd.guid
            WHERE a.client_id = %(client_id)s
              AND a.valid_to IS NULL
              AND a.ace_type = 'allow'
              AND a.inherited = FALSE
              AND a.trustee_sid NOT IN ('S-1-5-18', 'S-1-5-32-544', 'S-1-5-9', 'S-1-3-0', 'S-1-5-10')
              AND a.trustee_sid !~ '^S-1-5-21-[0-9-]+-(512|516|518|519|526|527)$'
              AND NOT EXISTS (SELECT 1 FROM tier0_sid t WHERE t.sid = a.trustee_sid)
        ),
        grants_reach AS (
            SELECT g.trustee_sid, g.is_root, g.right_label, g.scope_label,
                   ARRAY(SELECT et.name FROM exposed_tier0 et
                         WHERE et.cls = ANY (g.target_classes)
                           AND right(et.dn, length(g.scope_dn) + 1) = ',' || lower(g.scope_dn)
                         ORDER BY et.name) AS reached
            FROM grants g
        ),
        per_pair AS (
            SELECT gr.trustee_sid, gr.right_label, gr.scope_label,
                   bool_or(gr.is_root) AS is_root,
                   (SELECT array_agg(DISTINCT x ORDER BY x)
                      FROM grants_reach g2, unnest(g2.reached) x
                     WHERE g2.trustee_sid = gr.trustee_sid AND g2.right_label = gr.right_label
                       AND g2.scope_label = gr.scope_label) AS reached
            FROM grants_reach gr
            GROUP BY gr.trustee_sid, gr.right_label, gr.scope_label
        ),
        per_trustee AS (
            SELECT pp.trustee_sid,
                   bool_or(pp.reached IS NOT NULL) AS reaches_tier0,
                   bool_or(pp.is_root) AS at_root,
                   string_agg(pp.right_label || ' -> ' || pp.scope_label, '; '
                              ORDER BY pp.right_label, pp.scope_label) AS grant_list,
                   jsonb_agg(jsonb_build_object(
                       'right', pp.right_label,
                       'scope', pp.scope_label,
                       'exposed_tier0_objects', COALESCE(to_jsonb(pp.reached[1:20]), '[]'::jsonb),
                       'exposed_tier0_count', COALESCE(cardinality(pp.reached), 0)
                   ) ORDER BY pp.right_label, pp.scope_label) AS grants
            FROM per_pair pp
            GROUP BY pp.trustee_sid
        )
        SELECT
            'fail' AS status,
            tdo.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN pt.reaches_tier0 THEN 'critical'
                 WHEN pt.at_root THEN 'high'
                 ELSE 'medium' END AS fd_severity,
            'Principal ' || COALESCE(tdo.sam_account_name, wk.name, pt.trustee_sid)
                || ' holds targeted write/reset rights: ' || pt.grant_list
                || CASE WHEN pt.reaches_tier0
                        THEN ' (reaches Tier 0 objects not protected by AdminSDHolder)'
                        ELSE '' END AS summary,
            jsonb_build_object(
                'trustee_sid', pt.trustee_sid,
                'sam_account_name', tdo.sam_account_name,
                'object_class', tdo.object_class,
                'grants', pt.grants
            ) AS detail
        FROM per_trustee pt
        LEFT JOIN LATERAL (
            SELECT d.object_guid, d.sam_account_name, d.object_class
            FROM directory_object d
            WHERE d.client_id = %(client_id)s AND d.object_sid = pt.trustee_sid
              AND NOT d.is_deleted
            ORDER BY d.object_guid
            LIMIT 1
        ) tdo ON TRUE
        LEFT JOIN (VALUES
            ('S-1-1-0', 'Everyone'), ('S-1-5-7', 'Anonymous Logon'),
            ('S-1-5-11', 'Authenticated Users'), ('S-1-5-32-545', 'Users'),
            ('S-1-5-32-548', 'Account Operators'), ('S-1-5-32-549', 'Server Operators'),
            ('S-1-5-32-550', 'Print Operators'), ('S-1-5-32-551', 'Backup Operators'),
            ('S-1-5-32-554', 'Pre-Windows 2000 Compatible Access')
        ) AS wk(sid, name) ON wk.sid = pt.trustee_sid
    """,
}

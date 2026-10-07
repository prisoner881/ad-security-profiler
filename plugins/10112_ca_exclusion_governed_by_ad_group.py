"""
Plugin 10112: Conditional Access Exclusion Governed by an AD-Synced Group

Cross-domain attack path (hybrid identity). Reports Entra groups that are
listed in conditions.users.excludeGroups of an ENABLED Conditional Access
policy that requires MFA (builtInControls 'mfa' or an authentication
strength) or blocks access (builtInControls 'block'), when the group is
synchronized from on-premises AD (entra_group.on_premises_sync_enabled).

Why: the membership of a synced group is mastered in AD. An on-premises
attacker -- or any help-desk delegate -- who can write the AD group's member
attribute adds an account to the "MFA exempt" group, waits for the next sync
cycle (30 minutes by default), and has bypassed the cloud policy. Exclusion
groups are routinely synced for convenience. MITRE ATT&CK T1556.007 (Hybrid
Identity) and T1098; NIST AC-6, AC-2(1).

Escalation to critical: non-Tier-0 AD principals can modify the membership of
the AD group (resolved through entra_group.on_prem_object_guid, or the
group's on-premises SID) or of any AD group nested in it (members of nested
groups are transitive members in Entra too, and CA evaluates transitive
membership):
  * WriteProperty on the member attribute (bf9679c0-0de6-11d0-a285-00aa003049e2)
    or on all attributes (GenericWrite), validated write / Self on member
    (add self), GenericAll, WriteDacl, WriteOwner, or ownership;
  * from direct ACEs (when collected), ACEs on ancestor OUs / the domain
    root inherited by group objects (bf967a9c-0de6-11d0-a285-00aa003049e2)
    or by all classes, or control of such a container; inheritance cut by a
    protected OU DACL in between; adminCount=1 groups get AdminSDHolder's ACL
    instead (same model as plugins 1037 and 10111).
managedBy (which lets the manager edit membership when "Manager can update
membership list" is ticked) is not collected for groups, so it is not
evaluated. Deny ACEs are not evaluated.

"Non-Tier-0": as plugin 10111 (default administrative SIDs, Tier 0
principals per v_privileged_principal, AdminSDHolder-protected groups).

Requires source 'groups' (entra_group); without it nothing is known about
which excluded groups are synced. Severity: high; critical when non-Tier-0
modifiers exist. One row per Entra group (object_guid = the Entra group id).
"""

PLUGIN = {
    "plugin_id": 10112,
    "category": "Hybrid Identity",
    "name": "Conditional Access Exclusion Governed by an AD-Synced Group",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "HYBRID-10112",
    "requires_sources": ["groups"],
    "framework_tags": [
        "NIST-800-53-AC-6", "NIST-800-53-AC-3", "NIST-800-53-AC-6(1)", "NIST-800-53-IA-2(1)",
        "NIST-CSF-2.0-PR.AA-05", "NIST-CSF-2.0-PR.AA-03",
        "PCI-DSS-4.0-7.2.1", "PCI-DSS-4.0-7.2.2", "PCI-DSS-4.0-8.4.2",
        "CIS-CSC-8-3.3", "CIS-CSC-8-6.8", "CIS-CSC-8-6.3",
        "ISO-27001-2022-A.5.15", "ISO-27001-2022-A.8.3", "ISO-27001-2022-A.8.5",
        "SOC2-CC6.3", "SOC2-CC6.1",
        "HIPAA-164.312(a)(1)", "HIPAA-164.312(d)",
        "MITRE-ATTCK-T1556.007", "MITRE-ATTCK-T1098",
    ],
    "references": [
        {"title": "Microsoft: Conditional Access -- users and groups (exclusions)",
         "url": "https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-users-groups"},
        {"title": "Microsoft: Protecting Microsoft 365 from on-premises attacks",
         "url": "https://learn.microsoft.com/en-us/entra/architecture/protect-m365-from-on-premises-attacks"},
        {"title": "BloodHound (SpecterOps): AddMember edge",
         "url": "https://bloodhound.specterops.io/resources/edges/add-member"},
        {"title": "MITRE ATT&CK T1556.007: Modify Authentication Process: Hybrid Identity",
         "url": "https://attack.mitre.org/techniques/T1556/007/"},
    ],
    "description": (
        "Reports groups excluded from enabled Conditional Access policies that require MFA or "
        "block access, when the group is synchronized from on-premises AD. Its membership is "
        "mastered in AD, so whoever can change the AD group's membership can exempt any "
        "account from the policy. Critical when non-Tier-0 AD principals can write the AD "
        "group's (or a nested group's) member attribute, add themselves, or hold "
        "GenericAll/GenericWrite/WriteDacl/WriteOwner or ownership -- directly, through an "
        "ancestor OU, or through AdminSDHolder for adminCount=1 groups."
    ),
    "remediation": (
        "Use a cloud-only group for Conditional Access exclusions (break-glass accounts and "
        "documented exceptions), managed in Entra and ideally through PIM for Groups or an "
        "access review; remove the synced group from the policy's excludeGroups. If a synced "
        "group must stay, place it (and any nested group) in a Tier 0 OU, remove the listed "
        "non-Tier-0 delegations (dsacls / Get-Acl \"AD:CN=...\"), set the owner to Domain "
        "Admins, and alert on membership changes (event 4728/4732/4756)."
    ),
    "base_severity": "high",
    "query": """
        WITH ca AS (
            SELECT p->>'id' AS policy_id,
                   COALESCE(p->>'display_name', p->>'id') AS policy_name,
                   CASE WHEN jsonb_typeof(p->'grant_controls'->'builtInControls') = 'array'
                             AND p->'grant_controls'->'builtInControls' ? 'block'
                        THEN 'block' ELSE 'MFA' END AS control,
                   p->'conditions'->'users'->'excludeGroups' AS exclude_groups
            FROM entra_security_posture sp
            CROSS JOIN LATERAL jsonb_array_elements(
                CASE WHEN jsonb_typeof(sp.ca_policies) = 'array' THEN sp.ca_policies
                     ELSE '[]'::jsonb END) p
            WHERE sp.client_id = %(client_id)s
              AND p->>'state' = 'enabled'
              AND ((jsonb_typeof(p->'grant_controls'->'builtInControls') = 'array'
                    AND (p->'grant_controls'->'builtInControls' ? 'mfa'
                         OR p->'grant_controls'->'builtInControls' ? 'block'))
                   OR jsonb_typeof(p->'grant_controls'->'authenticationStrength') = 'object')
        ),
        excluded AS (
            SELECT ca.policy_id, ca.policy_name, ca.control, g.value #>> '{}' AS group_id
            FROM ca
            CROSS JOIN LATERAL jsonb_array_elements(
                CASE WHEN jsonb_typeof(ca.exclude_groups) = 'array' THEN ca.exclude_groups
                     ELSE '[]'::jsonb END) g
        ),
        grp AS (
            SELECT eg.entra_object_id, eg.display_name, eg.on_premises_security_identifier,
                   COALESCE(eg.on_prem_object_guid,
                            (SELECT d.object_guid FROM directory_object d
                             WHERE d.client_id = %(client_id)s
                               AND d.object_sid = eg.on_premises_security_identifier
                               AND NOT d.is_deleted
                             ORDER BY d.object_guid LIMIT 1)) AS ad_guid,
                   string_agg(DISTINCT '"' || e.policy_name || '" (' || e.control || ')', ', '
                              ORDER BY '"' || e.policy_name || '" (' || e.control || ')') AS policy_list,
                   jsonb_agg(DISTINCT jsonb_build_object('policy_id', e.policy_id,
                                                         'policy_name', e.policy_name,
                                                         'control', e.control)) AS policies
            FROM entra_group eg
            JOIN excluded e ON e.group_id = eg.entra_object_id::text
            WHERE eg.client_id = %(client_id)s
              AND eg.on_premises_sync_enabled IS TRUE
            GROUP BY eg.entra_object_id, eg.display_name, eg.on_premises_security_identifier,
                     eg.on_prem_object_guid
        ),
        ad_target AS (
            -- The synced AD group itself and every AD group nested in it.
            SELECT g.entra_object_id, ag.object_guid AS ad_group_guid, NULL::text AS via_nested
            FROM grp g
            JOIN ad_group ag
              ON ag.client_id = %(client_id)s AND ag.object_guid = g.ad_guid AND ag.valid_to IS NULL
            UNION
            SELECT g.entra_object_id, ng.object_guid, ng.sam_account_name
            FROM grp g
            JOIN v_effective_group_membership vem
              ON vem.client_id = %(client_id)s AND vem.group_guid = g.ad_guid
            JOIN ad_group ng
              ON ng.client_id = %(client_id)s AND ng.object_guid = vem.member_guid
             AND ng.valid_to IS NULL
        ),
        target AS (
            SELECT at.entra_object_id, at.ad_group_guid, at.via_nested,
                   ag.sam_account_name, ag.admin_count,
                   d.object_sid, d.owner_sid, lower(d.dn_current) AS dn_lc,
                   CASE WHEN ag.admin_count = 1
                        THEN d.sd_control IS NOT NULL AND (d.sd_control & 4096) = 0
                        ELSE d.sd_control IS NULL OR (d.sd_control & 4096) = 0
                   END AS inherits
            FROM ad_target at
            JOIN ad_group ag
              ON ag.client_id = %(client_id)s AND ag.object_guid = at.ad_group_guid
             AND ag.valid_to IS NULL
            JOIN directory_object d
              ON d.client_id = ag.client_id AND d.object_guid = ag.object_guid AND NOT d.is_deleted
        ),
        tier0_sid AS (
            SELECT DISTINCT d.object_sid::text AS sid
            FROM directory_object d
            WHERE d.client_id = %(client_id)s
              AND d.object_sid IS NOT NULL
              AND NOT d.is_deleted
              AND (EXISTS (SELECT 1 FROM v_privileged_principal p
                           WHERE p.client_id = d.client_id AND p.object_guid = d.object_guid)
                   OR EXISTS (SELECT 1 FROM v_tier0_object t
                              WHERE t.client_id = d.client_id AND t.object_guid = d.object_guid
                                AND t.tier0_reason = 'protected_group'))
        ),
        container AS (
            SELECT o.object_guid, lower(d.dn_current) AS dn_lc,
                   'OU "' || COALESCE(o.ou_name, d.dn_current) || '"' AS label,
                   d.sd_control, TRUE AS is_ou
            FROM ad_ou o
            JOIN directory_object d
              ON d.client_id = o.client_id AND d.object_guid = o.object_guid AND NOT d.is_deleted
            WHERE o.client_id = %(client_id)s AND o.valid_to IS NULL
            UNION ALL
            SELECT dm.object_guid, lower(d.dn_current), 'domain root', d.sd_control, FALSE
            FROM ad_domain dm
            JOIN directory_object d
              ON d.client_id = dm.client_id AND d.object_guid = dm.object_guid AND NOT d.is_deleted
            WHERE dm.client_id = %(client_id)s AND dm.valid_to IS NULL
        ),
        adminsdholder AS (
            SELECT t.object_guid FROM v_tier0_object t
            WHERE t.client_id = %(client_id)s AND t.tier0_reason = 'adminsdholder'
        ),
        ace AS (
            SELECT a.object_guid, a.trustee_sid::text AS trustee_sid, a.inherit_only,
                   a.inherited_object_type_guid,
                   CASE
                       WHEN (a.access_mask & 983551) = 983551 OR (a.access_mask & 268435456) <> 0
                           THEN 'GenericAll'
                       WHEN (a.access_mask & 1073741824) <> 0
                         OR ((a.access_mask & 32) <> 0 AND a.object_type_guid IS NULL)
                           THEN 'GenericWrite'
                       WHEN (a.access_mask & 262144) <> 0 THEN 'WriteDacl'
                       WHEN (a.access_mask & 524288) <> 0 THEN 'WriteOwner'
                       WHEN (a.access_mask & 32) <> 0
                        AND a.object_type_guid = 'bf9679c0-0de6-11d0-a285-00aa003049e2'
                           THEN 'WriteMember'
                       WHEN (a.access_mask & 8) <> 0
                        AND (a.object_type_guid IS NULL
                             OR a.object_type_guid = 'bf9679c0-0de6-11d0-a285-00aa003049e2')
                           THEN 'AddSelf'
                   END AS right_name
            FROM acl_edge a
            WHERE a.client_id = %(client_id)s
              AND a.valid_to IS NULL
              AND a.ace_type = 'allow'
        ),
        grant_path AS (
            SELECT t.entra_object_id, t.ad_group_guid, t.sam_account_name, t.via_nested, t.object_sid,
                   x.trustee_sid, x.right_name, 'direct ACE' AS path
            FROM target t
            JOIN ace x ON x.object_guid = t.ad_group_guid
            WHERE x.right_name IS NOT NULL AND x.inherit_only IS NOT TRUE
            UNION
            SELECT t.entra_object_id, t.ad_group_guid, t.sam_account_name, t.via_nested, t.object_sid,
                   x.trustee_sid, x.right_name, 'AdminSDHolder ACL (SDProp)'
            FROM target t
            JOIN adminsdholder s ON TRUE
            JOIN ace x ON x.object_guid = s.object_guid
            WHERE t.admin_count = 1 AND x.right_name IS NOT NULL AND x.inherit_only IS NOT TRUE
            UNION
            SELECT t.entra_object_id, t.ad_group_guid, t.sam_account_name, t.via_nested, t.object_sid,
                   x.trustee_sid, x.right_name, 'inherited from ' || c.label
            FROM target t
            JOIN container c ON right(t.dn_lc, length(c.dn_lc) + 1) = ',' || c.dn_lc
            JOIN ace x ON x.object_guid = c.object_guid
            WHERE t.inherits
              AND x.right_name IS NOT NULL
              AND (
                    (x.inherit_only IS NOT TRUE
                     AND x.right_name IN ('GenericAll', 'GenericWrite', 'WriteDacl', 'WriteOwner'))
                 OR x.inherited_object_type_guid IS NULL
                 OR x.inherited_object_type_guid = 'bf967a9c-0de6-11d0-a285-00aa003049e2'
                  )
              AND NOT EXISTS (
                    SELECT 1 FROM container b
                    WHERE b.is_ou
                      AND b.sd_control IS NOT NULL AND (b.sd_control & 4096) <> 0
                      AND right(t.dn_lc, length(b.dn_lc) + 1) = ',' || b.dn_lc
                      AND right(b.dn_lc, length(c.dn_lc) + 1) = ',' || c.dn_lc
                  )
            UNION
            SELECT t.entra_object_id, t.ad_group_guid, t.sam_account_name, t.via_nested, t.object_sid,
                   t.owner_sid::text, 'Owner', 'object owner'
            FROM target t
            WHERE t.owner_sid IS NOT NULL
        ),
        modifier AS (
            SELECT g.entra_object_id, g.trustee_sid, g.right_name, g.path,
                   g.sam_account_name AS ad_group, g.via_nested,
                   COALESCE(tdo.sam_account_name, wk.name, g.trustee_sid) AS trustee_name
            FROM grant_path g
            LEFT JOIN LATERAL (
                SELECT d.sam_account_name FROM directory_object d
                WHERE d.client_id = %(client_id)s AND d.object_sid = g.trustee_sid
                ORDER BY d.is_deleted, d.object_guid LIMIT 1
            ) tdo ON TRUE
            LEFT JOIN (VALUES ('S-1-1-0', 'Everyone'), ('S-1-5-7', 'Anonymous Logon'),
                              ('S-1-5-11', 'Authenticated Users'),
                              ('S-1-5-32-545', 'BUILTIN\\Users'),
                              ('S-1-5-32-554', 'Pre-Windows 2000 Compatible Access')
                      ) AS wk(sid, name) ON wk.sid = g.trustee_sid
            WHERE g.trustee_sid NOT IN ('S-1-5-18', 'S-1-5-32-544', 'S-1-5-32-548', 'S-1-5-32-549',
                                        'S-1-5-32-550', 'S-1-5-32-551', 'S-1-5-9', 'S-1-5-10',
                                        'S-1-3-0')
              AND g.trustee_sid !~ '^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-(512|516|518|519|526|527)$'
              AND g.trustee_sid IS DISTINCT FROM g.object_sid::text
              AND NOT EXISTS (SELECT 1 FROM tier0_sid s WHERE s.sid = g.trustee_sid)
        ),
        modifier_agg AS (
            SELECT m.entra_object_id,
                   string_agg(DISTINCT m.trustee_name, ', ' ORDER BY m.trustee_name) AS trustee_list,
                   jsonb_agg(DISTINCT jsonb_build_object(
                       'trustee', m.trustee_name, 'trustee_sid', m.trustee_sid,
                       'right', m.right_name, 'path', m.path,
                       'ad_group', m.ad_group, 'via_nested_group', m.via_nested)) AS modifiers
            FROM modifier m
            GROUP BY m.entra_object_id
        )
        SELECT
            CASE WHEN ma.entra_object_id IS NOT NULL THEN 'fail' ELSE 'warn' END AS status,
            g.entra_object_id AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN ma.entra_object_id IS NOT NULL THEN 'critical' ELSE 'high' END AS fd_severity,
            'Group "' || COALESCE(g.display_name, g.entra_object_id::text)
                || '", excluded from enabled Conditional Access polic(ies) ' || g.policy_list
                || ', is synchronized from on-premises AD'
                || CASE WHEN ma.entra_object_id IS NOT NULL
                        THEN ' and non-Tier-0 AD principal(s) ' || ma.trustee_list
                             || ' can change its membership'
                        ELSE ' -- whoever controls its AD membership bypasses those policies'
                   END AS summary,
            jsonb_build_object(
                'group_display_name', g.display_name,
                'on_premises_security_identifier', g.on_premises_security_identifier,
                'ad_group_guid', g.ad_guid,
                'ad_group_resolved', EXISTS (SELECT 1 FROM ad_target t
                                             WHERE t.entra_object_id = g.entra_object_id),
                'ad_group_sam_account_name', (SELECT ag.sam_account_name FROM ad_group ag
                                              WHERE ag.client_id = %(client_id)s
                                                AND ag.object_guid = g.ad_guid
                                                AND ag.valid_to IS NULL),
                'excluded_from_policies', g.policies,
                'non_tier0_membership_modifiers', COALESCE(ma.modifiers, '[]'::jsonb),
                'note', 'managedBy is not collected for groups and deny ACEs are not evaluated.',
                'related_plugins', jsonb_build_array(10111, 1037)
            ) AS detail
        FROM grp g
        LEFT JOIN modifier_agg ma ON ma.entra_object_id = g.entra_object_id
    """,
}

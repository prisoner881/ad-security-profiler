"""
Plugin 10111: On-Premises Principals Can Control a Privileged Entra ID Account's AD Object

Cross-domain attack path (hybrid identity, BloodHound's hybrid edge computed
from our own data). Population: AD user accounts synchronized to Entra ID
(entra_user.on_prem_object_guid, falling back to the role-member row's own
on_prem_object_guid) whose Entra account holds a highly privileged directory
role -- active or PIM-eligible, directly or via a role-assignable group (the
TIER0 role set: Global, Privileged Role, Privileged Authentication, Security,
Hybrid Identity, Application, Cloud Application, Exchange, SharePoint, User,
Conditional Access, Authentication and Intune Administrator).

Reports every non-Tier-0 AD principal that can take over such an AD object:
  * reset its password (extended right User-Force-Change-Password,
    00299570-246d-11d0-a768-00aa006e0529) or All Extended Rights;
  * GenericAll, GenericWrite / WriteProperty on all attributes, WriteDacl,
    WriteOwner;
  * ownership of the object (directory_object.owner_sid).

Why: the attacker resets the AD password (or adds a credential), password
hash sync carries it to the cloud within minutes, and the attacker signs in
as a tenant administrator. MITRE ATT&CK T1098 / T1078.004; CISA SCuBA
MS.AAD.7.3 (privileged cloud accounts must be cloud-only).

Where the rights come from (ACLs are collected on OUs, the domain root and
AdminSDHolder, not on every user; same model as plugin 1037):
  * direct ACEs on the user object when the collector has them;
  * ACEs on every ancestor OU and the domain root (DN-suffix match) that
    reach user objects: rights on the container itself (GenericAll /
    GenericWrite / WriteDacl / WriteOwner -- the holder can grant itself an
    inheritable ACE), or ACEs inherited by all classes or by the user class
    (bf967aba-0de6-11d0-a285-00aa003049e2). Inheritance is cut by an OU in
    between whose DACL is protected (directory_object.sd_control 0x1000);
  * AdminSDHolder: SDProp stamps AdminSDHolder's DACL onto adminCount=1
    accounts and turns inheritance off, so for them the AdminSDHolder ACEs
    apply and the OU ACEs do NOT -- unless the user's sd_control is known and
    shows inheritance re-enabled (protection lapsed). For other users a known
    protected DACL (sd_control 0x1000) also stops OU inheritance.
Deny ACEs are not evaluated (an allow can be shadowed by an explicit deny;
review before acting). The ACE's CONTAINER_INHERIT flag is not collected, so
a non-inherit-only ACE on an OU is assumed to flow to descendants (as 1037).

"Non-Tier-0": the trustee SID is not SYSTEM, Administrators, Account /
Server / Print / Backup Operators, Enterprise Domain Controllers, SELF,
Creator Owner, Domain Admins, Domain Controllers, Schema Admins, Enterprise
Admins, Key Admins, Enterprise Key Admins, not a v_privileged_principal
object or AdminSDHolder-protected group, and not the account itself.
Unresolvable SIDs are reported by SID.

Severity: critical; high when the AD account is disabled (a password reset
alone does not re-enable it, though GenericAll/GenericWrite could). One row
per AD user (object_guid = the AD objectGUID), aggregating every trustee.
"""

PLUGIN = {
    "plugin_id": 10111,
    "category": "Hybrid Identity",
    "name": "On-Premises Principals Can Control a Privileged Entra ID Account's AD Object",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "HYBRID-10111",
    "framework_tags": [
        "CISA-SCUBA-MS.AAD.7.3",
        "NIST-800-53-AC-3", "NIST-800-53-AC-6", "NIST-800-53-AC-6(1)",
        "NIST-800-53-AC-2(7)", "NIST-800-53-AC-6(5)",
        "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-7.2.1", "PCI-DSS-4.0-7.2.2",
        "CIS-CSC-8-3.3", "CIS-CSC-8-6.8", "CIS-CSC-8-5.4",
        "ISO-27001-2022-A.5.15", "ISO-27001-2022-A.8.3", "ISO-27001-2022-A.8.2",
        "SOC2-CC6.3",
        "HIPAA-164.312(a)(1)", "HIPAA-164.308(a)(4)(ii)(B)",
        "MITRE-ATTCK-T1098", "MITRE-ATTCK-T1078.004",
    ],
    "references": [
        {"title": "Microsoft: Protecting Microsoft 365 from on-premises attacks",
         "url": "https://learn.microsoft.com/en-us/entra/architecture/protect-m365-from-on-premises-attacks"},
        {"title": "CISA SCuBA Microsoft Entra ID baseline (MS.AAD.7.3)",
         "url": "https://github.com/cisagov/ScubaGear/blob/main/PowerShell/ScubaGear/baselines/aad.md"},
        {"title": "BloodHound (SpecterOps): ForceChangePassword edge",
         "url": "https://bloodhound.specterops.io/resources/edges/force-change-password"},
        {"title": "BloodHound (SpecterOps): GenericAll edge",
         "url": "https://bloodhound.specterops.io/resources/edges/generic-all"},
        {"title": "MITRE ATT&CK T1078.004: Valid Accounts: Cloud Accounts",
         "url": "https://attack.mitre.org/techniques/T1078/004/"},
    ],
    "description": (
        "Reports synced AD accounts whose Entra identity holds a highly privileged role "
        "(active or eligible, direct or via a group) and over which non-Tier-0 AD principals "
        "can reset the password or hold GenericAll, GenericWrite, WriteDacl, WriteOwner or "
        "ownership -- through direct ACEs, inheritable ACEs on an ancestor OU or the domain "
        "root, or, for adminCount=1 accounts, the AdminSDHolder ACL. A reset AD password "
        "syncs to the cloud, so each such principal can become a tenant administrator. One "
        "finding per AD account, listing every trustee and the path of its right."
    ),
    "remediation": (
        "Preferred: hold privileged Entra roles only on cloud-only accounts (SCuBA MS.AAD.7.3) "
        "and remove the role (or PIM eligibility) from the synced account. Otherwise move the "
        "synced account into a Tier 0 OU whose ACL grants rights only to Tier 0 admins, and "
        "remove the listed delegations: review the OU ACL (dsacls \"OU=...\" or Get-Acl "
        "\"AD:OU=...\"), remove help-desk password-reset or full-control ACEs that reach user "
        "objects, remove non-Tier-0 ACEs from CN=AdminSDHolder,CN=System, and set the owner of "
        "the account to Domain Admins. Consider scoping the Entra Connect sync rules so that "
        "admin accounts are not synchronized at all."
    ),
    "base_severity": "critical",
    "query": """
        WITH priv_role (template_id, role_name) AS (
            VALUES ('62e90394-69f5-4237-9190-012177145e10'::uuid, 'Global Administrator'),
                   ('e8611ab8-c189-46e8-94e1-60213ab1f814'::uuid, 'Privileged Role Administrator'),
                   ('7be44c8a-adaf-4e2a-84d6-ab2649e08a13'::uuid, 'Privileged Authentication Administrator'),
                   ('194ae4cb-b126-40b2-bd5b-6091b380977d'::uuid, 'Security Administrator'),
                   ('8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2'::uuid, 'Hybrid Identity Administrator'),
                   ('9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3'::uuid, 'Application Administrator'),
                   ('158c047a-c907-4556-b7ef-446551a6b5f7'::uuid, 'Cloud Application Administrator'),
                   ('29232cdf-9323-42fd-ade2-1d097af3e4de'::uuid, 'Exchange Administrator'),
                   ('f28a1f50-f6e7-4571-818b-6a12f2af6b6c'::uuid, 'SharePoint Administrator'),
                   ('fe930be7-5e62-47db-91af-98c3a49a38b1'::uuid, 'User Administrator'),
                   ('b1be1c3e-b65d-4f19-8427-f6fa0d97feb9'::uuid, 'Conditional Access Administrator'),
                   ('c4e39bd9-1100-46d3-8c65-fb160da0071f'::uuid, 'Authentication Administrator'),
                   ('3a2c62db-5318-420d-8d74-23affee5d9d5'::uuid, 'Intune Administrator')
        ),
        holder AS (
            SELECT COALESCE(eu.on_prem_object_guid, rm.on_prem_object_guid) AS ad_guid,
                   rm.member_id,
                   COALESCE(eu.user_principal_name, rm.member_upn) AS upn,
                   pr.role_name, rm.assignment_type, rm.via_group_id, rm.via_group_display_name
            FROM entra_directory_role_member rm
            JOIN priv_role pr ON pr.template_id = rm.role_template_id
            LEFT JOIN entra_user eu
              ON eu.client_id = rm.client_id AND eu.entra_object_id = rm.member_id
            WHERE rm.client_id = %(client_id)s
              AND rm.member_type = '#microsoft.graph.user'
              AND COALESCE(eu.on_prem_object_guid, rm.on_prem_object_guid) IS NOT NULL
        ),
        holder_agg AS (
            SELECT h.ad_guid,
                   min(h.member_id::text) AS entra_object_id,
                   min(h.upn) AS upn,
                   string_agg(DISTINCT h.role_name, ', ' ORDER BY h.role_name) AS role_list,
                   jsonb_agg(DISTINCT jsonb_build_object(
                       'role', h.role_name,
                       'assignment_type', h.assignment_type,
                       'via_group', COALESCE(h.via_group_display_name, h.via_group_id::text)
                   )) AS role_assignments
            FROM holder h
            GROUP BY h.ad_guid
        ),
        target AS (
            SELECT ha.*, u.object_guid, u.sam_account_name, u.is_enabled, u.admin_count,
                   d.object_sid, d.owner_sid, d.sd_control, lower(d.dn_current) AS dn_lc,
                   -- Does this account inherit ACEs from its containers?
                   CASE WHEN u.admin_count = 1
                        THEN d.sd_control IS NOT NULL AND (d.sd_control & 4096) = 0
                        ELSE d.sd_control IS NULL OR (d.sd_control & 4096) = 0
                   END AS inherits
            FROM holder_agg ha
            JOIN ad_user u
              ON u.client_id = %(client_id)s AND u.object_guid = ha.ad_guid AND u.valid_to IS NULL
            JOIN directory_object d
              ON d.client_id = u.client_id AND d.object_guid = u.object_guid AND NOT d.is_deleted
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
                       WHEN (a.access_mask & 256) <> 0 AND a.object_type_guid IS NULL
                           THEN 'AllExtendedRights'
                       WHEN (a.access_mask & 256) <> 0
                        AND a.object_type_guid = '00299570-246d-11d0-a768-00aa006e0529'
                           THEN 'ForceChangePassword'
                   END AS right_name
            FROM acl_edge a
            WHERE a.client_id = %(client_id)s
              AND a.valid_to IS NULL
              AND a.ace_type = 'allow'
        ),
        grant_path AS (
            -- Direct ACEs on the account (when collected).
            SELECT t.object_guid, x.trustee_sid, x.right_name, 'direct ACE' AS path
            FROM target t
            JOIN ace x ON x.object_guid = t.object_guid
            WHERE x.right_name IS NOT NULL AND x.inherit_only IS NOT TRUE
            UNION
            -- AdminSDHolder's DACL, stamped by SDProp onto adminCount=1 accounts.
            SELECT t.object_guid, x.trustee_sid, x.right_name, 'AdminSDHolder ACL (SDProp)'
            FROM target t
            JOIN adminsdholder s ON TRUE
            JOIN ace x ON x.object_guid = s.object_guid
            WHERE t.admin_count = 1
              AND x.right_name IS NOT NULL AND x.inherit_only IS NOT TRUE
            UNION
            -- Ancestor OUs and the domain root.
            SELECT t.object_guid, x.trustee_sid, x.right_name, 'inherited from ' || c.label
            FROM target t
            JOIN container c
              ON right(t.dn_lc, length(c.dn_lc) + 1) = ',' || c.dn_lc
            JOIN ace x ON x.object_guid = c.object_guid
            WHERE t.inherits
              AND x.right_name IS NOT NULL
              AND (
                    (x.inherit_only IS NOT TRUE
                     AND x.right_name IN ('GenericAll', 'GenericWrite', 'WriteDacl', 'WriteOwner'))
                 OR x.inherited_object_type_guid IS NULL
                 OR x.inherited_object_type_guid = 'bf967aba-0de6-11d0-a285-00aa003049e2'
                  )
              -- An OU in between with a protected DACL stops inheritance.
              AND NOT EXISTS (
                    SELECT 1 FROM container b
                    WHERE b.is_ou
                      AND b.sd_control IS NOT NULL AND (b.sd_control & 4096) <> 0
                      AND right(t.dn_lc, length(b.dn_lc) + 1) = ',' || b.dn_lc
                      AND right(b.dn_lc, length(c.dn_lc) + 1) = ',' || c.dn_lc
                  )
            UNION
            -- Ownership.
            SELECT t.object_guid, t.owner_sid::text, 'Owner', 'object owner'
            FROM target t
            WHERE t.owner_sid IS NOT NULL
        ),
        nontier0 AS (
            SELECT g.object_guid, g.trustee_sid, g.right_name, g.path,
                   COALESCE(tdo.sam_account_name, wk.name, g.trustee_sid) AS trustee_name
            FROM grant_path g
            JOIN target t ON t.object_guid = g.object_guid
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
              AND g.trustee_sid IS DISTINCT FROM t.object_sid::text
              AND NOT EXISTS (SELECT 1 FROM tier0_sid s WHERE s.sid = g.trustee_sid)
        )
        SELECT
            'fail' AS status,
            t.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN t.is_enabled IS FALSE THEN 'high' ELSE 'critical' END AS fd_severity,
            'Non-Tier-0 AD principal(s) '
                || string_agg(DISTINCT n.trustee_name, ', ' ORDER BY n.trustee_name)
                || ' can take over synced AD account "'
                || COALESCE(t.sam_account_name, t.object_guid::text)
                || '", which holds privileged Entra role(s) ' || t.role_list
                || ' as "' || COALESCE(t.upn, t.entra_object_id) || '"'
                || CASE WHEN t.is_enabled IS FALSE THEN ' (AD account disabled)' ELSE '' END
                || ' -- a password set on-premises syncs to the cloud' AS summary,
            jsonb_build_object(
                'ad_sam_account_name', t.sam_account_name,
                'entra_object_id', t.entra_object_id,
                'entra_user_principal_name', t.upn,
                'privileged_entra_roles', t.role_assignments,
                'ad_account_enabled', t.is_enabled,
                'admin_count', t.admin_count,
                'inherits_container_aces', t.inherits,
                'trustees', jsonb_agg(DISTINCT jsonb_build_object(
                    'trustee', n.trustee_name,
                    'trustee_sid', n.trustee_sid,
                    'right', n.right_name,
                    'path', n.path)),
                'note', 'Deny ACEs are not evaluated.',
                'related_plugins', jsonb_build_array(1037, 10110, 10018),
                'scuba_policy', 'MS.AAD.7.3'
            ) AS detail
        FROM target t
        JOIN nontier0 n ON n.object_guid = t.object_guid
        GROUP BY t.object_guid, t.sam_account_name, t.entra_object_id, t.upn, t.role_list,
                 t.role_assignments, t.is_enabled, t.admin_count, t.inherits
    """,
}

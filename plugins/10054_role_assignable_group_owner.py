"""
Plugin 10054: Non-Privileged Owner of a Role-Assignable Group

Reports owners of role-assignable / role-holding Entra groups who do not
themselves hold a highly privileged role.

Why it matters: a group owner can change the group's membership. When the
group is role-assignable (isAssignableToRole) and holds a directory role,
its owner can add themselves -- or an account they control -- to the group
and so obtain the role, without ever being granted it. This is the
AzureHound "Owns -> AddMember" edge, and it bypasses PIM approval on the
role itself. Owners of role-assignable groups should be limited to
administrators who already hold the roles the group grants.

What is reported: every owner (entra_group_owner, schema v42) of a group
with is_assignable_to_role true or sensitive_reason 'holds_role', where the
owner holds no highly privileged role (Global, Privileged Role, Privileged
Authentication, Security, Hybrid Identity, Application, Cloud Application,
Exchange, SharePoint, User, Conditional Access, Authentication or Intune
Administrator; active or eligible, any path -- entra_directory_role_member).
- high 'fail' when the group itself holds one of those roles (active or
  eligible: entra_directory_role_member.member_id = the group);
- medium 'fail' otherwise (role-assignable group holding a lesser role or no
  role yet -- it can be given one at any time).
Disabled owner accounts are reported one level lower (high -> medium,
medium -> low) because they cannot act until re-enabled.

Data caveats: requires_sources ['groups'] (owners are only collected for
sensitive groups, which include every role-assignable and role-holding
group). Owners that are service principals are reported too (owner_type in
detail). Roles held by the owner are taken from entra_directory_role_member;
when PIM eligibility was not readable an owner who is only eligible would
appear unprivileged (see entra_security_posture.role_eligibility_status,
copied to detail).

object_guid: md5('10054:' || client_id || ':' || group id || ':' || owner id),
one finding per (group, owner).
"""

PLUGIN = {
    "plugin_id": 10054,
    "category": "Hybrid Identity",
    "name": "Non-Privileged Owner of a Role-Assignable Group",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "HYBRID-10054",
    "requires_sources": ["groups"],
    "framework_tags": [
        "NIST-800-53-AC-6",
        "NIST-800-53-AC-3",
        "NIST-800-53-AC-6(5)",
        "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-7.2.1",
        "PCI-DSS-4.0-7.2.2",
        "CIS-CSC-8-6.8",
        "ISO-27001-2022-A.5.15",
        "SOC2-CC6.3",
        "MITRE-ATTCK-T1098.003",
    ],
    "references": [
        {"title": "Microsoft: Use Microsoft Entra groups to manage role assignments",
         "url": "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/groups-concept"},
        {"title": "BloodHound: AZAddMembers edge",
         "url": "https://bloodhound.specterops.io/resources/edges/az-add-members"},
    ],
    "description": (
        "An owner of a role-assignable Entra group does not itself hold a "
        "highly privileged role. Group owners manage membership, so the "
        "owner can add themselves to the group and obtain every role the "
        "group holds, bypassing PIM on the role. High when the group holds "
        "a highly privileged role, medium otherwise; one finding per "
        "(group, owner)."
    ),
    "remediation": (
        "Remove the owner (Entra admin center -> Groups -> <group> -> Owners, "
        "or Remove-MgGroupOwnerByRef -GroupId <group> -DirectoryObjectId "
        "<owner>). Role-assignable groups should have no owners, or only "
        "administrators who already hold the roles the group grants; manage "
        "their membership through PIM for Groups with approval instead. "
        "Review recent membership changes of the group in the audit log."
    ),
    "base_severity": "high",
    "query": """
        WITH tier0 (template_id, role_name) AS (
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
        grp AS (
            SELECT g.entra_object_id AS group_id, g.display_name, g.is_assignable_to_role, g.sensitive_reasons
              FROM entra_group g
             WHERE g.client_id = %(client_id)s
               AND (g.is_assignable_to_role IS TRUE OR 'holds_role' = ANY (g.sensitive_reasons))
        ),
        grp_roles AS (
            SELECT rm.member_id AS group_id,
                   bool_or(t.template_id IS NOT NULL) AS holds_tier0,
                   jsonb_agg(DISTINCT COALESCE(t.role_name, rm.role_display_name, rm.role_template_id::text)
                             || ' (' || rm.assignment_type || ')') AS roles
              FROM entra_directory_role_member rm
              LEFT JOIN tier0 t ON t.template_id = rm.role_template_id
             WHERE rm.client_id = %(client_id)s
               AND rm.member_id IN (SELECT group_id FROM grp)
             GROUP BY rm.member_id
        ),
        priv_owner AS (
            SELECT DISTINCT rm.member_id
              FROM entra_directory_role_member rm
              JOIN tier0 t ON t.template_id = rm.role_template_id
             WHERE rm.client_id = %(client_id)s
        ),
        posture AS (
            SELECT sp.role_eligibility_status
              FROM (SELECT 1) one
              LEFT JOIN entra_security_posture sp ON sp.client_id = %(client_id)s
        ),
        f AS (
            SELECT g.group_id, g.display_name AS group_name, g.is_assignable_to_role, g.sensitive_reasons,
                   o.owner_id, o.owner_type, o.owner_display_name, o.owner_upn, o.owner_user_type,
                   o.owner_on_premises_sync_enabled, o.owner_account_enabled,
                   COALESCE(gr.holds_tier0, FALSE) AS holds_tier0, gr.roles,
                   (CASE WHEN COALESCE(gr.holds_tier0, FALSE) THEN 3 ELSE 2 END
                    - CASE WHEN o.owner_account_enabled IS FALSE THEN 1 ELSE 0 END) AS rank
              FROM grp g
              JOIN entra_group_owner o ON o.client_id = %(client_id)s AND o.group_id = g.group_id
              LEFT JOIN grp_roles gr ON gr.group_id = g.group_id
             WHERE NOT EXISTS (SELECT 1 FROM priv_owner p WHERE p.member_id = o.owner_id)
        )
        SELECT
            CASE WHEN f.rank >= 2 THEN 'fail' ELSE 'warn' END AS status,
            md5('10054:' || %(client_id)s::text || ':' || f.group_id::text || ':' || f.owner_id::text)::uuid
                AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE f.rank WHEN 3 THEN 'high' WHEN 2 THEN 'medium' ELSE 'low' END AS fd_severity,
            COALESCE(f.owner_upn, f.owner_display_name, f.owner_id::text)
                || CASE WHEN f.owner_account_enabled IS FALSE THEN ' (disabled)' ELSE '' END
                || ' owns ' || CASE WHEN f.is_assignable_to_role IS TRUE THEN 'role-assignable ' ELSE 'role-holding ' END
                || 'group ' || COALESCE(f.group_name, f.group_id::text)
                || CASE WHEN f.holds_tier0 THEN ', which holds a highly privileged role,'
                        ELSE '' END
                || ' without holding a highly privileged role itself' AS summary,
            jsonb_build_object(
                'group_id', f.group_id,
                'group_name', f.group_name,
                'is_assignable_to_role', f.is_assignable_to_role,
                'sensitive_reasons', to_jsonb(f.sensitive_reasons),
                'group_roles', f.roles,
                'owner_id', f.owner_id,
                'owner_type', f.owner_type,
                'owner_upn', f.owner_upn,
                'owner_display_name', f.owner_display_name,
                'owner_user_type', f.owner_user_type,
                'owner_on_premises_sync_enabled', f.owner_on_premises_sync_enabled,
                'owner_account_enabled', f.owner_account_enabled,
                'role_eligibility_status', po.role_eligibility_status
            ) AS detail
        FROM f
        CROSS JOIN posture po
    """,
}

"""
Plugin 10052: Too Many Holders of Tier-0 Entra Roles

Counts the distinct USERS holding each highly privileged Entra directory role
other than Global Administrator -- active or PIM-eligible, directly or
through a role-assignable group -- and reports roles held by more users than
a fixed threshold. Plugin 10011 already does this for Global Administrator.

Why it matters: each of these roles can escalate to Global Administrator or
an equivalent level of control. Privileged Role Administrator can assign
itself any role; Privileged Authentication Administrator can reset a Global
Administrator's password and MFA methods; Application / Cloud Application
Administrator can add a credential to a service principal holding a
privileged role or Graph permission; Hybrid Identity Administrator can
change federation and sync; Conditional Access Administrator can switch off
the policies protecting everyone else. Each extra holder is another
credential whose compromise is a tenant takeover (NIST AC-6(5), PCI 7.2.2,
the intent of SCuBA MS.AAD.7.1 / 7.2).

Thresholds (constants):
- Privileged Role Administrator, Privileged Authentication Administrator:
  more than 3 users -> medium 'fail' (these two are direct GA equivalents);
- Security, Hybrid Identity, Application, Cloud Application, Exchange,
  SharePoint, User, Conditional Access, Authentication, Intune
  Administrator: more than 10 users -> low 'warn'.
Service principals and groups are not counted (the group's expanded members
are); service principals holding these roles are reported by plugin 10019.
Disabled accounts are still counted (the assignment exists) and marked in
detail.

Data caveats: when PIM eligibility or role-holding group membership could not
be read (entra_security_posture.role_eligibility_status /
group_expansion_status not 'ok'), the count is a lower bound; the plugin
can still prove "too many" and says so in detail. Tier A data (no
requires_sources). No row for a role with no holders.

object_guid: md5('10052:' || client_id || ':' || role template id).
"""

PLUGIN = {
    "plugin_id": 10052,
    "category": "Hybrid Identity",
    "name": "Too Many Holders of Tier-0 Entra Roles",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "HYBRID-10052",
    "framework_tags": [
        "NIST-800-53-AC-6(5)",
        "NIST-800-53-AC-2(7)",
        "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-7.2.1",
        "PCI-DSS-4.0-7.2.2",
        "CIS-CSC-8-5.4",
        "ISO-27001-2022-A.8.2",
        "SOC2-CC6.3",
        "HIPAA-164.308(a)(4)(ii)(B)",
        "MITRE-ATTCK-T1078.004",
    ],
    "references": [
        {"title": "Microsoft: Best practices for Microsoft Entra roles",
         "url": "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-practices"},
        {"title": "Microsoft: Microsoft Entra built-in roles (privileged roles and permissions)",
         "url": "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/privileged-roles-permissions"},
    ],
    "description": (
        "A highly privileged Entra role other than Global Administrator is "
        "held (active or PIM-eligible, directly or via a group) by more "
        "users than needed: more than 3 for Privileged Role / Privileged "
        "Authentication Administrator (medium), more than 10 for the other "
        "Tier-0 roles (low). Each of these roles can escalate to Global "
        "Administrator, so every extra holder widens the takeover surface. "
        "Global Administrator itself is covered by plugin 10011."
    ),
    "remediation": (
        "Review the holders of each reported role (Entra admin center -> "
        "Roles and administrators -> <role> -> Assignments, both Eligible and "
        "Active) and remove those who do not need it, moving them to "
        "narrower roles (e.g. Helpdesk Administrator instead of "
        "Authentication / Privileged Authentication Administrator, "
        "application owner instead of Application Administrator) or to "
        "administrative-unit-scoped assignments. Make the remaining "
        "assignments PIM-eligible with approval. PowerShell: "
        "Get-MgRoleManagementDirectoryRoleAssignment / "
        "Get-MgRoleManagementDirectoryRoleEligibilitySchedule -Filter "
        "\"roleDefinitionId eq '<template id>'\"."
    ),
    "base_severity": "medium",
    "query": """
        WITH roles (template_id, role_name, max_users) AS (
            VALUES ('e8611ab8-c189-46e8-94e1-60213ab1f814'::uuid, 'Privileged Role Administrator', 3),
                   ('7be44c8a-adaf-4e2a-84d6-ab2649e08a13'::uuid, 'Privileged Authentication Administrator', 3),
                   ('194ae4cb-b126-40b2-bd5b-6091b380977d'::uuid, 'Security Administrator', 10),
                   ('8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2'::uuid, 'Hybrid Identity Administrator', 10),
                   ('9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3'::uuid, 'Application Administrator', 10),
                   ('158c047a-c907-4556-b7ef-446551a6b5f7'::uuid, 'Cloud Application Administrator', 10),
                   ('29232cdf-9323-42fd-ade2-1d097af3e4de'::uuid, 'Exchange Administrator', 10),
                   ('f28a1f50-f6e7-4571-818b-6a12f2af6b6c'::uuid, 'SharePoint Administrator', 10),
                   ('fe930be7-5e62-47db-91af-98c3a49a38b1'::uuid, 'User Administrator', 10),
                   ('b1be1c3e-b65d-4f19-8427-f6fa0d97feb9'::uuid, 'Conditional Access Administrator', 10),
                   ('c4e39bd9-1100-46d3-8c65-fb160da0071f'::uuid, 'Authentication Administrator', 10),
                   ('3a2c62db-5318-420d-8d74-23affee5d9d5'::uuid, 'Intune Administrator', 10)
        ),
        posture AS (
            SELECT sp.role_eligibility_status, sp.group_expansion_status
              FROM (SELECT 1) one
              LEFT JOIN entra_security_posture sp ON sp.client_id = %(client_id)s
        ),
        holder AS (
            SELECT r.template_id, r.role_name, r.max_users, rm.member_id,
                   (COALESCE(min(rm.member_upn), min(rm.member_display_name), rm.member_id::text)
                    || CASE WHEN bool_or(rm.account_enabled IS FALSE) AND NOT bool_or(rm.account_enabled IS TRUE)
                            THEN ' (disabled)' ELSE '' END
                    || ' [' || string_agg(DISTINCT
                           (CASE WHEN rm.assignment_type = 'eligible' THEN 'eligible' ELSE 'active' END
                            || CASE WHEN rm.via_group_id IS NOT NULL
                                    THEN ' via group ' || COALESCE(rm.via_group_display_name, rm.via_group_id::text)
                                    ELSE '' END) COLLATE "C", '; ') || ']') COLLATE "C" AS label
              FROM entra_directory_role_member rm
              JOIN roles r ON r.template_id = rm.role_template_id
             WHERE rm.client_id = %(client_id)s
               AND rm.member_type = '#microsoft.graph.user'
             GROUP BY r.template_id, r.role_name, r.max_users, rm.member_id
        ),
        per_role AS (
            SELECT template_id, role_name, max_users, count(*) AS user_count,
                   jsonb_agg(label ORDER BY label) AS users
              FROM holder
             GROUP BY template_id, role_name, max_users
        )
        SELECT
            CASE WHEN pr.max_users = 3 THEN 'fail' ELSE 'warn' END AS status,
            md5('10052:' || %(client_id)s::text || ':' || pr.template_id::text)::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN pr.max_users = 3 THEN 'medium' ELSE 'low' END AS fd_severity,
            pr.role_name || ' is held by ' || pr.user_count || ' users (more than '
                || pr.max_users || ')' AS summary,
            jsonb_build_object(
                'role', pr.role_name,
                'role_template_id', pr.template_id,
                'user_count', pr.user_count,
                'threshold', pr.max_users,
                'users', pr.users,
                'role_eligibility_status', po.role_eligibility_status,
                'group_expansion_status', po.group_expansion_status,
                'count_is_lower_bound', (po.role_eligibility_status IS DISTINCT FROM 'ok'
                                         OR po.group_expansion_status IS DISTINCT FROM 'ok')
            ) AS detail
        FROM per_role pr
        CROSS JOIN posture po
        WHERE pr.user_count > pr.max_users
    """,
}

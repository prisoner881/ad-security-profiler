"""
Plugin 10012: Permanent Active Assignment to a Highly Privileged Entra Role

Reports users and role-assignable groups holding a highly privileged Entra
ID directory role as a PERMANENT ACTIVE assignment (no end date) instead of
a PIM-eligible (just-in-time) or time-bound one.

Why it matters: CISA SCuBA MS.AAD.7.4 ("Permanent active role assignments
SHALL NOT be allowed for highly privileged roles") and MS.AAD.7.5
(provisioning outside a PAM system). A standing assignment means the role's
full power is available to anyone who steals the account's session or
credential at any moment; with PIM eligibility the role must be activated
(MFA, justification, approval, time limit, alert) first. NIST AC-2(7),
AC-6.

"Highly privileged" is this project's set (defined identically in plugins
10012, 10014, 10018, 10019): Global Administrator, Privileged Role
Administrator, Privileged Authentication Administrator, Security
Administrator, Hybrid Identity Administrator, Application Administrator,
Cloud Application Administrator, Exchange Administrator, SharePoint
Administrator, User Administrator, Conditional Access Administrator,
Authentication Administrator, Intune Administrator. This is a superset of
SCuBA's list.

Severity: high when a permanent assignment is to Global Administrator,
Privileged Role Administrator or Privileged Authentication Administrator,
medium for the other roles; one step lower when every such assignment is
administrative-unit scoped. SCuBA exempts emergency-access (break-glass)
accounts, which need perpetual access: an account whose display name or UPN
contains "break-glass", "breakglass", "break glass" or "emergency" is
reported as a low 'warn' so the exemption is visible and can be confirmed.
Disabled accounts are low 'warn'.

Data: entra_directory_role_member.assignment_kind (schema v38) from
roleAssignmentScheduleInstances: 'permanent' = active with no end date,
'time_bound' = active with an end date, 'activated' = a PIM activation --
the last two are compliant and not reported; eligible rows are not active
assignments. Requires Entra ID P2 / ID Governance: when
entra_security_posture.role_schedule_status is not 'ok' (licence missing,
403, collector older than 0.7.0) nothing can be told apart and the plugin
returns no rows; a NULL assignment_kind on an individual row is likewise
not reported.

Scope: one finding per directly assigned principal (identity = the Entra
object id, member_id, as in plugin 10002), listing every permanent role.
A role-assignable group with a permanent assignment is reported as the
group (that is the assignment to convert to eligible; its expanded members
are listed in detail) -- members holding the role only through the group
are not reported separately. Service principals are excluded: they cannot
activate PIM roles, and plugin 10019 reports any service principal in a
highly privileged role.
"""

PLUGIN = {
    "plugin_id": 10012,
    "category": "Hybrid Identity",
    "name": "Permanent Active Assignment to a Highly Privileged Entra Role",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "HYBRID-10012",
    "framework_tags": [
        "CISA-SCUBA-MS.AAD.7.4",
        "CISA-SCUBA-MS.AAD.7.5",
        "NIST-800-53-AC-2(7)",
        "NIST-800-53-AC-6",
        "NIST-800-53-AC-6(5)",
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
        {"title": "CISA SCuBA Microsoft Entra ID baseline (MS.AAD.7.4, 7.5)",
         "url": "https://github.com/cisagov/ScubaGear/blob/main/PowerShell/ScubaGear/baselines/aad.md"},
        {"title": "Microsoft: What is Microsoft Entra Privileged Identity Management?",
         "url": "https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure"},
        {"title": "Microsoft: Best practices for Microsoft Entra roles",
         "url": "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-practices"},
        {"title": "Microsoft: Manage emergency access accounts in Microsoft Entra ID",
         "url": "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access"},
    ],
    "description": (
        "A user or role-assignable group holds a highly privileged Entra "
        "role (Global, Privileged Role, Privileged Authentication, "
        "Security, Hybrid Identity, Application, Cloud Application, "
        "Exchange, SharePoint, User, Conditional Access, Authentication "
        "or Intune Administrator) as a permanent active assignment "
        "instead of PIM-eligible or time-bound, so the role is usable at "
        "any moment by whoever steals the account (SCuBA MS.AAD.7.4/7.5). "
        "High for Global / Privileged Role / Privileged Authentication "
        "Administrator, medium otherwise; emergency-access (break-glass) "
        "accounts, which SCuBA exempts, and disabled accounts are a low "
        "warning. Needs PIM schedule data (Entra ID P2); silent when it "
        "could not be read."
    ),
    "remediation": (
        "In Entra admin center -> Identity Governance -> Privileged "
        "Identity Management -> Microsoft Entra roles -> Assignments, "
        "convert each permanent active assignment to an Eligible one "
        "(or give it an end date), and require MFA, justification and "
        "approval on activation for the role (Role settings). PowerShell: "
        "New-MgRoleManagementDirectoryRoleEligibilityScheduleRequest "
        "-Action adminAssign ... then remove the active assignment with "
        "New-MgRoleManagementDirectoryRoleAssignmentScheduleRequest "
        "-Action adminRemove. For a role-assignable group, assign the "
        "group as eligible or use PIM for Groups. Keep permanent "
        "assignments only for the documented emergency-access accounts, "
        "and alert on their use."
    ),
    "base_severity": "high",
    "query": """
        WITH hp_role(role_template_id, role_name, top_tier) AS (
            VALUES ('62e90394-69f5-4237-9190-012177145e10'::uuid, 'Global Administrator', true),
                   ('e8611ab8-c189-46e8-94e1-60213ab1f814'::uuid, 'Privileged Role Administrator', true),
                   ('7be44c8a-adaf-4e2a-84d6-ab2649e08a13'::uuid, 'Privileged Authentication Administrator', true),
                   ('194ae4cb-b126-40b2-bd5b-6091b380977d'::uuid, 'Security Administrator', false),
                   ('8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2'::uuid, 'Hybrid Identity Administrator', false),
                   ('9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3'::uuid, 'Application Administrator', false),
                   ('158c047a-c907-4556-b7ef-446551a6b5f7'::uuid, 'Cloud Application Administrator', false),
                   ('29232cdf-9323-42fd-ade2-1d097af3e4de'::uuid, 'Exchange Administrator', false),
                   ('f28a1f50-f6e7-4571-818b-6a12f2af6b6c'::uuid, 'SharePoint Administrator', false),
                   ('fe930be7-5e62-47db-91af-98c3a49a38b1'::uuid, 'User Administrator', false),
                   ('b1be1c3e-b65d-4f19-8427-f6fa0d97feb9'::uuid, 'Conditional Access Administrator', false),
                   ('c4e39bd9-1100-46d3-8c65-fb160da0071f'::uuid, 'Authentication Administrator', false),
                   ('3a2c62db-5318-420d-8d74-23affee5d9d5'::uuid, 'Intune Administrator', false)
        ),
        perm AS (
            SELECT rm.client_id, rm.member_id, rm.member_type, rm.member_display_name, rm.member_upn,
                   rm.account_enabled, r.role_name, r.top_tier, rm.directory_scope_id,
                   (r.role_name || CASE WHEN rm.directory_scope_id <> '/'
                                        THEN ' (scope ' || rm.directory_scope_id || ')' ELSE '' END) COLLATE "C" AS label
              FROM entra_directory_role_member rm
              JOIN hp_role r ON r.role_template_id = rm.role_template_id
              JOIN entra_security_posture sp ON sp.client_id = rm.client_id AND sp.role_schedule_status = 'ok'
             WHERE rm.client_id = %(client_id)s
               AND rm.assignment_type = 'active'
               AND rm.assignment_kind = 'permanent'
               AND rm.via_group_id IS NULL
               AND rm.member_type IN ('#microsoft.graph.user', '#microsoft.graph.group')
        ),
        held AS (
            SELECT p.client_id, p.member_id,
                   min(p.member_type) AS member_type,
                   min(p.member_display_name) AS member_display_name,
                   min(p.member_upn) AS member_upn,
                   bool_or(p.account_enabled IS FALSE) AND NOT bool_or(p.account_enabled IS TRUE) AS disabled,
                   bool_or(p.top_tier AND p.directory_scope_id = '/') AS top_full,
                   bool_or(p.top_tier) OR bool_or(p.directory_scope_id = '/') AS any_full,
                   string_agg(DISTINCT p.label, ', ' ORDER BY p.label) AS roles_summary,
                   jsonb_agg(DISTINCT p.label ORDER BY p.label) AS roles,
                   lower(COALESCE(min(p.member_display_name), '') || ' ' || COALESCE(min(p.member_upn), ''))
                       ~ '(break[-_ .]?glass|emergency)' AS emergency_named
              FROM perm p
             GROUP BY p.client_id, p.member_id
        ),
        graded AS (
            SELECT h.*,
                   CASE WHEN h.emergency_named OR h.disabled THEN 1
                        WHEN h.top_full THEN 3
                        WHEN h.any_full THEN 2
                        ELSE 1 END AS sev_rank
              FROM held h
        )
        SELECT
            CASE WHEN g.sev_rank = 1 THEN 'warn' ELSE 'fail' END AS status,
            g.member_id AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE g.sev_rank WHEN 3 THEN 'high' WHEN 2 THEN 'medium' ELSE 'low' END AS fd_severity,
            CASE WHEN g.member_type = '#microsoft.graph.group' THEN 'Role-assignable group ' ELSE 'User ' END
                || COALESCE(g.member_upn, g.member_display_name, g.member_id::text)
                || ' has a permanent active assignment to ' || g.roles_summary
                || CASE WHEN g.emergency_named THEN ' (named as an emergency-access account)'
                        WHEN g.disabled THEN ' (account disabled)' ELSE '' END AS summary,
            jsonb_build_object(
                'member_id', g.member_id,
                'member_type', g.member_type,
                'member_display_name', g.member_display_name,
                'member_upn', g.member_upn,
                'account_disabled', g.disabled,
                'emergency_access_named', g.emergency_named,
                'permanent_roles', g.roles,
                'group_members', CASE WHEN g.member_type = '#microsoft.graph.group' THEN (
                    SELECT jsonb_agg(DISTINCT COALESCE(x.member_upn, x.member_display_name, x.member_id::text)
                                     ORDER BY COALESCE(x.member_upn, x.member_display_name, x.member_id::text))
                      FROM entra_directory_role_member x
                     WHERE x.client_id = g.client_id AND x.via_group_id = g.member_id) END
            ) AS detail
        FROM graded g
    """,
}

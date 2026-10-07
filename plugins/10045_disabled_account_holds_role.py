"""
Plugin 10045: Disabled Account Still Holds an Entra ID Role

Detects disabled user accounts (entra_directory_role_member.account_enabled
= false) that still hold one or more Entra directory roles -- actively,
as a PIM eligibility, or through a role-assignable group.

Why: re-enabling the account -- a helpdesk mistake, an on-prem change that
syncs up for a hybrid account, or an attacker holding User Administrator /
Helpdesk-type rights -- instantly restores the privilege, with no role
assignment event to alert on (MITRE ATT&CK T1078.004, T1098). Role removal
belongs in the offboarding process; a disabled account should hold no
privilege.

Data: entra_directory_role_member (Tier A: member_type, account_enabled,
role_template_id, assignment_type, via_group_id). Users only; service
principals and groups are covered by other plugins. Rows whose
account_enabled is NULL (unknown) are not reported.

Severity: one row per user (identity = the user's Entra object id)
aggregating every role held: medium when any role is highly privileged
(TIER0 set: Global, Privileged Role, Privileged Authentication, Security,
Hybrid Identity, Application, Cloud Application, Exchange, SharePoint,
User, Conditional Access, Authentication, Intune Administrator), low
otherwise. Status warn.
"""

PLUGIN = {
    "plugin_id": 10045,
    "category": "Hybrid Identity",
    "name": "Disabled Account Still Holds an Entra ID Role",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "HYBRID-10045",
    "framework_tags": [
        "NIST-800-53-AC-2",
        "NIST-800-53-AC-2(3)",
        "NIST-800-53-AC-2(7)",
        "NIST-CSF-2.0-PR.AA-01",
        "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-8.2.6",
        "PCI-DSS-4.0-7.2.1",
        "CIS-CSC-8-5.3",
        "ISO-27001-2022-A.5.18",
        "SOC2-CC6.2",
        "SOC2-CC6.3",
        "HIPAA-164.308(a)(3)(ii)(C)",
        "MITRE-ATTCK-T1078.004",
    ],
    "references": [
        {"title": "Microsoft: Remove Microsoft Entra role assignments",
         "url": "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/manage-roles-portal"},
        {"title": "Microsoft: Best practices for Microsoft Entra roles",
         "url": "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-practices"},
    ],
    "description": (
        "A disabled user account still holds Entra directory roles (active, PIM-eligible "
        "or through a role-assignable group). Re-enabling the account -- by mistake, by "
        "an on-prem change for a synced account, or by an attacker with user-management "
        "rights -- restores the privilege without any role-assignment event. Medium when "
        "a highly privileged role is held, low otherwise; one finding per user listing "
        "all roles."
    ),
    "remediation": (
        "Remove the role assignments, PIM eligibilities and role-assignable group "
        "memberships of each listed account (Entra admin center > Users > <user> > "
        "Assigned roles; Remove-MgRoleManagementDirectoryRoleAssignment, "
        "Remove-MgRoleManagementDirectoryRoleEligibilityScheduleRequest, "
        "Remove-MgGroupMemberByRef), or delete the account if offboarding is complete. "
        "Add role and group removal to the leaver process, and run periodic PIM access "
        "reviews."
    ),
    "base_severity": "medium",
    "query": """
        WITH tier0 (template_id) AS (
            VALUES ('62e90394-69f5-4237-9190-012177145e10'::uuid), ('e8611ab8-c189-46e8-94e1-60213ab1f814'::uuid),
                   ('7be44c8a-adaf-4e2a-84d6-ab2649e08a13'::uuid), ('194ae4cb-b126-40b2-bd5b-6091b380977d'::uuid),
                   ('8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2'::uuid), ('9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3'::uuid),
                   ('158c047a-c907-4556-b7ef-446551a6b5f7'::uuid), ('29232cdf-9323-42fd-ade2-1d097af3e4de'::uuid),
                   ('f28a1f50-f6e7-4571-818b-6a12f2af6b6c'::uuid), ('fe930be7-5e62-47db-91af-98c3a49a38b1'::uuid),
                   ('b1be1c3e-b65d-4f19-8427-f6fa0d97feb9'::uuid), ('c4e39bd9-1100-46d3-8c65-fb160da0071f'::uuid),
                   ('3a2c62db-5318-420d-8d74-23affee5d9d5'::uuid)
        ),
        held AS (
            SELECT rm.member_id,
                   max(rm.member_upn) AS member_upn,
                   max(rm.member_display_name) AS member_display_name,
                   bool_or(t.template_id IS NOT NULL) AS has_tier0,
                   array_agg(DISTINCT COALESCE(rm.role_display_name, rm.role_template_id::text, rm.role_id::text)
                                      || CASE WHEN rm.assignment_type = 'eligible' THEN ' (eligible)' ELSE '' END
                             ORDER BY COALESCE(rm.role_display_name, rm.role_template_id::text, rm.role_id::text)
                                      || CASE WHEN rm.assignment_type = 'eligible' THEN ' (eligible)' ELSE '' END)
                       AS roles,
                   jsonb_agg(DISTINCT jsonb_build_object(
                       'role', rm.role_display_name,
                       'role_template_id', rm.role_template_id,
                       'assignment_type', rm.assignment_type,
                       'via_group', rm.via_group_display_name,
                       'via_group_id', rm.via_group_id,
                       'directory_scope_id', rm.directory_scope_id)) AS assignments
              FROM entra_directory_role_member rm
              LEFT JOIN tier0 t ON t.template_id = rm.role_template_id
             WHERE rm.client_id = %(client_id)s
               AND rm.member_type = '#microsoft.graph.user'
               AND rm.account_enabled IS FALSE
             GROUP BY rm.member_id
        )
        SELECT
            'warn' AS status,
            h.member_id AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN h.has_tier0 THEN 'medium' ELSE 'low' END AS fd_severity,
            'Disabled user "' || COALESCE(h.member_upn, h.member_display_name, h.member_id::text)
                || '" still holds Entra role(s): ' || array_to_string(h.roles, ', ') AS summary,
            jsonb_build_object(
                'user_principal_name', h.member_upn,
                'display_name', h.member_display_name,
                'holds_highly_privileged_role', h.has_tier0,
                'roles', to_jsonb(h.roles),
                'assignments', h.assignments
            ) AS detail
        FROM held h
    """,
}

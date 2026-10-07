"""
Plugin 10081: Users Can Create Security or Microsoft 365 Groups

Two tenant-level checks, each its own finding identity:
- security groups: the tenant authorization policy (entra_security_posture.
  authorization_policy) has defaultUserRolePermissions.
  allowedToCreateSecurityGroups = true (the default) -> low 'warn';
  object_guid md5('10081:' || client_id || ':security_groups');
- Microsoft 365 groups: the Group.Unified directory setting
  (entra_tenant_setting 'group_unified_settings', schema v42) has
  EnableGroupCreation true, or the setting object does not exist (defaults
  in force: every user can create Microsoft 365 groups) -> low 'warn';
  object_guid md5('10081:' || client_id || ':m365_groups'). Evaluated only
  when source directory_settings is 'ok' (a missing row then really means
  "defaults"); EnableGroupCreation false (optionally with
  GroupCreationAllowedGroupId naming the group allowed to create) passes.

Why it matters: groups end up referenced by Conditional Access policies,
app assignments, licence assignments and access packages. Groups any user
can create -- and own, and so manage the membership of -- become ungoverned
access paths and sprawl (NIST CM-7, AC-6). Microsoft and the CIS Microsoft
365 benchmark recommend restricting group creation to administrators or a
designated group.

Data caveats: authorization_policy NULL (read failed, see
authorization_policy_status) -> no security-group row. directory_settings
not 'ok' -> no Microsoft 365 group row. Group.Unified values arrive as
strings ('true' / 'false') and are compared case-insensitively. No
requires_sources: the security-group check is Tier A data.
"""

PLUGIN = {
    "plugin_id": 10081,
    "category": "Hybrid Identity",
    "name": "Users Can Create Security or Microsoft 365 Groups",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "HYBRID-10081",
    "framework_tags": [
        "NIST-800-53-CM-7",
        "NIST-800-53-AC-6",
        "NIST-CSF-2.0-PR.PS-01",
        "NIST-CSF-2.0-PR.AA-05",
        "CIS-CSC-8-4.1",
        "ISO-27001-2022-A.5.15",
        "SOC2-CC6.3",
    ],
    "references": [
        {"title": "Microsoft: Default user permissions in Microsoft Entra ID",
         "url": "https://learn.microsoft.com/en-us/entra/fundamentals/users-default-permissions"},
        {"title": "Microsoft: Manage who can create Microsoft 365 Groups",
         "url": "https://learn.microsoft.com/en-us/microsoft-365/solutions/manage-creation-of-groups"},
        {"title": "Microsoft Graph: authorizationPolicy resource type",
         "url": "https://learn.microsoft.com/en-us/graph/api/resources/authorizationpolicy"},
    ],
    "description": (
        "Non-administrator users can create security groups "
        "(allowedToCreateSecurityGroups = true) and/or Microsoft 365 groups "
        "(Group.Unified EnableGroupCreation true or not configured). "
        "User-created groups become ungoverned access paths once referenced "
        "by Conditional Access, app or licence assignments. Low; one "
        "finding per group type."
    ),
    "remediation": (
        "Security groups: Entra admin center -> Groups -> General -> 'Users "
        "can create security groups in Azure portals, API or PowerShell' = "
        "No (Update-MgPolicyAuthorizationPolicy -DefaultUserRolePermissions "
        "@{AllowedToCreateSecurityGroups=$false}). Microsoft 365 groups: "
        "create or update the Group.Unified directory setting with "
        "EnableGroupCreation = false and GroupCreationAllowedGroupId = the "
        "group allowed to create (New-MgBetaDirectorySetting / "
        "Update-MgBetaDirectorySetting, see 'Manage who can create Microsoft "
        "365 Groups')."
    ),
    "base_severity": "low",
    "query": """
        SELECT
            'warn' AS status,
            md5('10081:' || sp.client_id::text || ':security_groups')::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'low' AS fd_severity,
            'Non-administrator users can create security groups (allowedToCreateSecurityGroups is true)' AS summary,
            jsonb_build_object(
                'group_type', 'security',
                'allowed_to_create_security_groups',
                    sp.authorization_policy->'defaultUserRolePermissions'->'allowedToCreateSecurityGroups'
            ) AS detail
        FROM entra_security_posture sp
        WHERE sp.client_id = %(client_id)s
          AND jsonb_typeof(sp.authorization_policy) = 'object'
          AND sp.authorization_policy->'defaultUserRolePermissions'->'allowedToCreateSecurityGroups' = 'true'::jsonb
        UNION ALL
        SELECT
            'warn',
            md5('10081:' || %(client_id)s::text || ':m365_groups')::uuid,
            NULL, NULL, NULL, NULL,
            'low',
            CASE WHEN ts.content IS NULL
                 THEN 'Non-administrator users can create Microsoft 365 groups (Group.Unified setting not configured; default allows it)'
                 ELSE 'Non-administrator users can create Microsoft 365 groups (Group.Unified EnableGroupCreation is true)'
            END,
            jsonb_build_object(
                'group_type', 'microsoft365',
                'group_unified_setting_present', ts.content IS NOT NULL,
                'enable_group_creation', ts.content->'EnableGroupCreation',
                'group_creation_allowed_group_id', ts.content->'GroupCreationAllowedGroupId'
            )
        FROM (SELECT 1) one
        LEFT JOIN entra_tenant_setting ts
               ON ts.client_id = %(client_id)s AND ts.setting_name = 'group_unified_settings'
        WHERE EXISTS (SELECT 1 FROM entra_collection_status s
                       WHERE s.client_id = %(client_id)s AND s.source = 'directory_settings' AND s.status = 'ok')
          AND (ts.content IS NULL
               OR NOT (ts.content ? 'EnableGroupCreation')
               OR lower(ts.content->>'EnableGroupCreation') = 'true')
    """,
}

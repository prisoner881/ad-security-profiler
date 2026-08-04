"""
Plugin 10007: Application Holds a Highly Privileged Microsoft Graph API Permission

Flags standing, unattended grants of a curated set of Microsoft Graph
APPLICATION permissions -- not delegated permissions a signed-in user
might exercise, but permissions an app can use entirely on its own,
with no human in the loop at all. The specific permissions checked
here (Application.ReadWrite.All, AppRoleAssignment.ReadWrite.All,
RoleManagement.ReadWrite.Directory, Directory.ReadWrite.All,
EntitlementManagement.ReadWrite.All) are not this project's own
judgment call -- each is explicitly called out with "use caution when
granting" language directly in Microsoft's own Graph permissions
reference documentation, falling into one of two categories Microsoft
itself names: permissions that let an app "grant additional privileges
to itself, other applications, or any user" (a documented privilege-
escalation path -- see Tenchi Security's writeup on chaining consent-
policy manipulation through RoleManagement.ReadWrite.Directory to
Global Administrator), or permissions that let an app "act as other
entities, and use the privileges they were granted" (impersonation).

A compromised app registration's client secret, combined with any one
of these permissions, is not "the app's data got accessed" -- it's a
credential that can create new admin accounts, grant itself more
permissions, or take over any other application in the tenant, with no
MFA prompt or human approval anywhere in that chain.
"""

PLUGIN = {
    "plugin_id": 10007,
    "category": "Hybrid Identity",
    "name": "Application Holds a Highly Privileged Microsoft Graph API Permission",
    "version": "1.0",
    "revision_date": "2026-07-19",
    "remediation": (
        "Confirm this application genuinely needs this specific "
        "permission -- these are rarely the correct choice; Microsoft's "
        "own guidance recommends a narrower, resource-specific "
        "permission wherever one exists instead. If the permission "
        "isn't actually needed, remove it: Entra admin center -> App "
        "registrations -> select the application -> API permissions -> "
        "remove the grant. If it genuinely is needed, treat this "
        "application's client secret/certificate with the same care as "
        "a Global Administrator credential -- rotate it on a defined "
        "schedule (see plugin 10005 for expiry tracking), restrict who "
        "can read or regenerate it, and monitor its sign-in activity."
    ),
    "control_id": "HYBRID-007",
    "framework_tags": [],
    "references": [
        {"title": "Microsoft Graph permissions reference",
         "url": "https://learn.microsoft.com/en-us/graph/permissions-reference"},
        {"title": "Tenchi Security: Manipulating roles and permissions in Microsoft 365 via MS Graph",
         "url": "https://www.tenchisecurity.com/en/insights-news/manipulando-funcoes-e-permissoes-em-ambiente-microsoft-365-via-ms-graph"},
    ],
    "description": (
        "A principal holds a standing, unattended (application, not "
        "delegated) grant of one of a curated set of highly privileged "
        "Microsoft Graph permissions -- each explicitly flagged with "
        "'use caution when granting' language directly in Microsoft's "
        "own permissions reference, not this project's own judgment "
        "call. These permissions let an app grant additional privileges "
        "to itself or any user, or act as other entities using their "
        "privileges -- a compromised credential holding any of them is "
        "a documented path to full tenant compromise, not merely data "
        "exposure."
    ),
    "base_severity": "critical",
    "query": """
        SELECT
            'fail' AS status,
            NULL::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'critical' AS fd_severity,
            COALESCE(g.principal_display_name, g.principal_id::text) || ' (' || g.principal_type
                || ') holds the highly privileged Microsoft Graph permission "'
                || g.permission_name || '"' AS summary,
            jsonb_build_object(
                'principal_display_name', g.principal_display_name,
                'principal_type', g.principal_type,
                'permission_name', g.permission_name
            ) AS detail
        FROM entra_dangerous_permission_grant g
        WHERE g.client_id = %(client_id)s
    """,
}

"""
Plugin 10064: Application Holds High-Impact API Permissions (Mail, Files, Sites, Tenant Configuration)

Extends plugin 10007 beyond its 11 Microsoft Graph directory-takeover
permissions to the application permissions (app roles: standing,
unattended access, no signed-in user) that give bulk access to an
organisation's data or change its tenant-wide configuration:
- Office 365 Exchange Online: full_access_as_app, Mail.ReadWrite,
  Mail.Read, Mail.Send, Exchange.ManageAsApp;
- Office 365 SharePoint Online: Sites.FullControl.All,
  Sites.ReadWrite.All, Sites.Read.All;
- Microsoft Graph: Mail.Read, Mail.ReadWrite, Mail.Send, Files.Read.All,
  Files.ReadWrite.All, Sites.Read.All, Sites.ReadWrite.All,
  Sites.FullControl.All, User.ReadWrite.All, Domain.ReadWrite.All,
  Policy.ReadWrite.ConditionalAccess, Organization.ReadWrite.All,
  Chat.Read.All, ChannelMessage.Read.All;
- Azure AD Graph (legacy, 00000002-0000-0000-c000-000000000000):
  Directory.ReadWrite.All, Application.ReadWrite.All.
Read-only directory access (Directory.Read.All) is deliberately not listed;
Azure Key Vault exposes only a delegated scope and is not an app-role risk.
Permissions already in 10007's list are reported there, not here.

Why it matters: Midnight Blizzard used full_access_as_app, granted to an
application it controlled, to read the mailboxes of Microsoft's senior
leadership (CISA ED 24-02). Anyone who obtains such an application's
credential reads every mailbox, file or chat in the tenant -- or, with
Domain/Policy/Organization write, federates a domain or switches off
Conditional Access -- with no user and no MFA in the loop.

Severity: high, status 'fail'; medium 'warn' when the service principal is
disabled. One finding per service principal, every such permission listed.
Excluded: Microsoft first-party service principals (appOwnerOrganizationId
f8cdef31-a31e-4b4a-93e4-5f571e91255a / 72f988bf-86f1-41af-91ab-2d7cd011db47;
only recognised when the service principal was collected) and grants to
users or groups.

Data: entra_app_role_grant (source app_role_grants, required), matched on
(resource appId, permission value); entra_service_principal for owner
tenant, publisher and enabled state (enrichment). Identity = the service
principal's object id. Related: 10065 (third-party apps holding these),
10060 (credentials on the service principal), 10062 (non-admin owners).
"""

# ---------------------------------------------------------------------------
# Shared definitions (copied verbatim into plugins 10060-10069 that need them).
# ---------------------------------------------------------------------------

# Owner tenants of Microsoft first-party applications (appOwnerOrganizationId).
MICROSOFT_OWNER_TENANTS_SQL = (
    "('f8cdef31-a31e-4b4a-93e4-5f571e91255a'::uuid, '72f988bf-86f1-41af-91ab-2d7cd011db47'::uuid)"
)

# Highly privileged directory roles (role template ids, fixed across tenants;
# same set as plugins 10012, 10014, 10018, 10019, 11020).
TIER0_ROLES_SQL = """
        tier0_role(role_template_id, role_name, top_tier) AS (
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
        )"""

# PRIVILEGED_APP_PERMISSIONS: application permissions (app roles) matched on
# (resource appId, permission value). takeover = true for the 11 Microsoft
# Graph permissions of plugin 10007 (entra_graph_collector.py
# DANGEROUS_GRAPH_PERMISSIONS: direct paths to Global Administrator);
# takeover = false for the high-impact data-access / configuration
# permissions of plugin 10064.
PRIVILEGED_APP_PERMISSIONS_SQL = """
        priv_perm(resource_app_id, resource_name, permission_name, takeover) AS (
            VALUES ('00000003-0000-0000-c000-000000000000'::uuid, 'Microsoft Graph', 'Application.ReadWrite.All', true),
                   ('00000003-0000-0000-c000-000000000000'::uuid, 'Microsoft Graph', 'AppRoleAssignment.ReadWrite.All', true),
                   ('00000003-0000-0000-c000-000000000000'::uuid, 'Microsoft Graph', 'RoleManagement.ReadWrite.Directory', true),
                   ('00000003-0000-0000-c000-000000000000'::uuid, 'Microsoft Graph', 'Directory.ReadWrite.All', true),
                   ('00000003-0000-0000-c000-000000000000'::uuid, 'Microsoft Graph', 'EntitlementManagement.ReadWrite.All', true),
                   ('00000003-0000-0000-c000-000000000000'::uuid, 'Microsoft Graph', 'Policy.ReadWrite.PermissionGrant', true),
                   ('00000003-0000-0000-c000-000000000000'::uuid, 'Microsoft Graph', 'UserAuthenticationMethod.ReadWrite.All', true),
                   ('00000003-0000-0000-c000-000000000000'::uuid, 'Microsoft Graph', 'RoleAssignmentSchedule.ReadWrite.Directory', true),
                   ('00000003-0000-0000-c000-000000000000'::uuid, 'Microsoft Graph', 'RoleEligibilitySchedule.ReadWrite.Directory', true),
                   ('00000003-0000-0000-c000-000000000000'::uuid, 'Microsoft Graph', 'Group.ReadWrite.All', true),
                   ('00000003-0000-0000-c000-000000000000'::uuid, 'Microsoft Graph', 'GroupMember.ReadWrite.All', true),
                   ('00000003-0000-0000-c000-000000000000'::uuid, 'Microsoft Graph', 'Mail.Read', false),
                   ('00000003-0000-0000-c000-000000000000'::uuid, 'Microsoft Graph', 'Mail.ReadWrite', false),
                   ('00000003-0000-0000-c000-000000000000'::uuid, 'Microsoft Graph', 'Mail.Send', false),
                   ('00000003-0000-0000-c000-000000000000'::uuid, 'Microsoft Graph', 'Files.Read.All', false),
                   ('00000003-0000-0000-c000-000000000000'::uuid, 'Microsoft Graph', 'Files.ReadWrite.All', false),
                   ('00000003-0000-0000-c000-000000000000'::uuid, 'Microsoft Graph', 'Sites.Read.All', false),
                   ('00000003-0000-0000-c000-000000000000'::uuid, 'Microsoft Graph', 'Sites.ReadWrite.All', false),
                   ('00000003-0000-0000-c000-000000000000'::uuid, 'Microsoft Graph', 'Sites.FullControl.All', false),
                   ('00000003-0000-0000-c000-000000000000'::uuid, 'Microsoft Graph', 'User.ReadWrite.All', false),
                   ('00000003-0000-0000-c000-000000000000'::uuid, 'Microsoft Graph', 'Domain.ReadWrite.All', false),
                   ('00000003-0000-0000-c000-000000000000'::uuid, 'Microsoft Graph', 'Policy.ReadWrite.ConditionalAccess', false),
                   ('00000003-0000-0000-c000-000000000000'::uuid, 'Microsoft Graph', 'Organization.ReadWrite.All', false),
                   ('00000003-0000-0000-c000-000000000000'::uuid, 'Microsoft Graph', 'Chat.Read.All', false),
                   ('00000003-0000-0000-c000-000000000000'::uuid, 'Microsoft Graph', 'ChannelMessage.Read.All', false),
                   ('00000002-0000-0ff1-ce00-000000000000'::uuid, 'Office 365 Exchange Online', 'full_access_as_app', false),
                   ('00000002-0000-0ff1-ce00-000000000000'::uuid, 'Office 365 Exchange Online', 'Mail.ReadWrite', false),
                   ('00000002-0000-0ff1-ce00-000000000000'::uuid, 'Office 365 Exchange Online', 'Mail.Read', false),
                   ('00000002-0000-0ff1-ce00-000000000000'::uuid, 'Office 365 Exchange Online', 'Mail.Send', false),
                   ('00000002-0000-0ff1-ce00-000000000000'::uuid, 'Office 365 Exchange Online', 'Exchange.ManageAsApp', false),
                   ('00000003-0000-0ff1-ce00-000000000000'::uuid, 'Office 365 SharePoint Online', 'Sites.FullControl.All', false),
                   ('00000003-0000-0ff1-ce00-000000000000'::uuid, 'Office 365 SharePoint Online', 'Sites.ReadWrite.All', false),
                   ('00000003-0000-0ff1-ce00-000000000000'::uuid, 'Office 365 SharePoint Online', 'Sites.Read.All', false),
                   ('00000002-0000-0000-c000-000000000000'::uuid, 'Azure AD Graph (legacy)', 'Directory.ReadWrite.All', false),
                   ('00000002-0000-0000-c000-000000000000'::uuid, 'Azure AD Graph (legacy)', 'Application.ReadWrite.All', false)
        )"""

# Privileged service principals: hold a PRIVILEGED_APP_PERMISSIONS grant
# (entra_app_role_grant; the 10007 subset is also read from the older
# entra_dangerous_permission_grant, so the 10007 class is still known when
# source app_role_grants failed) or any TIER0 directory role (active,
# eligible, or via a role-assignable group). One row per service principal:
# takeover = holds a 10007-class permission or a TIER0 role.
PRIVILEGED_SP_SQL = """
        priv_sp_src AS (
            SELECT g.principal_id AS sp_id, p.takeover, false AS has_role,
                   (p.resource_name || ': ' || p.permission_name) COLLATE "C" AS label
              FROM entra_app_role_grant g
              JOIN priv_perm p ON p.resource_app_id = g.resource_app_id
                              AND p.permission_name = g.permission_name
             WHERE g.client_id = %(client_id)s
               AND g.principal_type = 'ServicePrincipal'
            UNION ALL
            SELECT d.principal_id, true, false,
                   ('Microsoft Graph: ' || d.permission_name) COLLATE "C"
              FROM entra_dangerous_permission_grant d
             WHERE d.client_id = %(client_id)s
               AND COALESCE(d.principal_type, 'ServicePrincipal') = 'ServicePrincipal'
            UNION ALL
            SELECT rm.member_id, true, true,
                   ('role ' || t.role_name
                    || CASE WHEN rm.assignment_type = 'eligible' THEN ' (PIM-eligible)' ELSE '' END) COLLATE "C"
              FROM entra_directory_role_member rm
              JOIN tier0_role t ON t.role_template_id = rm.role_template_id
             WHERE rm.client_id = %(client_id)s
               AND rm.member_type = '#microsoft.graph.servicePrincipal'
        ),
        priv_sp AS (
            SELECT s.sp_id,
                   bool_or(s.takeover) AS takeover,
                   bool_or(s.has_role) AS has_role,
                   string_agg(DISTINCT s.label, ', ' ORDER BY s.label) AS privilege_text,
                   jsonb_agg(DISTINCT s.label ORDER BY s.label) AS privileges
              FROM priv_sp_src s
             GROUP BY s.sp_id
        )"""

PLUGIN = {
    "plugin_id": 10064,
    "category": "Hybrid Identity",
    "name": "Application Holds High-Impact API Permissions (Mail, Files, Sites, Tenant Configuration)",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "HYBRID-10064",
    "requires_sources": ["app_role_grants"],
    "framework_tags": [
        "CISA-ED-24-02",
        "NIST-800-53-AC-6",
        "NIST-800-53-AC-6(1)",
        "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-7.2.1",
        "PCI-DSS-4.0-7.2.5",
        "CIS-CSC-8-6.7",
        "ISO-27001-2022-A.5.15",
        "ISO-27001-2022-A.5.23",
        "SOC2-CC6.3",
        "MITRE-ATTCK-T1114.002",
        "MITRE-ATTCK-T1098.003",
    ],
    "references": [
        {"title": "CISA ED 24-02: Mitigating the Significant Risk from Nation-State Compromise of Microsoft Corporate Email System",
         "url": "https://www.cisa.gov/news-events/directives/ed-24-02-mitigating-significant-risk-nation-state-compromise-microsoft-corporate-email-system"},
        {"title": "MSRC: Microsoft Actions Following Attack by Nation State Actor Midnight Blizzard",
         "url": "https://msrc.microsoft.com/blog/2024/01/microsoft-actions-following-attack-by-nation-state-actor-midnight-blizzard/"},
        {"title": "Microsoft Graph permissions reference",
         "url": "https://learn.microsoft.com/en-us/graph/permissions-reference"},
        {"title": "MITRE ATT&CK T1114.002: Remote Email Collection",
         "url": "https://attack.mitre.org/techniques/T1114/002/"},
    ],
    "description": (
        "A service principal holds an application permission that gives "
        "standing, unattended access to every mailbox (Exchange "
        "full_access_as_app, Mail.*), all files and sites (Files.*.All, "
        "Sites.*), Teams chats, or tenant configuration (domains, "
        "Conditional Access policy, organization, legacy AAD Graph "
        "directory write) -- the permission class Midnight Blizzard abused "
        "to read Microsoft executives' mail (CISA ED 24-02). High; medium "
        "when the service principal is disabled. Microsoft first-party "
        "applications are excluded; 10007 covers directory-takeover "
        "permissions."
    ),
    "remediation": (
        "For each application confirm the business need and owner. Remove "
        "permissions that are not needed (Enterprise applications -> the "
        "app -> Permissions -> Revoke, or Remove-MgServicePrincipalAppRoleAssignedTo). "
        "Narrow the rest: Exchange application access policies or RBAC for "
        "Applications to limit mailbox scope, Sites.Selected instead of "
        "tenant-wide SharePoint access, and resource-specific consent for "
        "Teams. Replace legacy Azure AD Graph permissions with Microsoft "
        "Graph equivalents. Protect the application's credentials like an "
        "administrator's (certificates in a key vault, no owners, alerting "
        "on credential changes) and monitor its sign-ins."
    ),
    "base_severity": "high",
    "query": """
        WITH
        @PERMS@,
        held AS (
            SELECT g.principal_id,
                   min(g.principal_display_name) AS principal_display_name,
                   string_agg(DISTINCT (p.resource_name || ': ' || p.permission_name) COLLATE "C", ', '
                              ORDER BY (p.resource_name || ': ' || p.permission_name) COLLATE "C") AS perm_text,
                   jsonb_agg(DISTINCT (p.resource_name || ': ' || p.permission_name) COLLATE "C"
                             ORDER BY (p.resource_name || ': ' || p.permission_name) COLLATE "C") AS permissions
              FROM entra_app_role_grant g
              JOIN priv_perm p ON p.resource_app_id = g.resource_app_id
                              AND p.permission_name = g.permission_name
                              AND NOT p.takeover
             WHERE g.client_id = %(client_id)s
               AND g.principal_type = 'ServicePrincipal'
             GROUP BY g.principal_id
        ),
        classified AS (
            SELECT h.*, sp.app_id, sp.display_name AS sp_display_name, sp.app_owner_organization_id,
                   sp.verified_publisher_name, sp.service_principal_type, sp.account_enabled,
                   sp.account_enabled IS FALSE AS disabled
              FROM held h
              LEFT JOIN entra_service_principal sp
                     ON sp.client_id = %(client_id)s AND sp.entra_object_id = h.principal_id
             WHERE sp.app_owner_organization_id IS NULL
                OR sp.app_owner_organization_id NOT IN @MSTENANTS@
        )
        SELECT
            CASE WHEN c.disabled THEN 'warn' ELSE 'fail' END AS status,
            c.principal_id AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN c.disabled THEN 'medium' ELSE 'high' END AS fd_severity,
            'Service principal "' || COALESCE(c.sp_display_name, c.principal_display_name, c.principal_id::text)
                || '" holds high-impact application permissions: ' || c.perm_text
                || CASE WHEN c.disabled THEN ' (service principal disabled)' ELSE '' END AS summary,
            jsonb_build_object(
                'service_principal_id', c.principal_id,
                'display_name', COALESCE(c.sp_display_name, c.principal_display_name),
                'app_id', c.app_id,
                'service_principal_type', c.service_principal_type,
                'app_owner_organization_id', c.app_owner_organization_id,
                'verified_publisher_name', c.verified_publisher_name,
                'account_enabled', c.account_enabled,
                'permissions', c.permissions
            ) AS detail
        FROM classified c
    """.replace("@PERMS@", PRIVILEGED_APP_PERMISSIONS_SQL.strip())
       .replace("@MSTENANTS@", MICROSOFT_OWNER_TENANTS_SQL),
}

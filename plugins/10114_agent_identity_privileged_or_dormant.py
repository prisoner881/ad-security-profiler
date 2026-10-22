"""
Plugin 10114: Entra Agent Identity Holds Privileged Access or Is Dormant

Reports Microsoft Entra Agent ID agent identities -- service principals
with servicePrincipalType 'ServiceIdentity', created for AI agents -- that:

- hold a highly privileged directory role or a takeover-class
  application permission (same definitions as plugin 10062) -> fail /
  high. An agent acts autonomously, often on untrusted input (prompt
  injection), so standing Tier 0 privilege on one is a direct path to the
  tenant (Maester MT.1200-1225, EntraFalcon AGT-*, Microsoft Zero Trust
  assessment 61006-61014);
- hold only high-impact data permissions (mail, files, sites) -> fail /
  medium;
- have not signed in for 90 days while enabled (when service principal
  sign-in activity was read) -> warn / low: an abandoned agent keeps its
  permissions and credentials.

Permissions an agent inherits from its blueprint are not listed by
Graph on the agent itself and are not seen here. One finding per agent
identity (object_guid md5('10114:' || client_id || ':' || object id)),
every issue listed. Data: entra_service_principal (source
service_principals), entra_app_role_grant, entra_dangerous_permission_grant,
entra_directory_role_member.
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
                   ('db506228-d27e-4b7d-95e5-295956d6615f'::uuid, 'Agent ID Administrator', false),
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
    "plugin_id": 10114,
    "category": "Hybrid Identity",
    "name": "Entra Agent Identity Holds Privileged Access or Is Dormant",
    "version": "1.0",
    "revision_date": "2026-10-22",
    "control_id": "HYBRID-10114",
    "requires_sources": ["service_principals", "app_role_grants"],
    "framework_tags": [
        "NIST-800-53-AC-6",
        "NIST-800-53-AC-6(5)",
        "NIST-800-53-AC-2(3)",
        "NIST-CSF-2.0-PR.AA-05",
        "CIS-CSC-8-5.4",
        "ISO-27001-2022-A.8.2",
        "SOC2-CC6.3",
        "MITRE-ATTCK-T1078.004",
        "MITRE-ATTCK-T1098.003",
    ],
    "references": [
        {"title": "Microsoft: Microsoft Entra Agent ID overview",
         "url": "https://learn.microsoft.com/en-us/entra/agent-id/identity-platform/what-is-agent-id"},
        {"title": "Microsoft Graph (beta): agentIdentity resource type",
         "url": "https://learn.microsoft.com/en-us/graph/api/resources/agentidentity?view=graph-rest-beta"},
        {"title": "MITRE ATT&CK T1098.003: Account Manipulation: Additional Cloud Roles",
         "url": "https://attack.mitre.org/techniques/T1098/003/"},
    ],
    "description": (
        "An AI agent identity (Entra Agent ID) holds a highly privileged directory role or "
        "application permission (high), only high-impact data permissions (medium), or has "
        "not signed in for 90 days while still enabled (low). Agents act autonomously and "
        "on untrusted input, so their privileges should be minimal and current."
    ),
    "remediation": (
        "Entra admin center > Agent ID > Agents (or Enterprise applications filtered on agent "
        "identities): remove directory roles from the agent, replace broad application "
        "permissions with the narrowest delegated or resource-specific ones, and disable or "
        "delete agents that are no longer used. Assign each agent a sponsor and review them "
        "with access reviews."
    ),
    "base_severity": "high",
    "query": """
        WITH
        @TIER0@,
        @PERMS@,
        @PRIVSP@,
        agent AS (
            SELECT sp.*,
                   EXISTS (SELECT 1 FROM entra_collection_status s
                            WHERE s.client_id = sp.client_id AND s.source = 'sp_sign_in_activity'
                              AND s.status = 'ok') AS sign_in_known
              FROM entra_service_principal sp
             WHERE sp.client_id = %(client_id)s
               AND sp.service_principal_type = 'ServiceIdentity'
        ),
        issue AS (
            SELECT a.entra_object_id, CASE WHEN p.takeover THEN 3 ELSE 2 END AS rank,
                   'holds ' || p.privilege_text AS issue
              FROM agent a JOIN priv_sp p ON p.sp_id = a.entra_object_id
            UNION ALL
            SELECT a.entra_object_id, 1,
                   'no sign-in for 90 days or more ('
                   || COALESCE('last ' || to_char(a.last_sign_in_activity_at AT TIME ZONE 'UTC', 'YYYY-MM-DD'), 'never')
                   || ') but still enabled'
              FROM agent a
             WHERE a.sign_in_known AND a.account_enabled IS NOT FALSE
               AND (a.last_sign_in_activity_at IS NULL OR a.last_sign_in_activity_at < a.collected_at - interval '90 days')
        ),
        agg AS (
            SELECT i.entra_object_id, max(i.rank) AS rank,
                   string_agg(i.issue, '; ' ORDER BY i.rank DESC, i.issue) AS issue_text,
                   jsonb_agg(i.issue ORDER BY i.rank DESC, i.issue) AS issues
              FROM issue i GROUP BY i.entra_object_id
        )
        SELECT
            CASE WHEN g.rank >= 2 THEN 'fail' ELSE 'warn' END AS status,
            md5('10114:' || %(client_id)s::text || ':' || g.entra_object_id::text)::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE g.rank WHEN 3 THEN 'high' WHEN 2 THEN 'medium' ELSE 'low' END AS fd_severity,
            'Agent identity ' || COALESCE(a.display_name, a.entra_object_id::text) || ': ' || g.issue_text AS summary,
            jsonb_build_object(
                'agent', a.display_name,
                'object_id', a.entra_object_id,
                'app_id', a.app_id,
                'account_enabled', a.account_enabled,
                'last_sign_in', a.last_sign_in_activity_at,
                'issues', g.issues,
                'privileges', (SELECT p.privileges FROM priv_sp p WHERE p.sp_id = a.entra_object_id)
            ) AS detail
        FROM agg g
        JOIN agent a ON a.entra_object_id = g.entra_object_id
    """.replace("@TIER0@", TIER0_ROLES_SQL.strip())
       .replace("@PERMS@", PRIVILEGED_APP_PERMISSIONS_SQL.strip())
       .replace("@PRIVSP@", PRIVILEGED_SP_SQL.strip()),
}

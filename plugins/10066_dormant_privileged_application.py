"""
Plugin 10066: Dormant Privileged Application

Reports privileged service principals -- holding a PRIVILEGED_APP_PERMISSIONS
application permission (the Graph directory-takeover permissions of plugin
10007 or the high-impact list of plugin 10064) or a highly privileged
(TIER0) directory role -- that have not signed in for 90 days or more, or
have no recorded sign-in at all. One finding per service principal.

Why it matters: the Midnight Blizzard intrusion at Microsoft began with a
legacy, non-production test OAuth application that still held elevated
access nobody was using or watching (CISA ED 24-02). An unused privileged
application is pure risk: its permissions serve no one, its credentials are
rarely rotated or monitored, and any sign-in by it is by definition
anomalous yet unlikely to be noticed. Remove its permissions or delete it
(NIST AC-2(3), CM-7).

Severity (status 'fail'): high when the service principal holds a TIER0
directory role or a 10007-class (directory-takeover) permission; medium when
it holds only 10064-class (data access / configuration) permissions. One
step lower and 'warn' when the service principal is disabled.

Excluded: Microsoft first-party service principals (appOwnerOrganizationId
f8cdef31-a31e-4b4a-93e4-5f571e91255a / 72f988bf-86f1-41af-91ab-2d7cd011db47).

Data: entra_service_principal.last_sign_in_activity_at
(servicePrincipalSignInActivities lastSignInActivity, beta, AuditLog.Read.All
and Entra ID P1; sources sp_sign_in_activity and service_principals both
required). NULL means no activity was recorded for this application: it has
not signed in since Microsoft began recording, or never. The 90-day test is
judged against the snapshot's collected_at; the summary states only the
threshold, exact dates are in detail. Privilege comes from
entra_app_role_grant, entra_dangerous_permission_grant and
entra_directory_role_member; when source app_role_grants was not read only
roles and the 10007 class are known. Identity = the service principal's
object id.
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
    "plugin_id": 10066,
    "category": "Hybrid Identity",
    "name": "Dormant Privileged Application",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "HYBRID-10066",
    "requires_sources": ["sp_sign_in_activity", "service_principals"],
    "framework_tags": [
        "CISA-ED-24-02",
        "NIST-800-53-AC-2",
        "NIST-800-53-AC-2(3)",
        "NIST-800-53-CM-7",
        "NIST-CSF-2.0-PR.AA-01",
        "PCI-DSS-4.0-8.2.6",
        "CIS-CSC-8-5.3",
        "ISO-27001-2022-A.5.18",
        "SOC2-CC6.2",
        "MITRE-ATTCK-T1078.004",
    ],
    "references": [
        {"title": "CISA ED 24-02: Mitigating the Significant Risk from Nation-State Compromise of Microsoft Corporate Email System",
         "url": "https://www.cisa.gov/news-events/directives/ed-24-02-mitigating-significant-risk-nation-state-compromise-microsoft-corporate-email-system"},
        {"title": "MSRC: Microsoft Actions Following Attack by Nation State Actor Midnight Blizzard",
         "url": "https://msrc.microsoft.com/blog/2024/01/microsoft-actions-following-attack-by-nation-state-actor-midnight-blizzard/"},
        {"title": "Microsoft Graph: servicePrincipalSignInActivity resource type",
         "url": "https://learn.microsoft.com/en-us/graph/api/resources/serviceprincipalsigninactivity"},
        {"title": "Microsoft: Govern and remove unused applications",
         "url": "https://learn.microsoft.com/en-us/entra/identity/monitoring-health/recommendation-remove-unused-apps"},
    ],
    "description": (
        "A service principal holding a privileged application permission "
        "or highly privileged directory role has not signed in for 90 "
        "days or more (or has no recorded sign-in). Unused privileged "
        "applications -- like the legacy test app that gave Midnight "
        "Blizzard its foothold at Microsoft -- carry risk with no benefit. "
        "High for directory-takeover permissions or roles, medium for "
        "data-access permissions; lower when disabled. Microsoft "
        "first-party applications are excluded."
    ),
    "remediation": (
        "Confirm with the application's owner whether it is still needed. "
        "If not, remove its permissions and role assignments and delete "
        "(or at least disable) the service principal and app "
        "registration. If it is needed only occasionally, remove standing "
        "privileges it does not use, rotate its credentials, and alert on "
        "its sign-ins. Make periodic review of application permissions "
        "and usage part of access reviews (Entra recommendations 'Remove "
        "unused applications' / 'Remove unused credentials')."
    ),
    "base_severity": "high",
    "query": """
        WITH
        @TIER0@,
        @PERMS@,
        @PRIVSP@,
        dormant AS (
            SELECT sp.entra_object_id, sp.display_name, sp.app_id, sp.service_principal_type,
                   sp.app_owner_organization_id, sp.account_enabled, sp.last_sign_in_activity_at,
                   sp.account_enabled IS FALSE AS disabled,
                   CASE WHEN sp.last_sign_in_activity_at IS NOT NULL
                        THEN extract(day FROM sp.collected_at - sp.last_sign_in_activity_at)::int END
                       AS days_since_sign_in,
                   p.takeover, p.privilege_text, p.privileges
              FROM entra_service_principal sp
              JOIN priv_sp p ON p.sp_id = sp.entra_object_id
             WHERE sp.client_id = %(client_id)s
               -- last_sign_in_activity_at is NULL for every SP when the
               -- sign-in activity read failed: no data is not "dormant".
               AND EXISTS (SELECT 1 FROM entra_collection_status cs
                            WHERE cs.client_id = %(client_id)s
                              AND cs.source = 'sp_sign_in_activity' AND cs.status = 'ok')
               AND (sp.app_owner_organization_id IS NULL
                    OR sp.app_owner_organization_id NOT IN @MSTENANTS@)
               AND (sp.last_sign_in_activity_at IS NULL
                    OR sp.last_sign_in_activity_at < sp.collected_at - interval '90 days')
        ),
        graded AS (
            SELECT d.*,
                   greatest(1, CASE WHEN d.takeover THEN 3 ELSE 2 END
                               - CASE WHEN d.disabled THEN 1 ELSE 0 END) AS sev_rank
              FROM dormant d
        )
        SELECT
            CASE WHEN g.disabled THEN 'warn' ELSE 'fail' END AS status,
            g.entra_object_id AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE g.sev_rank WHEN 3 THEN 'high' WHEN 2 THEN 'medium' ELSE 'low' END AS fd_severity,
            'Privileged service principal "' || COALESCE(g.display_name, g.app_id::text, g.entra_object_id::text)
                || '" ('
                || g.privilege_text || ') '
                || CASE WHEN g.last_sign_in_activity_at IS NULL THEN 'has no recorded sign-in activity'
                        ELSE 'has not signed in for 90 days or more' END
                || CASE WHEN g.disabled THEN ' (service principal disabled)' ELSE '' END AS summary,
            jsonb_build_object(
                'service_principal_id', g.entra_object_id,
                'display_name', g.display_name,
                'app_id', g.app_id,
                'service_principal_type', g.service_principal_type,
                'app_owner_organization_id', g.app_owner_organization_id,
                'account_enabled', g.account_enabled,
                'last_sign_in_activity_at', g.last_sign_in_activity_at,
                'days_since_sign_in', g.days_since_sign_in,
                'dormancy_threshold_days', 90,
                'privileges', g.privileges
            ) AS detail
        FROM graded g
    """.replace("@TIER0@", TIER0_ROLES_SQL.strip())
       .replace("@PERMS@", PRIVILEGED_APP_PERMISSIONS_SQL.strip())
       .replace("@PRIVSP@", PRIVILEGED_SP_SQL.strip())
       .replace("@MSTENANTS@", MICROSOFT_OWNER_TENANTS_SQL),
}

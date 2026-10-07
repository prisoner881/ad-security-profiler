"""
Plugin 10065: Third-Party Multi-Tenant Application Holds Privileged Permissions

Reports service principals of third-party multi-tenant applications --
applications registered in another organisation's tenant (owner tenant
neither Microsoft nor this tenant) -- that hold a PRIVILEGED_APP_PERMISSIONS
application permission (the 11 directory-takeover Graph permissions of
plugin 10007 or the high-impact mail / files / sites / configuration list of
plugin 10064) or a highly privileged (TIER0) directory role. One finding per
service principal.

Why it matters: the credentials of a multi-tenant application live in the
VENDOR's tenant. Whoever compromises the vendor (or its build pipeline or
key vault) can sign in as the application in every customer tenant and use
the permissions granted there -- a supply-chain path into this tenant that
none of this tenant's controls (MFA, Conditional Access for users, PIM)
covers (MITRE T1199 Trusted Relationship; the Midnight Blizzard and
SolarWinds campaigns abused exactly such application trust, CISA ED 24-02,
AA21-008A). A publisher that is not Microsoft-verified gives no assurance of
who operates the application.

Severity (status 'fail'): high; critical when the application has no
verified publisher (verifiedPublisher.displayName empty). One step lower and
'warn' when the service principal is disabled.

Third-party test: app_owner_organization_id is set, is not a Microsoft
tenant (f8cdef31-a31e-4b4a-93e4-5f571e91255a, 72f988bf-86f1-41af-91ab-2d7cd011db47)
and differs from this tenant's id (entra_tenant_setting 'organization'
content id; when that was not collected, the owner tenant of the service
principals of this tenant's own app registrations). When neither is known,
an application whose appId matches one of this tenant's app registrations
counts as its own.
Managed identities are not third-party.

Data: entra_service_principal (source service_principals) and
entra_app_role_grant (source app_role_grants), both required; TIER0 roles
from entra_directory_role_member. Identity = the service principal's object
id.
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
    "plugin_id": 10065,
    "category": "Hybrid Identity",
    "name": "Third-Party Multi-Tenant Application Holds Privileged Permissions",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "HYBRID-10065",
    "requires_sources": ["service_principals", "app_role_grants"],
    "framework_tags": [
        "CISA-ED-24-02",
        "NIST-800-53-AC-6",
        "NIST-800-53-AC-20",
        "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-7.2.1",
        "CIS-CSC-8-6.7",
        "ISO-27001-2022-A.5.19",
        "ISO-27001-2022-A.5.23",
        "SOC2-CC6.3",
        "MITRE-ATTCK-T1199",
        "MITRE-ATTCK-T1528",
    ],
    "references": [
        {"title": "CISA ED 24-02: Mitigating the Significant Risk from Nation-State Compromise of Microsoft Corporate Email System",
         "url": "https://www.cisa.gov/news-events/directives/ed-24-02-mitigating-significant-risk-nation-state-compromise-microsoft-corporate-email-system"},
        {"title": "Microsoft: Publisher verification",
         "url": "https://learn.microsoft.com/en-us/entra/identity-platform/publisher-verification-overview"},
        {"title": "Microsoft: Application and service principal objects in Microsoft Entra ID",
         "url": "https://learn.microsoft.com/en-us/entra/identity-platform/app-objects-and-service-principals"},
        {"title": "MITRE ATT&CK T1199: Trusted Relationship",
         "url": "https://attack.mitre.org/techniques/T1199/"},
    ],
    "description": (
        "A third-party multi-tenant application (registered in another "
        "organisation's tenant) holds a privileged application permission "
        "(directory takeover, or bulk mail / files / sites / tenant "
        "configuration access) or a highly privileged directory role in "
        "this tenant. Its credentials live with the vendor, so a vendor "
        "compromise hands those permissions to the attacker. High; "
        "critical without a verified publisher; lower when the service "
        "principal is disabled."
    ),
    "remediation": (
        "Confirm the vendor, the contract and the business need for each "
        "permission. Remove permissions the integration does not need and "
        "ask the vendor for least-privilege alternatives (Sites.Selected, "
        "Exchange RBAC for Applications, scoped roles). Prefer vendors "
        "with publisher verification. Disable or delete the service "
        "principal of applications no longer in use "
        "(Update-MgServicePrincipal -AccountEnabled:$false). Restrict who "
        "can grant admin consent, and monitor the application's sign-ins "
        "(Workload Identities Premium adds Conditional Access and risk "
        "detection for service principals)."
    ),
    "base_severity": "high",
    "query": """
        WITH
        @TIER0@,
        @PERMS@,
        @PRIVSP@,
        tenant AS (
            -- this tenant's id: /organization id, else the owner tenant of the
            -- service principals of this tenant's own app registrations
            SELECT COALESCE(
                       (SELECT CASE WHEN ts.content->>'id' ~* '^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$'
                                    THEN (ts.content->>'id')::uuid END
                          FROM entra_tenant_setting ts
                         WHERE ts.client_id = %(client_id)s
                           AND ts.setting_name = 'organization'),
                       (SELECT s.app_owner_organization_id
                          FROM entra_service_principal s
                          JOIN entra_application a ON a.client_id = s.client_id AND a.app_id = s.app_id
                         WHERE s.client_id = %(client_id)s
                           AND s.app_owner_organization_id IS NOT NULL
                           AND s.app_owner_organization_id NOT IN @MSTENANTS@
                         GROUP BY s.app_owner_organization_id
                         ORDER BY count(*) DESC, s.app_owner_organization_id
                         LIMIT 1)) AS tenant_id
        ),
        third_party AS (
            SELECT sp.*
              FROM entra_service_principal sp
             WHERE sp.client_id = %(client_id)s
               AND sp.service_principal_type IS DISTINCT FROM 'ManagedIdentity'
               AND sp.app_owner_organization_id IS NOT NULL
               AND sp.app_owner_organization_id NOT IN @MSTENANTS@
               AND CASE WHEN (SELECT t.tenant_id FROM tenant t) IS NOT NULL
                        THEN sp.app_owner_organization_id <> (SELECT t.tenant_id FROM tenant t)
                        ELSE NOT EXISTS (SELECT 1 FROM entra_application a
                                          WHERE a.client_id = %(client_id)s AND a.app_id = sp.app_id) END
        ),
        graded AS (
            SELECT tp.entra_object_id, tp.display_name, tp.app_id, tp.app_owner_organization_id,
                   tp.publisher_name, tp.verified_publisher_name, tp.sign_in_audience, tp.account_enabled,
                   tp.account_enabled IS FALSE AS disabled,
                   NULLIF(btrim(tp.verified_publisher_name), '') IS NULL AS unverified,
                   p.privilege_text, p.privileges,
                   (CASE WHEN NULLIF(btrim(tp.verified_publisher_name), '') IS NULL THEN 4 ELSE 3 END)
                   - CASE WHEN tp.account_enabled IS FALSE THEN 1 ELSE 0 END AS sev_rank
              FROM third_party tp
              JOIN priv_sp p ON p.sp_id = tp.entra_object_id
        )
        SELECT
            CASE WHEN g.disabled THEN 'warn' ELSE 'fail' END AS status,
            g.entra_object_id AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE g.sev_rank WHEN 4 THEN 'critical' WHEN 3 THEN 'high' ELSE 'medium' END AS fd_severity,
            'Third-party application "' || COALESCE(g.display_name, g.app_id::text, g.entra_object_id::text) || '"'
                || CASE WHEN g.unverified THEN ' (no verified publisher)'
                        ELSE ' (verified publisher ' || g.verified_publisher_name || ')' END
                || ' holds ' || g.privilege_text
                || CASE WHEN g.disabled THEN ' (service principal disabled)' ELSE '' END AS summary,
            jsonb_build_object(
                'service_principal_id', g.entra_object_id,
                'display_name', g.display_name,
                'app_id', g.app_id,
                'app_owner_organization_id', g.app_owner_organization_id,
                'publisher_name', g.publisher_name,
                'verified_publisher_name', g.verified_publisher_name,
                'sign_in_audience', g.sign_in_audience,
                'account_enabled', g.account_enabled,
                'privileges', g.privileges,
                'tenant_id_known', (SELECT t.tenant_id FROM tenant t) IS NOT NULL
            ) AS detail
        FROM graded g
    """.replace("@TIER0@", TIER0_ROLES_SQL.strip())
       .replace("@PERMS@", PRIVILEGED_APP_PERMISSIONS_SQL.strip())
       .replace("@PRIVSP@", PRIVILEGED_SP_SQL.strip())
       .replace("@MSTENANTS@", MICROSOFT_OWNER_TENANTS_SQL),
}

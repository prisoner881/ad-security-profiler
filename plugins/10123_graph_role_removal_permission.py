"""
Plugin 10123: Application Holds a Microsoft Graph Role-Removal Permission (CVE-2026-114162)

CVE-2026-114162 (Microsoft Graph elevation of privilege, CVSS 9.1, November
2026, customer action required): "An attacker who controls an application
with the affected role-removal permission could send a specially crafted
request ... to assign privileged directory roles", up to Global
Administrator. The role-removal permissions are the PIM schedule-request
permissions that only remove assignments:
  * RoleAssignmentSchedule.Remove.Directory
  * RoleEligibilitySchedule.Remove.Directory
They were regarded as low risk (they only take roles away), so they were
not in the directory-takeover list of plugins 10007 / 10058-10069 /
10078, which hold the matching ReadWrite permissions.

Evidence:
  * application permissions (app roles) on Microsoft Graph
    (resource appId 00000003-0000-0000-c000-000000000000) granted to a
    service principal (entra_app_role_grant, source app_role_grants);
  * delegated grants of the same scopes on Microsoft Graph
    (entra_delegated_grant.scopes, source delegated_grants): the app acts
    as a signed-in user, so the user's own roles also come into it.

One finding per service principal:
  * critical 'fail': an enabled service principal holds either permission
    as an application permission (standing, no user, no MFA);
  * high 'warn': the service principal is disabled, or it holds the
    permission only as a delegated grant.
Excluded: Microsoft first-party service principals (appOwnerOrganizationId
f8cdef31-a31e-4b4a-93e4-5f571e91255a / 72f988bf-86f1-41af-91ab-2d7cd011db47;
only recognised when the service principal was collected) -- they are not
under the tenant's control.

Data: entra_app_role_grant (required), entra_delegated_grant (when
collected), entra_service_principal (owner tenant, publisher, enabled
state), entra_collection_status. Identity = the service principal's object
id. Related: 10007, 10064, 10065 (other privileged permissions), 10060
(credentials on the service principal), 10062 (non-admin owners).
"""

PLUGIN = {
    "plugin_id": 10123,
    "category": "Hybrid Identity",
    "name": "Application Holds a Microsoft Graph Role-Removal Permission (CVE-2026-114162)",
    "version": "1.0",
    "revision_date": "2026-11-20",
    "control_id": "HYBRID-10123",
    "requires_sources": ["app_role_grants"],
    "framework_tags": [
        "NIST-800-53-SI-2",
        "NIST-800-53-RA-5",
        "NIST-800-53-AC-6",
        "NIST-800-53-AC-6(1)",
        "NIST-CSF-2.0-ID.RA-01",
        "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-6.3.3",
        "PCI-DSS-4.0-7.2.1",
        "CIS-CSC-8-6.7",
        "CIS-CSC-8-7.3",
        "ISO-27001-2022-A.8.8",
        "ISO-27001-2022-A.5.15",
        "SOC2-CC6.3",
        "SOC2-CC7.1",
        "MITRE-ATTCK-T1098.003",
        "CVE-2026-114162",
    ],
    "references": [
        {"title": "Microsoft Security Update Guide: CVE-2026-114162 (Microsoft Graph Elevation of Privilege)",
         "url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-114162"},
        {"title": "Microsoft Graph permissions reference",
         "url": "https://learn.microsoft.com/en-us/graph/permissions-reference"},
        {"title": "Microsoft Graph: Create roleAssignmentScheduleRequests (permissions)",
         "url": "https://learn.microsoft.com/en-us/graph/api/rbacapplication-post-roleassignmentschedulerequests"},
        {"title": "MITRE ATT&CK T1098.003: Additional Cloud Roles",
         "url": "https://attack.mitre.org/techniques/T1098/003/"},
    ],
    "description": (
        "A service principal holds a Microsoft Graph role-removal permission "
        "(RoleAssignmentSchedule.Remove.Directory or RoleEligibilitySchedule.Remove.Directory). "
        "CVE-2026-114162 (November 2026, CVSS 9.1) lets an application with such a permission "
        "assign privileged directory roles, up to Global Administrator. Critical for an enabled "
        "service principal holding it as an application permission; high when the service "
        "principal is disabled or holds it only as a delegated grant. Microsoft first-party "
        "applications are excluded."
    ),
    "remediation": (
        "Remove the permission from every application that does not strictly need it (Enterprise "
        "applications -> the app -> Permissions -> Revoke, or Remove-MgServicePrincipalAppRoleAssignedTo "
        "for an application permission and Remove-MgOauth2PermissionGrant / Update-MgOauth2PermissionGrant "
        "for a delegated grant). Where it is needed, confirm with Microsoft that the tenant has the "
        "CVE-2026-114162 fix, protect the application's credentials like a Global Administrator's "
        "(certificates in a key vault, no owners, alerting on credential changes), and review the "
        "directory audit log for role assignments made by the application since it was granted the "
        "permission (activity 'Add member to role' / 'Add eligible member to role' initiated by the "
        "application)."
    ),
    "base_severity": "critical",
    "query": """
        WITH
        remove_perm(permission_name) AS (
            VALUES ('RoleAssignmentSchedule.Remove.Directory'),
                   ('RoleEligibilitySchedule.Remove.Directory')
        ),
        src AS (
            SELECT g.principal_id AS sp_id, g.principal_display_name AS label_name,
                   g.permission_name, 'application'::text AS grant_kind,
                   NULL::text AS consent_type, NULL::text AS principal_upn
              FROM entra_app_role_grant g
              JOIN remove_perm p ON p.permission_name = g.permission_name
             WHERE g.client_id = %(client_id)s
               AND g.principal_type = 'ServicePrincipal'
               AND g.resource_app_id = '00000003-0000-0000-c000-000000000000'::uuid
            UNION ALL
            SELECT d.client_sp_id, d.client_display_name, s.scope, 'delegated',
                   d.consent_type, d.principal_upn
              FROM entra_delegated_grant d
              CROSS JOIN LATERAL unnest(d.scopes) AS s(scope)
              JOIN remove_perm p ON lower(p.permission_name) = lower(s.scope)
             WHERE d.client_id = %(client_id)s
               AND d.resource_app_id = '00000003-0000-0000-c000-000000000000'::uuid
        ),
        held AS (
            SELECT s.sp_id,
                   min(s.label_name) AS label_name,
                   bool_or(s.grant_kind = 'application') AS has_application,
                   bool_or(s.grant_kind = 'delegated') AS has_delegated,
                   jsonb_agg(DISTINCT s.permission_name) FILTER (WHERE s.grant_kind = 'application')
                       AS application_permissions,
                   jsonb_agg(DISTINCT jsonb_build_object(
                                 'scope', s.permission_name,
                                 'consent_type', s.consent_type,
                                 'user', s.principal_upn))
                       FILTER (WHERE s.grant_kind = 'delegated') AS delegated_grants,
                   string_agg(DISTINCT s.permission_name || ' (' || s.grant_kind || ')', ', ')
                       AS perm_text
              FROM src s
             GROUP BY s.sp_id
        ),
        classified AS (
            SELECT h.*, sp.app_id, sp.display_name AS sp_display_name, sp.app_owner_organization_id,
                   sp.verified_publisher_name, sp.publisher_name, sp.service_principal_type,
                   sp.account_enabled,
                   sp.account_enabled IS FALSE AS disabled
              FROM held h
              LEFT JOIN entra_service_principal sp
                     ON sp.client_id = %(client_id)s AND sp.entra_object_id = h.sp_id
             WHERE sp.app_owner_organization_id IS NULL
                OR sp.app_owner_organization_id NOT IN
                   ('f8cdef31-a31e-4b4a-93e4-5f571e91255a'::uuid, '72f988bf-86f1-41af-91ab-2d7cd011db47'::uuid)
        )
        SELECT
            CASE WHEN c.has_application AND NOT c.disabled THEN 'fail' ELSE 'warn' END AS status,
            c.sp_id AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN c.has_application AND NOT c.disabled THEN 'critical' ELSE 'high' END AS fd_severity,
            'Service principal "' || COALESCE(c.sp_display_name, c.label_name, c.sp_id::text)
                || '" holds a Microsoft Graph role-removal permission exposed to CVE-2026-114162 '
                || '(assignment of privileged roles, up to Global Administrator): ' || c.perm_text
                || CASE WHEN c.disabled THEN ' (service principal disabled)' ELSE '' END AS summary,
            jsonb_build_object(
                'service_principal_id', c.sp_id,
                'display_name', COALESCE(c.sp_display_name, c.label_name),
                'app_id', c.app_id,
                'service_principal_type', c.service_principal_type,
                'app_owner_organization_id', c.app_owner_organization_id,
                'publisher_name', c.publisher_name,
                'verified_publisher_name', c.verified_publisher_name,
                'account_enabled', c.account_enabled,
                'application_permissions', COALESCE(c.application_permissions, '[]'::jsonb),
                'delegated_grants', COALESCE(c.delegated_grants, '[]'::jsonb),
                'delegated_grants_collected', EXISTS (
                    SELECT 1 FROM entra_collection_status cs
                     WHERE cs.client_id = %(client_id)s AND cs.source = 'delegated_grants'
                       AND cs.status = 'ok'),
                'cve', 'CVE-2026-114162'
            ) AS detail
        FROM classified c
    """,
}

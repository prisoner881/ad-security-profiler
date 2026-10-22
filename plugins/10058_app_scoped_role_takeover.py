"""
Plugin 10058: App-Scoped Role Lets a Non-Privileged Principal Take Over a Privileged Application

Reports directory role assignments scoped to a single application
registration or service principal (directoryScopeId '/<object id>') that
let the assignee add credentials to it -- the built-in Application
Administrator or Cloud Application Administrator, or a custom role whose
actions include applications/servicePrincipals credentials or owners
update -- when that application is privileged (its service principal holds
a highly privileged directory role or a privileged application permission;
same definitions as plugin 10062) and the assignee does not already hold a
highly privileged role tenant-wide.

Why: an app-scoped role looks harmless in a role review ("Application
Administrator -- one app"), but adding a secret to that one app and signing
in as it grants everything the app holds. If the app holds
RoleManagement.ReadWrite.Directory or Global Administrator, the assignee is
one step from Global Administrator. Purple Knight rates "custom role
assigned to unprivileged principals in an app's scope" critical;
EntraFalcon CAP-011.

Severity (fail): critical when the target holds a takeover-class
permission or a highly privileged role, high when it holds only
high-impact data permissions. Assignees that are service principals or
groups are reported like users. One finding per (assignee, scope, role):
object_guid md5('10058:' || client_id || ':' || principal || ':' || scope
|| ':' || role). Data: entra_custom_role_assignment (source
custom_role_assignments; built-in app-scoped active assignments from
entra_graph_collector 0.9.0) and PIM-eligible scoped assignments in
entra_directory_role_member, plus the sources plugin 10062 uses.
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
    "plugin_id": 10058,
    "category": "Hybrid Identity",
    "name": "App-Scoped Role Lets a Non-Privileged Principal Take Over a Privileged Application",
    "version": "1.0",
    "revision_date": "2026-10-22",
    "control_id": "HYBRID-10058",
    "requires_sources": ["custom_role_assignments", "app_role_grants", "service_principals"],
    "framework_tags": [
        "NIST-800-53-AC-6",
        "NIST-800-53-AC-6(5)",
        "NIST-800-53-AC-2(7)",
        "NIST-CSF-2.0-PR.AA-05",
        "CIS-CSC-8-5.4",
        "ISO-27001-2022-A.8.2",
        "SOC2-CC6.3",
        "MITRE-ATTCK-T1098.001",
        "MITRE-ATTCK-T1078.004",
    ],
    "references": [
        {"title": "Microsoft: Assign Microsoft Entra roles at different scopes (application registration scope)",
         "url": "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/assign-roles-different-scopes"},
        {"title": "Microsoft: Application management custom role permissions",
         "url": "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/custom-available-permissions"},
        {"title": "MITRE ATT&CK T1098.001: Account Manipulation: Additional Cloud Credentials",
         "url": "https://attack.mitre.org/techniques/T1098/001/"},
    ],
    "description": (
        "A role assigned with the scope of a single application lets a principal that holds "
        "no highly privileged role add credentials to that application -- and the "
        "application is privileged (a Tier 0 directory role or a privileged application "
        "permission). Adding a secret and signing in as the app gives the assignee those "
        "privileges: critical when they lead to Global Administrator, high otherwise."
    ),
    "remediation": (
        "Entra admin center > App registrations (or Enterprise applications) > the "
        "application > Roles and administrators: remove the scoped assignment, or give it "
        "only to principals already trusted at the application's privilege level. Better, "
        "reduce what the application holds (least-privilege permissions, no directory "
        "role), enable app instance property lock, and review its credentials for any "
        "added by the assignee (Entra audit log 'Update application -- Certificates and "
        "secrets management')."
    ),
    "base_severity": "critical",
    "query": """
        WITH
        @TIER0@,
        @PERMS@,
        @PRIVSP@,
        tier0_holder AS (
            SELECT DISTINCT rm.member_id
              FROM entra_directory_role_member rm
              JOIN tier0_role t ON t.role_template_id = rm.role_template_id
             WHERE rm.client_id = %(client_id)s
               AND rm.directory_scope_id = '/'
        ),
        cred_role AS (
            SELECT v.role_definition_id, v.display_name
              FROM (VALUES ('9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3'::uuid, 'Application Administrator'),
                           ('158c047a-c907-4556-b7ef-446551a6b5f7'::uuid, 'Cloud Application Administrator'))
                   v(role_definition_id, display_name)
            UNION
            SELECT rd.role_definition_id, rd.display_name
              FROM entra_role_definition rd
             WHERE rd.client_id = %(client_id)s
               AND rd.is_built_in IS FALSE
               AND EXISTS (SELECT 1 FROM unnest(rd.allowed_actions) a
                            WHERE lower(a) ~ '^microsoft[.]directory/(applications|serviceprincipals)/(credentials|owners|allproperties|[*])/(update|alltasks|[*])$'
                               OR lower(a) ~ '^microsoft[.]directory/(applications|serviceprincipals)/[*]$')
        ),
        scoped AS (
            SELECT a.principal_id, a.principal_type, COALESCE(a.principal_upn, a.principal_display_name) AS principal_name,
                   a.role_definition_id, cr.display_name AS role_name, a.assignment_type,
                   lower(substr(a.directory_scope_id, 2)) AS scope_object_id, a.directory_scope_id
              FROM entra_custom_role_assignment a
              JOIN cred_role cr ON cr.role_definition_id = a.role_definition_id
             WHERE a.client_id = %(client_id)s
               AND a.directory_scope_id ~ '^/[0-9a-fA-F-]{36}$'
            UNION
            SELECT rm.member_id, rm.member_type, COALESCE(rm.member_upn, rm.member_display_name),
                   rm.role_template_id, rm.role_display_name, rm.assignment_type,
                   lower(substr(rm.directory_scope_id, 2)), rm.directory_scope_id
              FROM entra_directory_role_member rm
             WHERE rm.client_id = %(client_id)s
               AND rm.via_group_id IS NULL
               AND rm.role_template_id IN ('9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3',
                                           '158c047a-c907-4556-b7ef-446551a6b5f7')
               AND rm.directory_scope_id ~ '^/[0-9a-fA-F-]{36}$'
        ),
        target AS (
            -- the scope is an application registration (-> its service principal) or a service principal
            SELECT s.*,
                   COALESCE((SELECT sp.entra_object_id FROM entra_service_principal sp
                              WHERE sp.client_id = %(client_id)s
                                AND sp.entra_object_id::text = s.scope_object_id),
                            (SELECT min(sp.entra_object_id::text)::uuid
                               FROM entra_application app
                               JOIN entra_service_principal sp
                                 ON sp.client_id = app.client_id AND sp.app_id = app.app_id
                              WHERE app.client_id = %(client_id)s
                                AND app.entra_object_id::text = s.scope_object_id)) AS sp_id,
                   COALESCE((SELECT app.display_name FROM entra_application app
                              WHERE app.client_id = %(client_id)s AND app.entra_object_id::text = s.scope_object_id),
                            (SELECT sp.display_name FROM entra_service_principal sp
                              WHERE sp.client_id = %(client_id)s
                                AND sp.entra_object_id::text = s.scope_object_id)) AS target_name
              FROM scoped s
             WHERE NOT EXISTS (SELECT 1 FROM tier0_holder h WHERE h.member_id = s.principal_id)
        )
        SELECT
            'fail' AS status,
            md5('10058:' || %(client_id)s::text || ':' || t.principal_id::text || ':' || lower(t.directory_scope_id)
                || ':' || t.role_definition_id::text)::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN p.takeover THEN 'critical' ELSE 'high' END AS fd_severity,
            COALESCE(t.principal_name, t.principal_id::text) || ' holds ' || COALESCE(t.role_name, 'a custom role')
                || CASE WHEN t.assignment_type = 'eligible' THEN ' (PIM-eligible)' ELSE '' END
                || ' scoped to application ' || COALESCE(t.target_name, t.scope_object_id)
                || ', which holds ' || p.privilege_text
                || ' -- adding a credential to it gives those privileges' AS summary,
            jsonb_build_object(
                'principal_id', t.principal_id,
                'principal_name', t.principal_name,
                'principal_type', t.principal_type,
                'role', t.role_name,
                'role_definition_id', t.role_definition_id,
                'assignment_type', t.assignment_type,
                'scope', t.directory_scope_id,
                'target_application', t.target_name,
                'target_service_principal_id', t.sp_id,
                'target_privileges', p.privileges
            ) AS detail
        FROM target t
        JOIN priv_sp p ON p.sp_id = t.sp_id
    """.replace("@TIER0@", TIER0_ROLES_SQL.strip())
       .replace("@PERMS@", PRIVILEGED_APP_PERMISSIONS_SQL.strip())
       .replace("@PRIVSP@", PRIVILEGED_SP_SQL.strip()),
}

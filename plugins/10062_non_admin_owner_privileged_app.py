"""
Plugin 10062: Non-Admin Owner of a Privileged Application or Service Principal

Reports owners of application registrations and service principals that are
privileged -- the service principal holds a PRIVILEGED_APP_PERMISSIONS
application permission (the 11 Graph permissions of plugin 10007 plus the
high-impact list of plugin 10064) or a highly privileged (TIER0) directory
role -- when the owner is not itself a TIER0 role holder. One finding per
(owned object, owner) pair.

Why it matters: an owner can add a client secret or certificate to what it
owns and then sign in as the application, inheriting every permission and
role the application holds -- no MFA, no approval. A user who owns a
Global-Administrator-equivalent application is therefore a Global
Administrator in all but name (BloodHound/AzureHound AZOwns -> AZAddSecret;
MITRE T1098.001), and that ownership is invisible in role reviews.

Severity (status 'fail'):
- critical: the owner is a user who holds no TIER0 role (active or
  PIM-eligible, directly or via a group); guests and on-premises-synced
  owners are named in the summary (a synced owner extends the path to
  on-premises AD);
- high: the owner is another service principal (whoever controls that
  application controls this one);
- one step lower and 'warn' when the owning user is disabled.
Owners that are users holding a TIER0 role are not reported (they already
have equivalent power). For an application registration, "privileged" means
its service principal in this tenant (entra_service_principal.app_id = the
application's app_id) is privileged.

Data: entra_app_owner (source app_owners) and entra_app_role_grant (source
app_role_grants), both required; entra_dangerous_permission_grant and
entra_directory_role_member also feed the privileged set. Mapping an
application registration to its service principal needs
entra_service_principal (source service_principals): when that read failed,
only service-principal ownership is assessed. Microsoft first-party service
principals have no customer owners and are not collected in
entra_app_owner. Identity = md5('10062:' || client || ':' || owned object
id || ':' || owner id).
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
    "plugin_id": 10062,
    "category": "Hybrid Identity",
    "name": "Non-Admin Owner of a Privileged Application or Service Principal",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "HYBRID-10062",
    "requires_sources": ["app_owners", "app_role_grants", "service_principals"],
    "framework_tags": [
        "CISA-ED-24-02",
        "NIST-800-53-AC-6",
        "NIST-800-53-AC-6(1)",
        "NIST-800-53-AC-2(7)",
        "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-7.2.1",
        "PCI-DSS-4.0-7.2.2",
        "CIS-CSC-8-6.8",
        "ISO-27001-2022-A.8.2",
        "ISO-27001-2022-A.5.15",
        "SOC2-CC6.3",
        "MITRE-ATTCK-T1098.001",
    ],
    "references": [
        {"title": "Microsoft: Privileged roles and permissions in Microsoft Entra ID (application ownership)",
         "url": "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/privileged-roles-permissions"},
        {"title": "Microsoft: Overview of enterprise application ownership",
         "url": "https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/overview-assign-app-owners"},
        {"title": "MITRE ATT&CK T1098.001: Additional Cloud Credentials",
         "url": "https://attack.mitre.org/techniques/T1098/001/"},
    ],
    "description": (
        "A user who holds no highly privileged directory role (critical), "
        "or another service principal (high), owns an application "
        "registration or service principal that holds a privileged "
        "application permission or a highly privileged directory role. "
        "An owner can add a credential and sign in as the application, "
        "inheriting its permissions without MFA -- a direct path from an "
        "ordinary account to tenant takeover. One finding per owner and "
        "owned object; lower when the owning user is disabled."
    ),
    "remediation": (
        "Remove the owner (Remove-MgApplicationOwnerByRef / "
        "Remove-MgServicePrincipalOwnerByRef) unless that person is meant "
        "to have the application's power; manage privileged applications "
        "only through Tier-0 administrators (Application Administrator "
        "scoped with care, or a dedicated custom role) and keep the owner "
        "list empty. Check the audit log for credentials the owner added "
        "('Update application - Certificates and secrets management') and "
        "remove any unexplained ones. Where an owner must remain, protect "
        "that account like a Global Administrator (cloud-only, "
        "phishing-resistant MFA, PIM)."
    ),
    "base_severity": "critical",
    "query": """
        WITH
        @TIER0@,
        @PERMS@,
        @PRIVSP@,
        tier0_user AS (
            SELECT DISTINCT rm.member_id
              FROM entra_directory_role_member rm
              JOIN tier0_role t ON t.role_template_id = rm.role_template_id
             WHERE rm.client_id = %(client_id)s
               AND rm.member_type = '#microsoft.graph.user'
        ),
        owned AS (
            SELECT o.*,
                   CASE WHEN o.owned_object_type = 'servicePrincipal' THEN o.owned_object_id
                        ELSE (SELECT min(s.entra_object_id::text)::uuid
                                FROM entra_service_principal s
                               WHERE s.client_id = %(client_id)s
                                 AND s.app_id = COALESCE(o.owned_app_id,
                                         (SELECT a.app_id FROM entra_application a
                                           WHERE a.client_id = %(client_id)s
                                             AND a.entra_object_id = o.owned_object_id)))
                   END AS target_sp_id
              FROM entra_app_owner o
             WHERE o.client_id = %(client_id)s
               AND o.owned_object_type IN ('application', 'servicePrincipal')
        ),
        flagged AS (
            SELECT o.*, p.privilege_text, p.privileges,
                   CASE WHEN o.owner_type = '#microsoft.graph.user' THEN 4 ELSE 3 END
                   - CASE WHEN o.owner_type = '#microsoft.graph.user' AND o.owner_account_enabled IS FALSE
                          THEN 1 ELSE 0 END AS sev_rank,
                   o.owner_type = '#microsoft.graph.user' AND o.owner_account_enabled IS FALSE AS owner_disabled
              FROM owned o
              JOIN priv_sp p ON p.sp_id = o.target_sp_id
             WHERE (o.owner_type = '#microsoft.graph.user'
                    AND NOT EXISTS (SELECT 1 FROM tier0_user t WHERE t.member_id = o.owner_id))
                OR o.owner_type = '#microsoft.graph.servicePrincipal'
        )
        SELECT
            CASE WHEN f.owner_disabled THEN 'warn' ELSE 'fail' END AS status,
            md5('10062:' || %(client_id)s::text || ':' || f.owned_object_id::text || ':' || f.owner_id::text)::uuid
                AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE f.sev_rank WHEN 4 THEN 'critical' WHEN 3 THEN 'high' ELSE 'medium' END AS fd_severity,
            CASE WHEN f.owner_type = '#microsoft.graph.user'
                 THEN 'User ' || COALESCE(f.owner_upn, f.owner_display_name, f.owner_id::text)
                      || CASE WHEN f.owner_user_type = 'Guest' THEN ' (guest)' ELSE '' END
                      || CASE WHEN f.owner_on_premises_sync_enabled THEN ' (synced from on-premises)' ELSE '' END
                      || CASE WHEN f.owner_disabled THEN ' (disabled)' ELSE '' END
                      || ', who holds no highly privileged role,'
                 ELSE 'Service principal ' || COALESCE(f.owner_display_name, f.owner_id::text) END
                || ' owns '
                || CASE WHEN f.owned_object_type = 'application' THEN 'application registration "'
                        ELSE 'service principal "' END
                || COALESCE(f.owned_display_name, f.owned_app_id::text, f.owned_object_id::text)
                || '", which holds ' || f.privilege_text AS summary,
            jsonb_build_object(
                'owned_object_id', f.owned_object_id,
                'owned_object_type', f.owned_object_type,
                'owned_display_name', f.owned_display_name,
                'owned_app_id', f.owned_app_id,
                'service_principal_id', f.target_sp_id,
                'privileges', f.privileges,
                'owner_id', f.owner_id,
                'owner_type', f.owner_type,
                'owner_display_name', f.owner_display_name,
                'owner_upn', f.owner_upn,
                'owner_user_type', f.owner_user_type,
                'owner_on_premises_sync_enabled', f.owner_on_premises_sync_enabled,
                'owner_account_enabled', f.owner_account_enabled
            ) AS detail
        FROM flagged f
    """.replace("@TIER0@", TIER0_ROLES_SQL.strip())
       .replace("@PERMS@", PRIVILEGED_APP_PERMISSIONS_SQL.strip())
       .replace("@PRIVSP@", PRIVILEGED_SP_SQL.strip()),
}

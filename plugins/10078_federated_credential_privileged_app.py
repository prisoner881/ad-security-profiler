"""
Plugin 10078: Federated Identity Credential on a Privileged Application

Reports federated identity credentials (FICs) on application
registrations whose service principal is privileged -- it holds a highly
privileged directory role or a privileged application permission (same
definitions as plugin 10062).

Why: a FIC tells Entra ID to accept a token from an outside identity
provider (GitHub Actions, Azure DevOps, Kubernetes, Google, another
tenant...) whose issuer and subject match, and to hand out the
application's own token in exchange -- no secret or certificate exists to
rotate, expire or detect. Whoever can make that provider issue a matching
token (push to the GitHub repository or branch, run a pipeline, control
the Kubernetes service account, or own the issuer URL) acts as the
application. It is a favoured persistence mechanism because credential
reviews (plugins 10005, 10060, 11023) never see it; BloodHound models it
as AZFederatedIdentityCredential. No baseline tool checks it.

Severity (fail): high when the application holds a takeover-class
permission or a highly privileged role, medium when it holds only
high-impact data permissions. The summary names the issuer and subject;
a GitHub subject for pull requests (any branch's pull request can obtain
the token) or an issuer outside the well-known providers is called out in
detail. Credentials on user-assigned managed identities are Azure
resources and are not read. One finding per credential (object_guid
md5('10078:' || client_id || ':' || application || ':' || credential)).
Data: entra_federated_identity_credential (source
federated_identity_credentials, entra_graph_collector 0.9.0).
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
    "plugin_id": 10078,
    "category": "Hybrid Identity",
    "name": "Federated Identity Credential on a Privileged Application",
    "version": "1.0",
    "revision_date": "2026-10-22",
    "control_id": "HYBRID-10078",
    "requires_sources": ["federated_identity_credentials", "app_role_grants", "service_principals"],
    "framework_tags": [
        "NIST-800-53-AC-6",
        "NIST-800-53-IA-5",
        "NIST-800-53-AC-20",
        "NIST-CSF-2.0-PR.AA-05",
        "CIS-CSC-8-5.4",
        "ISO-27001-2022-A.5.17",
        "SOC2-CC6.1",
        "MITRE-ATTCK-T1098.001",
        "MITRE-ATTCK-T1550.001",
    ],
    "references": [
        {"title": "Microsoft: Workload identity federation",
         "url": "https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation"},
        {"title": "Microsoft: Configure an app to trust an external identity provider",
         "url": "https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation-create-trust"},
        {"title": "Microsoft Graph: federatedIdentityCredential resource type",
         "url": "https://learn.microsoft.com/en-us/graph/api/resources/federatedidentitycredential"},
        {"title": "MITRE ATT&CK T1098.001: Account Manipulation: Additional Cloud Credentials",
         "url": "https://attack.mitre.org/techniques/T1098/001/"},
    ],
    "description": (
        "A privileged application trusts tokens from an outside identity provider through a "
        "federated identity credential: whoever can make that provider issue a matching token "
        "(a GitHub workflow, a pipeline, a Kubernetes service account) signs in as the "
        "application without any secret. High when the application can take over the tenant."
    ),
    "remediation": (
        "Entra admin center > App registrations > the application > Certificates & secrets > "
        "Federated credentials: confirm each credential is expected, that the subject is as "
        "narrow as possible (a protected branch or environment, not pull requests), and that "
        "write access to the source (repository, pipeline, cluster) is restricted to people "
        "trusted at the application's privilege level. Remove unknown credentials and review "
        "the application's sign-ins. Prefer a dedicated, least-privileged application per "
        "pipeline."
    ),
    "base_severity": "high",
    "query": """
        WITH
        @TIER0@,
        @PERMS@,
        @PRIVSP@,
        fic AS (
            SELECT f.*,
                   (SELECT min(sp.entra_object_id::text)::uuid FROM entra_service_principal sp
                     WHERE sp.client_id = f.client_id AND sp.app_id = f.app_id) AS sp_id
              FROM entra_federated_identity_credential f
             WHERE f.client_id = %(client_id)s
        )
        SELECT
            'fail' AS status,
            md5('10078:' || f.client_id::text || ':' || f.app_object_id::text || ':' || f.credential_id::text)::uuid
                AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN p.takeover THEN 'high' ELSE 'medium' END AS fd_severity,
            'Application ' || COALESCE(f.app_display_name, f.app_id::text) || ' (holds ' || p.privilege_text
                || ') trusts tokens from ' || COALESCE(f.issuer, '(no issuer)') || ' for subject '
                || COALESCE(f.subject, '(none)') || ' (federated credential '
                || COALESCE(f.name, f.credential_id::text) || ')' AS summary,
            jsonb_build_object(
                'application', f.app_display_name,
                'app_id', f.app_id,
                'credential_name', f.name,
                'issuer', f.issuer,
                'subject', f.subject,
                'audiences', f.audiences,
                'description', f.description,
                'application_privileges', p.privileges,
                'subject_note', CASE WHEN f.issuer = 'https://token.actions.githubusercontent.com'
                                          AND f.subject LIKE '%%:pull_request'
                                     THEN 'Any pull request workflow run from a branch of the repository can obtain this token, without a merge or review.' END,
                'issuer_note', CASE WHEN f.issuer NOT LIKE 'https://token.actions.githubusercontent.com%%'
                                         AND f.issuer NOT LIKE 'https://login.microsoftonline.com/%%'
                                         AND f.issuer NOT LIKE 'https://sts.windows.net/%%'
                                         AND f.issuer NOT LIKE 'https://vstoken.dev.azure.com/%%'
                                         AND f.issuer NOT LIKE 'https://accounts.google.com%%'
                                         AND f.issuer NOT LIKE 'https://oidc.prod-aks.azure.com/%%'
                                         AND f.issuer NOT LIKE 'https://%%.oic.prod-aks.azure.com/%%'
                                    THEN 'Issuer is not one of the well-known providers; confirm who controls it.'
                               END
            ) AS detail
        FROM fic f
        JOIN priv_sp p ON p.sp_id = f.sp_id
    """.replace("@TIER0@", TIER0_ROLES_SQL.strip())
       .replace("@PERMS@", PRIVILEGED_APP_PERMISSIONS_SQL.strip())
       .replace("@PRIVSP@", PRIVILEGED_SP_SQL.strip()),
}

"""
Plugin 10126: Federated Credential Trusts a Repository by Name (Repository Recycling)

A federated identity credential lets a CI/CD pipeline sign in as an Entra
application without a stored secret: Entra accepts the pipeline's OIDC
token when its issuer and subject match. For GitHub Actions the default
subject is name-based (repo:<owner>/<repository>:ref:refs/heads/main,
...:environment:prod, ...), and GitLab's is project_path:<group>/<project>.
Names are reusable: if the repository, organisation or project is deleted
or renamed, whoever registers the same name gets pipelines whose tokens
match -- and signs in as the application. Nicola Suter, "Preventing subject
recycling in Entra ID federated credentials" (2026-10-21), recommends
immutable subjects that carry numeric IDs (GitHub OIDC subject
customisation with repository_owner_id / repository_id, or owner@<id> /
repo@<id> forms; GitLab project_id via a claims-matching expression). The
November 2026 compromise of the agent-framework PyPI package (Wiz,
2026-11-17), which stole GitHub and Azure DevOps OIDC tokens, shows these
tokens are actively sought.

Reported: credentials whose issuer is GitHub Actions
(https://token.actions.githubusercontent.com) and whose subject carries no
numeric owner / repository ID, and credentials whose issuer is GitLab
(https://gitlab.com or a host named gitlab.*) and whose subject is
project_path-based. Flexible credentials (claims-matching expression, no
subject) are not evaluated. One finding per application, status 'fail':
  * high: the application's service principal is privileged (a directory
    takeover permission, a high-impact API permission, or a Tier 0 role --
    the definitions of plugins 10064 / 10078);
  * medium: otherwise.

Data: entra_federated_identity_credential, entra_service_principal,
entra_app_role_grant, entra_dangerous_permission_grant,
entra_directory_role_member. Identity = the application object. Related:
10078 (federated credential on a privileged application), 11030 (new
federated credential).
"""

# Shared definitions copied verbatim from plugin 10064 (as in 10058-10078).
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
    "plugin_id": 10126,
    "category": "Hybrid Identity",
    "name": "Federated Credential Trusts a Repository by Name (Repository Recycling)",
    "version": "1.0",
    "revision_date": "2026-11-20",
    "control_id": "HYBRID-10126",
    "requires_sources": ["federated_identity_credentials"],
    "framework_tags": [
        "NIST-800-53-IA-5",
        "NIST-800-53-AC-6",
        "NIST-800-53-CM-11",
        "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-8.6.1",
        "CIS-CSC-8-6.7",
        "ISO-27001-2022-A.5.17",
        "ISO-27001-2022-A.5.23",
        "SOC2-CC6.1",
        "MITRE-ATTCK-T1078.004",
        "MITRE-ATTCK-T1195.002",
    ],
    "references": [
        {"title": "Nicola Suter: Preventing subject recycling in Entra ID federated credentials (2026-10-21)",
         "url": "https://nicolasuter.ch/til/entra-federated-credentials-subject-recycling/"},
        {"title": "Wiz: Malicious version of Microsoft's agent-framework published to PyPI (2026-11-17)",
         "url": "https://www.wiz.io/blog/malicious-version-of-microsofts-agent-framework-published-to-pypi"},
        {"title": "GitHub Docs: About security hardening with OpenID Connect (subject claim customisation)",
         "url": "https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect"},
        {"title": "Microsoft Learn: Workload identity federation",
         "url": "https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation"},
    ],
    "description": (
        "An application's federated identity credential trusts a GitHub Actions or GitLab pipeline "
        "by repository name (a subject such as repo:<owner>/<repo>:ref:...) rather than by its "
        "immutable numeric ID. If the repository or organisation is deleted or renamed, whoever "
        "re-creates the name can sign in as the application. High when the application is "
        "privileged; medium otherwise."
    ),
    "remediation": (
        "Change the credential's subject to an immutable form: for GitHub, customise the "
        "organisation's or repository's OIDC subject template to include repository_owner_id and "
        "repository_id, then update the credential to match; for GitLab, use a flexible "
        "credential (claims-matching expression) on project_id. Remove credentials for "
        "repositories that no longer exist (confirm each one still exists and is owned by you). "
        "Scope credentials to a protected branch or environment, and keep the application's "
        "permissions to what the pipeline needs."
    ),
    "base_severity": "high",
    "query": """
        WITH
        @TIER0@,
        @PERMS@,
        @PRIVSP@,
        fic AS (
            SELECT f.app_object_id, f.app_id, f.app_display_name, f.name, f.issuer, f.subject,
                   CASE WHEN lower(rtrim(f.issuer, '/')) = 'https://token.actions.githubusercontent.com'
                        THEN 'GitHub Actions'
                        WHEN f.issuer ~* '^https://gitlab[.]' THEN 'GitLab' END AS platform
              FROM entra_federated_identity_credential f
             WHERE f.client_id = %(client_id)s
               AND f.subject IS NOT NULL AND f.subject <> ''
        ),
        mutable AS (
            SELECT * FROM fic
             WHERE (platform = 'GitHub Actions'
                    AND subject !~* '(repository_owner_id|repository_id)[:=]'
                    AND subject !~ '@[0-9]+')
                OR (platform = 'GitLab' AND subject !~* 'project_id[:=]')
        ),
        per_app AS (
            SELECT m.app_object_id, min(m.app_id::text)::uuid AS app_id,
                   min(m.app_display_name) AS app_name,
                   string_agg(DISTINCT m.platform, ', ') AS platforms,
                   count(*) AS cred_count,
                   jsonb_agg(jsonb_build_object('name', m.name, 'platform', m.platform,
                                                'issuer', m.issuer, 'subject', m.subject)
                             ORDER BY m.name) AS credentials
              FROM mutable m
             GROUP BY m.app_object_id
        ),
        cls AS (
            SELECT a.*, sp.entra_object_id AS sp_id, ps.privilege_text,
                   ps.sp_id IS NOT NULL AS privileged
              FROM per_app a
              LEFT JOIN entra_service_principal sp
                     ON sp.client_id = %(client_id)s AND sp.app_id = a.app_id
              LEFT JOIN priv_sp ps ON ps.sp_id = sp.entra_object_id
        )
        SELECT
            'fail' AS status,
            c.app_object_id AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN c.privileged THEN 'high' ELSE 'medium' END AS fd_severity,
            'Application "' || COALESCE(c.app_name, c.app_id::text) || '" has ' || c.cred_count
                || ' federated credential(s) trusting a ' || c.platforms
                || ' pipeline by repository name, so a re-created repository could sign in as it'
                || CASE WHEN c.privileged THEN ' -- the application is privileged (' || c.privilege_text || ')'
                        ELSE '' END AS summary,
            jsonb_build_object(
                'application', c.app_name,
                'app_id', c.app_id,
                'application_object_id', c.app_object_id,
                'service_principal_id', c.sp_id,
                'privileged', c.privileged,
                'privileges', c.privilege_text,
                'credentials', c.credentials,
                'note', 'Flexible credentials (claims-matching expressions) are not evaluated.'
            ) AS detail
        FROM cls c
    """.replace("@TIER0@", TIER0_ROLES_SQL.strip())
       .replace("@PERMS@", PRIVILEGED_APP_PERMISSIONS_SQL.strip())
       .replace("@PRIVSP@", PRIVILEGED_SP_SQL.strip()),
}

"""
Plugin 10060: Credentials Added Directly to a Service Principal

Reports service principals (enterprise applications) that carry client
secrets (passwordCredentials) or certificates (keyCredentials) on the
SERVICE PRINCIPAL object itself rather than on the application
registration. One finding per service principal, every credential listed.

Why it matters: credentials on the service principal let anyone holding
them authenticate as that application in this tenant, yet they do not show
in the App registrations blade (Certificates & secrets), so administrators
rarely see them. Adding a credential to an existing, already-privileged
service principal -- in particular a Microsoft first-party one, which has no
app registration in the tenant at all -- was the persistence technique of
the SolarWinds/Solorigate actor (CISA AA21-008A) and of Midnight Blizzard
against Microsoft (MITRE T1098.001 Additional Cloud Credentials). CISA SCuBA
MS.AAD.5.5 recommends blocking application password addition.

Severity (status 'fail'):
- critical: the service principal belongs to a Microsoft first-party
  application (appOwnerOrganizationId f8cdef31-a31e-4b4a-93e4-5f571e91255a
  or 72f988bf-86f1-41af-91ab-2d7cd011db47) -- Microsoft never needs a
  customer-added credential there -- or it is privileged: it holds a
  PRIVILEGED_APP_PERMISSIONS application permission (the 11 Graph
  permissions of plugin 10007 plus the high-impact list of plugin 10064) or
  a highly privileged directory role (the TIER0 set of plugin 10019);
- high: any other service principal (this tenant's own application or a
  third-party multi-tenant application).
One step lower and status 'warn' when the service principal is disabled
(it can be re-enabled). When every reported credential has already expired,
the finding is a low 'warn' (an inert leftover: delete it, and check the
audit log for when and by whom it was added).

Excluded:
- SAML single sign-on signing material: on a service principal with
  preferred_single_sign_on_mode 'saml', certificates with usage 'Sign' or
  'Verify' are the token-signing certificate Entra creates, and a password
  credential paired with them (same key_id or custom_key_identifier, or
  the same end date to the minute for data collected before
  custom_key_identifier was stored) holds its private-key
  password. Any OTHER credential on a SAML application is still reported.
- Managed identities (service_principal_type 'ManagedIdentity'): Azure
  manages their certificate itself.

Data: entra_service_principal (source service_principals, required).
Privilege enrichment reads entra_app_role_grant (source app_role_grants),
entra_dangerous_permission_grant and entra_directory_role_member; when
app_role_grants was not read, only the 10007 class and roles are known.
The tenant's own id comes from entra_tenant_setting 'organization' (else it
is inferred from this tenant's app registrations; used only to label the
owner). Credential dates are judged against the
snapshot's collected_at. Identity = the service principal's object id.
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
    "plugin_id": 10060,
    "category": "Hybrid Identity",
    "name": "Credentials Added Directly to a Service Principal",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "HYBRID-10060",
    "requires_sources": ["service_principals"],
    "framework_tags": [
        "CISA-AA21-008A",
        "CISA-ED-24-02",
        "CISA-SCUBA-MS.AAD.5.5",
        "NIST-800-53-AC-2",
        "NIST-800-53-IA-5",
        "NIST-800-53-AC-6",
        "PCI-DSS-4.0-8.6.1",
        "PCI-DSS-4.0-8.6.3",
        "CIS-CSC-8-5.5",
        "ISO-27001-2022-A.5.17",
        "SOC2-CC6.1",
        "MITRE-ATTCK-T1098.001",
    ],
    "references": [
        {"title": "CISA AA21-008A: Detecting Post-Compromise Threat Activity in Microsoft Cloud Environments",
         "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-008a"},
        {"title": "MSRC: Microsoft Actions Following Attack by Nation State Actor Midnight Blizzard",
         "url": "https://msrc.microsoft.com/blog/2024/01/microsoft-actions-following-attack-by-nation-state-actor-midnight-blizzard/"},
        {"title": "CISA SCuBA Microsoft Entra ID baseline (MS.AAD.5.5)",
         "url": "https://github.com/cisagov/ScubaGear/blob/main/PowerShell/ScubaGear/baselines/aad.md"},
        {"title": "Microsoft Graph: servicePrincipal resource type",
         "url": "https://learn.microsoft.com/en-us/graph/api/resources/serviceprincipal"},
        {"title": "MITRE ATT&CK T1098.001: Additional Cloud Credentials",
         "url": "https://attack.mitre.org/techniques/T1098/001/"},
    ],
    "description": (
        "A client secret or certificate is set directly on a service "
        "principal (enterprise application) rather than on its app "
        "registration, where it does not appear in the App registrations "
        "blade -- the persistence technique of the Solorigate actor "
        "(CISA AA21-008A) and of Midnight Blizzard. Critical on a "
        "Microsoft first-party application or a service principal holding "
        "a privileged application permission or directory role, high "
        "otherwise; lower when the service principal is disabled or every "
        "credential has expired. SAML token-signing certificates and "
        "managed identities are excluded."
    ),
    "remediation": (
        "Find who added the credential and when (Entra audit log: "
        "'Update service principal' / 'Add service principal credentials'). "
        "If it is not a documented integration, treat it as a compromise: "
        "remove it (Remove-MgServicePrincipalPassword / "
        "Update-MgServicePrincipal -KeyCredentials with the credential "
        "removed), review the application's sign-ins and the actions it "
        "took, and rotate anything it could reach. Never add credentials "
        "to Microsoft first-party service principals. For your own "
        "applications put credentials on the app registration (prefer "
        "certificates or managed identities / workload identity "
        "federation), and block password addition with an app management "
        "policy (SCuBA MS.AAD.5.5)."
    ),
    "base_severity": "critical",
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
        sps AS (
            SELECT sp.*
              FROM entra_service_principal sp
             WHERE sp.client_id = %(client_id)s
               AND sp.service_principal_type IS DISTINCT FROM 'ManagedIdentity'
        ),
        creds AS (
            SELECT sp.entra_object_id, 'secret' AS cred_type, c.value AS cred, c.ord
              FROM sps sp
              CROSS JOIN LATERAL jsonb_array_elements(
                  CASE WHEN jsonb_typeof(sp.password_credentials) = 'array'
                       THEN sp.password_credentials ELSE '[]'::jsonb END) WITH ORDINALITY AS c(value, ord)
            UNION ALL
            SELECT sp.entra_object_id, 'certificate', c.value, c.ord
              FROM sps sp
              CROSS JOIN LATERAL jsonb_array_elements(
                  CASE WHEN jsonb_typeof(sp.key_credentials) = 'array'
                       THEN sp.key_credentials ELSE '[]'::jsonb END) WITH ORDINALITY AS c(value, ord)
        ),
        saml_cert AS (
            SELECT c.entra_object_id, c.cred->>'key_id' AS key_id,
                   c.cred->>'custom_key_identifier' AS custom_key_identifier,
                   (c.cred->>'end_date_time')::timestamptz AS end_at
              FROM creds c
              JOIN sps sp ON sp.entra_object_id = c.entra_object_id
             WHERE lower(sp.preferred_single_sign_on_mode) = 'saml'
               AND c.cred_type = 'certificate'
               AND c.cred->>'usage' IN ('Sign', 'Verify')
        ),
        reported AS (
            SELECT c.entra_object_id, c.cred_type, c.ord,
                   c.cred->>'key_id' AS key_id,
                   c.cred->>'display_name' AS cred_display_name,
                   c.cred->>'usage' AS usage,
                   (c.cred->>'start_date_time')::timestamptz AS start_at,
                   (c.cred->>'end_date_time')::timestamptz AS end_at
              FROM creds c
             WHERE NOT EXISTS (
                       SELECT 1 FROM saml_cert s
                        WHERE s.entra_object_id = c.entra_object_id
                          AND ( (c.cred_type = 'certificate' AND c.cred->>'usage' IN ('Sign', 'Verify'))
                             OR (c.cred_type = 'secret'
                                 AND (s.key_id = c.cred->>'key_id'
                                      OR s.custom_key_identifier = c.cred->>'custom_key_identifier'
                                      OR date_trunc('minute', s.end_at)
                                         = date_trunc('minute', (c.cred->>'end_date_time')::timestamptz)))))
        ),
        per_sp AS (
            SELECT sp.entra_object_id, sp.display_name, sp.app_id, sp.app_owner_organization_id,
                   sp.verified_publisher_name, sp.preferred_single_sign_on_mode, sp.account_enabled,
                   count(*) FILTER (WHERE r.cred_type = 'secret'
                                      AND (r.end_at IS NULL OR r.end_at >= sp.collected_at)) AS active_secrets,
                   count(*) FILTER (WHERE r.cred_type = 'certificate'
                                      AND (r.end_at IS NULL OR r.end_at >= sp.collected_at)) AS active_certs,
                   count(*) FILTER (WHERE r.cred_type = 'secret') AS all_secrets,
                   count(*) FILTER (WHERE r.cred_type = 'certificate') AS all_certs,
                   jsonb_agg(jsonb_build_object(
                       'type', r.cred_type, 'key_id', r.key_id, 'display_name', r.cred_display_name,
                       'usage', r.usage, 'start_date_time', r.start_at, 'end_date_time', r.end_at,
                       'expired', r.end_at < sp.collected_at)
                       ORDER BY r.cred_type, r.end_at, r.key_id COLLATE "C", r.ord) AS credentials
              FROM reported r
              JOIN sps sp ON sp.entra_object_id = r.entra_object_id
             GROUP BY sp.entra_object_id, sp.display_name, sp.app_id, sp.app_owner_organization_id,
                      sp.verified_publisher_name, sp.preferred_single_sign_on_mode, sp.account_enabled
        ),
        classified AS (
            SELECT p.*,
                   ps.privilege_text, ps.privileges,
                   p.app_owner_organization_id IN @MSTENANTS@ AS microsoft_first_party,
                   CASE WHEN p.app_owner_organization_id IN @MSTENANTS@ THEN 'Microsoft first-party'
                        WHEN p.app_owner_organization_id = (SELECT t.tenant_id FROM tenant t)
                          OR EXISTS (SELECT 1 FROM entra_application a
                                      WHERE a.client_id = %(client_id)s AND a.app_id = p.app_id)
                        THEN 'this tenant''s application'
                        WHEN p.app_owner_organization_id IS NOT NULL THEN 'third-party application'
                        ELSE 'owner tenant unknown' END AS owner_class,
                   (p.active_secrets + p.active_certs) > 0 AS has_active,
                   p.account_enabled IS FALSE AS disabled
              FROM per_sp p
              LEFT JOIN priv_sp ps ON ps.sp_id = p.entra_object_id
        ),
        graded AS (
            SELECT c.*,
                   CASE WHEN NOT c.has_active THEN 1
                        ELSE greatest(1, CASE WHEN c.microsoft_first_party OR c.privileges IS NOT NULL THEN 4 ELSE 3 END
                                         - CASE WHEN c.disabled THEN 1 ELSE 0 END) END AS sev_rank
              FROM classified c
        )
        SELECT
            CASE WHEN g.has_active AND NOT g.disabled THEN 'fail' ELSE 'warn' END AS status,
            g.entra_object_id AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE g.sev_rank WHEN 4 THEN 'critical' WHEN 3 THEN 'high' WHEN 2 THEN 'medium' ELSE 'low' END AS fd_severity,
            'Service principal "' || COALESCE(g.display_name, g.app_id::text, g.entra_object_id::text)
                || '" (' || g.owner_class
                || CASE WHEN g.privileges IS NOT NULL THEN ', privileged: ' || g.privilege_text ELSE '' END
                || ') has credentials set directly on the service principal: '
                || CASE WHEN g.has_active
                        THEN g.active_secrets::text || ' active client secret(s), '
                             || g.active_certs::text || ' active certificate(s)'
                        ELSE (g.all_secrets + g.all_certs)::text || ' credential(s), all expired' END
                || CASE WHEN g.disabled THEN ' (service principal disabled)' ELSE '' END AS summary,
            jsonb_build_object(
                'service_principal_id', g.entra_object_id,
                'display_name', g.display_name,
                'app_id', g.app_id,
                'app_owner_organization_id', g.app_owner_organization_id,
                'owner', g.owner_class,
                'microsoft_first_party', COALESCE(g.microsoft_first_party, false),
                'verified_publisher_name', g.verified_publisher_name,
                'preferred_single_sign_on_mode', g.preferred_single_sign_on_mode,
                'account_enabled', g.account_enabled,
                'privileges', COALESCE(g.privileges, '[]'::jsonb),
                'active_secrets', g.active_secrets,
                'active_certificates', g.active_certs,
                'credentials', g.credentials
            ) AS detail
        FROM graded g
    """.replace("@TIER0@", TIER0_ROLES_SQL.strip())
       .replace("@PERMS@", PRIVILEGED_APP_PERMISSIONS_SQL.strip())
       .replace("@PRIVSP@", PRIVILEGED_SP_SQL.strip())
       .replace("@MSTENANTS@", MICROSOFT_OWNER_TENANTS_SQL),
}

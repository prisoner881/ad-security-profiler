"""
Plugin 10067: Risky Application Redirect URIs and Token Settings

Reviews each application registration's reply (redirect) URIs -- web, SPA
and public-client platforms -- and its token settings. One finding per
application, every issue listed, worst severity wins.

Checks:
- a redirect URI containing a wildcard '*' -> high when the application's
  service principal is privileged (holds a PRIVILEGED_APP_PERMISSIONS
  application permission or a TIER0 directory role), medium otherwise.
  Entra no longer accepts new wildcard reply URLs; an existing one lets any
  matching host -- possibly attacker-registered -- receive authorization
  codes and tokens.
- an http:// redirect URI other than localhost / 127.0.0.1 / [::1] ->
  medium: codes and tokens travel in clear text and can be intercepted.
- a redirect URI on a shared Azure hosting domain (azurewebsites.net,
  cloudapp.net, cloudapp.azure.com, trafficmanager.net, azureedge.net,
  blob.core.windows.net) -> low: if the Azure resource behind the name was
  deleted, anyone can re-register the name (subdomain takeover) and collect
  tokens issued to it. Verify that the resource still exists and belongs to
  you.
- implicit grant access-token issuance enabled
  (implicitGrantSettings.enableAccessTokenIssuance) -> low: tokens returned
  in the URL fragment; use the authorization code flow with PKCE instead.
- isFallbackPublicClient true on an application whose service principal is
  privileged -> medium: public-client (no secret) flows such as ROPC and
  device code are then allowed for that application.

Why it matters: whoever controls a redirect URI receives what Entra sends
to it -- authorization codes, ID and access tokens -- and can then act as
the signed-in user against the application's APIs (MITRE T1528; OWASP
OAuth 2.0 security guidance, RFC 9700).

Data: entra_application web_redirect_uris, spa_redirect_uris,
public_client_redirect_uris, implicit_access_token_issuance,
is_fallback_public_client (schema v42, core applications step). NULL = the
collector did not return the field (older collector): that check is
skipped. Privilege needs entra_service_principal (app_id) plus grants and
roles; when the service principal is unknown the application is treated as
not privileged (detail 'privilege_known' false). Status 'fail' for medium
and above, 'warn' for low only. Identity = the application's object id.
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
    "plugin_id": 10067,
    "category": "Hybrid Identity",
    "name": "Risky Application Redirect URIs and Token Settings",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "HYBRID-10067",
    "framework_tags": [
        "NIST-800-53-CM-6",
        "NIST-800-53-CM-7",
        "NIST-CSF-2.0-PR.PS-01",
        "PCI-DSS-4.0-2.2.1",
        "CIS-CSC-8-4.1",
        "ISO-27001-2022-A.8.9",
        "SOC2-CC7.1",
        "MITRE-ATTCK-T1528",
    ],
    "references": [
        {"title": "Microsoft: Redirect URI (reply URL) best practices and limitations",
         "url": "https://learn.microsoft.com/en-us/entra/identity-platform/reply-url"},
        {"title": "Microsoft: Security best practices for application properties in Microsoft Entra ID",
         "url": "https://learn.microsoft.com/en-us/entra/identity-platform/security-best-practices-for-app-registration"},
        {"title": "Microsoft: Prevent dangling DNS entries and avoid subdomain takeover",
         "url": "https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover"},
        {"title": "RFC 9700: Best Current Practice for OAuth 2.0 Security",
         "url": "https://datatracker.ietf.org/doc/html/rfc9700"},
        {"title": "MITRE ATT&CK T1528: Steal Application Access Token",
         "url": "https://attack.mitre.org/techniques/T1528/"},
    ],
    "description": (
        "An application registration has a wildcard redirect URI (high "
        "when the application is privileged, otherwise medium), an http:// "
        "redirect URI to a non-loopback host (medium), a redirect URI on a "
        "shared Azure hosting domain that could be dangling and taken over "
        "(low), implicit-grant access-token issuance enabled (low), or "
        "public-client fallback enabled on a privileged application "
        "(medium). Whoever controls a redirect URI receives the "
        "application's authorization codes and tokens. One finding per "
        "application."
    ),
    "remediation": (
        "Entra admin center -> App registrations -> the app -> "
        "Authentication: replace wildcard redirect URIs with the exact "
        "URIs in use; change http:// URIs to https:// (loopback URIs for "
        "native apps may stay http); for URIs on azurewebsites.net, "
        "cloudapp.net and similar domains confirm the Azure resource "
        "exists and belongs to you, and remove URIs of deleted resources "
        "(see Microsoft's subdomain-takeover guidance); clear 'Access "
        "tokens (used for implicit flows)' and move SPAs to the "
        "authorization code flow with PKCE; set 'Allow public client "
        "flows' to No unless the app is a native/public client. "
        "PowerShell: Update-MgApplication -Web @{RedirectUris=...; "
        "ImplicitGrantSettings=@{EnableAccessTokenIssuance=$false}} "
        "-IsFallbackPublicClient:$false."
    ),
    "base_severity": "medium",
    "query": r"""
        WITH
        @TIER0@,
        @PERMS@,
        @PRIVSP@,
        app_priv AS (
            SELECT a.entra_object_id,
                   bool_or(s.entra_object_id IS NOT NULL) AS privilege_known,
                   bool_or(p.sp_id IS NOT NULL) AS privileged,
                   min(p.privilege_text) AS privilege_text
              FROM entra_application a
              LEFT JOIN entra_service_principal s
                     ON s.client_id = a.client_id AND s.app_id = a.app_id
              LEFT JOIN priv_sp p ON p.sp_id = s.entra_object_id
             WHERE a.client_id = %(client_id)s
             GROUP BY a.entra_object_id
        ),
        uris AS (
            SELECT a.entra_object_id, u.uri COLLATE "C" AS uri,
                   lower(substring(u.uri FROM '^[A-Za-z][A-Za-z0-9+.-]*://(?:[^@/?#]*@)?([^/:?#]+)')) AS host
              FROM entra_application a
              CROSS JOIN LATERAL (
                  SELECT unnest(a.web_redirect_uris)
                  UNION SELECT unnest(a.spa_redirect_uris)
                  UNION SELECT unnest(a.public_client_redirect_uris)) AS u(uri)
             WHERE a.client_id = %(client_id)s
               AND u.uri IS NOT NULL
        ),
        uri_issue AS (
            SELECT u.entra_object_id, 'wildcard' AS kind, u.uri
              FROM uris u
             WHERE strpos(u.uri, '*') > 0
            UNION ALL
            SELECT u.entra_object_id, 'http', u.uri
              FROM uris u
             WHERE u.uri ~* '^http://'
               AND u.uri !~* '^http://(localhost|127\.0\.0\.1|\[::1\])([:/?#]|$)'
            UNION ALL
            SELECT u.entra_object_id, 'shared_host', u.uri
              FROM uris u
             WHERE u.host ~ '(^|\.)(azurewebsites\.net|cloudapp\.net|cloudapp\.azure\.com|trafficmanager\.net|azureedge\.net|blob\.core\.windows\.net)$'
        ),
        uri_agg AS (
            SELECT ui.entra_object_id, ui.kind,
                   string_agg(DISTINCT ui.uri, ', ' ORDER BY ui.uri) AS uri_text,
                   jsonb_agg(DISTINCT ui.uri ORDER BY ui.uri) AS uri_list
              FROM uri_issue ui
             GROUP BY ui.entra_object_id, ui.kind
        ),
        issues AS (
            SELECT ua.entra_object_id,
                   CASE ua.kind WHEN 'wildcard' THEN CASE WHEN ap.privileged THEN 3 ELSE 2 END
                                WHEN 'http' THEN 2 ELSE 1 END AS rank,
                   CASE ua.kind WHEN 'wildcard' THEN 'wildcard redirect URI: '
                                WHEN 'http' THEN 'non-HTTPS redirect URI: '
                                ELSE 'redirect URI on shared Azure hosting (verify the resource still exists): ' END
                   || ua.uri_text AS issue
              FROM uri_agg ua
              JOIN app_priv ap ON ap.entra_object_id = ua.entra_object_id
            UNION ALL
            SELECT a.entra_object_id, 1, 'implicit grant access-token issuance enabled'
              FROM entra_application a
             WHERE a.client_id = %(client_id)s
               AND a.implicit_access_token_issuance IS TRUE
            UNION ALL
            SELECT a.entra_object_id, 2, 'public client flows allowed (isFallbackPublicClient) on a privileged application'
              FROM entra_application a
              JOIN app_priv ap ON ap.entra_object_id = a.entra_object_id
             WHERE a.client_id = %(client_id)s
               AND a.is_fallback_public_client IS TRUE
               AND ap.privileged
        ),
        agg AS (
            SELECT i.entra_object_id, max(i.rank) AS rank,
                   string_agg(i.issue COLLATE "C", '; ' ORDER BY i.rank DESC, i.issue COLLATE "C") AS issue_text,
                   jsonb_agg(i.issue ORDER BY i.rank DESC, i.issue COLLATE "C") AS issue_list
              FROM issues i
             GROUP BY i.entra_object_id
        )
        SELECT
            CASE WHEN g.rank >= 2 THEN 'fail' ELSE 'warn' END AS status,
            a.entra_object_id AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE g.rank WHEN 3 THEN 'high' WHEN 2 THEN 'medium' ELSE 'low' END AS fd_severity,
            'Application "' || COALESCE(a.display_name, a.app_id::text, a.entra_object_id::text)
                || '": ' || g.issue_text AS summary,
            jsonb_build_object(
                'application_id', a.entra_object_id,
                'app_id', a.app_id,
                'display_name', a.display_name,
                'issues', g.issue_list,
                'wildcard_redirect_uris', (SELECT ua.uri_list FROM uri_agg ua
                                            WHERE ua.entra_object_id = a.entra_object_id AND ua.kind = 'wildcard'),
                'http_redirect_uris', (SELECT ua.uri_list FROM uri_agg ua
                                        WHERE ua.entra_object_id = a.entra_object_id AND ua.kind = 'http'),
                'shared_hosting_redirect_uris', (SELECT ua.uri_list FROM uri_agg ua
                                                  WHERE ua.entra_object_id = a.entra_object_id AND ua.kind = 'shared_host'),
                'implicit_access_token_issuance', a.implicit_access_token_issuance,
                'is_fallback_public_client', a.is_fallback_public_client,
                'privileged', COALESCE(ap.privileged, false),
                'privileges', ap.privilege_text,
                'privilege_known', COALESCE(ap.privilege_known, false)
            ) AS detail
        FROM agg g
        JOIN entra_application a ON a.client_id = %(client_id)s AND a.entra_object_id = g.entra_object_id
        LEFT JOIN app_priv ap ON ap.entra_object_id = g.entra_object_id
    """.replace("@TIER0@", TIER0_ROLES_SQL.strip())
       .replace("@PERMS@", PRIVILEGED_APP_PERMISSIONS_SQL.strip())
       .replace("@PRIVSP@", PRIVILEGED_SP_SQL.strip()),
}

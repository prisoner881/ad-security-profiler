"""
Plugin 10063: High-Risk Delegated Permissions Granted to an Application

Reports applications holding delegated permission grants
(oauth2PermissionGrants) that include high-risk scopes, either tenant-wide
(admin consent, consentType 'AllPrincipals') or consented by individual
users (consentType 'Principal'). One finding per client application
(service principal), aggregating its grants.

High-risk scopes (on any resource API): Mail.ReadWrite, Mail.Send,
Mail.Read, MailboxSettings.ReadWrite, Files.ReadWrite.All,
Sites.ReadWrite.All, Sites.FullControl.All, Directory.AccessAsUser.All,
Directory.ReadWrite.All, User.ReadWrite.All, full_access_as_user,
EWS.AccessAsUser.All, Application.ReadWrite.All,
RoleManagement.ReadWrite.Directory. offline_access (refresh tokens: access
that persists without the user) is reported in detail when the same
application also holds it.

Why it matters: illicit consent grant / consent phishing (MITRE T1528)
gives an attacker's application persistent access to mailboxes and files
that survives password resets and MFA, because the application holds its
own refresh tokens. Tenant-wide grants expose every user; the directory
scopes act with the signed-in user's full rights (an administrator's, when
one uses the app). CISA SCuBA MS.AAD.5.2 restricts consent to
administrators.

Severity (status 'fail'):
- high: any high-risk scope granted tenant-wide (AllPrincipals);
- medium: high-risk scopes granted only by individual users (the number of
  users and a sample are in detail);
- one level higher (up to critical) when the client is a third-party
  application (owner tenant neither Microsoft nor this tenant) with no
  verified publisher -- only judged when source service_principals is 'ok'.
Excluded: Microsoft first-party client applications (appOwnerOrganizationId
f8cdef31-a31e-4b4a-93e4-5f571e91255a / 72f988bf-86f1-41af-91ab-2d7cd011db47),
which need these grants for Microsoft's own portals and tools -- only
excluded when the client's service principal was collected.

Data: entra_delegated_grant (source delegated_grants, required);
entra_service_principal for owner tenant / publisher (enrichment); this
tenant's id from entra_tenant_setting 'organization' (when absent, inferred
from the owner tenant of this tenant's own app registrations' service
principals; a client whose appId matches one of this tenant's app
registrations always counts as this tenant's own). Identity = the client service principal's object id.
"""

PLUGIN = {
    "plugin_id": 10063,
    "category": "Hybrid Identity",
    "name": "High-Risk Delegated Permissions Granted to an Application",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "HYBRID-10063",
    "requires_sources": ["delegated_grants"],
    "framework_tags": [
        "CISA-SCUBA-MS.AAD.5.2",
        "NIST-800-53-AC-6",
        "NIST-800-53-CM-11",
        "NIST-800-53-CM-7",
        "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-7.2.1",
        "CIS-CSC-8-6.7",
        "ISO-27001-2022-A.5.23",
        "SOC2-CC6.3",
        "MITRE-ATTCK-T1528",
    ],
    "references": [
        {"title": "Microsoft: Detect and remediate illicit consent grants",
         "url": "https://learn.microsoft.com/en-us/defender-office-365/detect-and-remediate-illicit-consent-grants"},
        {"title": "Microsoft Graph: oAuth2PermissionGrant resource type",
         "url": "https://learn.microsoft.com/en-us/graph/api/resources/oauth2permissiongrant"},
        {"title": "CISA SCuBA Microsoft Entra ID baseline (MS.AAD.5.2)",
         "url": "https://github.com/cisagov/ScubaGear/blob/main/PowerShell/ScubaGear/baselines/aad.md"},
        {"title": "MITRE ATT&CK T1528: Steal Application Access Token",
         "url": "https://attack.mitre.org/techniques/T1528/"},
    ],
    "description": (
        "An application holds delegated permissions with high-risk scopes "
        "(mail read/send, all files and sites, directory write or "
        "act-as-user, Exchange full access, application or role "
        "management): granted tenant-wide by an administrator (high) or "
        "consented by individual users (medium), one level higher for a "
        "third-party application without a verified publisher. Consent "
        "phishing uses exactly these grants for persistent access that "
        "survives password resets and MFA. Microsoft first-party "
        "applications are excluded; one finding per application."
    ),
    "remediation": (
        "Review each application: Entra admin center -> Enterprise "
        "applications -> the app -> Permissions (admin consent and user "
        "consent tabs). If the application is not recognised or no longer "
        "needed, revoke the grants (Remove-MgOauth2PermissionGrant) and "
        "disable or delete the service principal, then review its "
        "sign-ins and the mailbox and file access it performed. Where it "
        "is needed, reduce scopes to the least privilege (e.g. Mail.Read "
        "instead of Mail.ReadWrite, Sites.Selected instead of "
        "Sites.ReadWrite.All). Restrict user consent to verified "
        "publishers and low-risk permissions or disable it, and enable "
        "the admin consent workflow."
    ),
    "base_severity": "high",
    "query": """
        WITH risky(scope_lc) AS (
            VALUES ('mail.readwrite'), ('mail.send'), ('mail.read'), ('mailboxsettings.readwrite'),
                   ('files.readwrite.all'), ('sites.readwrite.all'), ('sites.fullcontrol.all'),
                   ('directory.accessasuser.all'), ('directory.readwrite.all'), ('user.readwrite.all'),
                   ('full_access_as_user'), ('ews.accessasuser.all'), ('application.readwrite.all'),
                   ('rolemanagement.readwrite.directory')
        ),
        sp_ok AS (
            SELECT EXISTS (SELECT 1 FROM entra_collection_status s
                            WHERE s.client_id = %(client_id)s
                              AND s.source = 'service_principals' AND s.status = 'ok') AS ok
        ),
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
                           AND s.app_owner_organization_id NOT IN ('f8cdef31-a31e-4b4a-93e4-5f571e91255a'::uuid, '72f988bf-86f1-41af-91ab-2d7cd011db47'::uuid)
                         GROUP BY s.app_owner_organization_id
                         ORDER BY count(*) DESC, s.app_owner_organization_id
                         LIMIT 1)) AS tenant_id
        ),
        scoped AS (
            SELECT dg.client_sp_id, dg.client_display_name, dg.consent_type, dg.principal_id,
                   dg.principal_upn, (s.scope) COLLATE "C" AS scope,
                   EXISTS (SELECT 1 FROM risky r WHERE r.scope_lc = lower(s.scope)) AS is_risky
              FROM entra_delegated_grant dg
              CROSS JOIN LATERAL unnest(dg.scopes) AS s(scope)
             WHERE dg.client_id = %(client_id)s
        ),
        per_client AS (
            SELECT sc.client_sp_id,
                   min(sc.client_display_name) AS client_display_name,
                   bool_or(sc.is_risky AND sc.consent_type = 'AllPrincipals') AS tenant_wide,
                   string_agg(DISTINCT sc.scope, ', ' ORDER BY sc.scope)
                       FILTER (WHERE sc.is_risky AND sc.consent_type = 'AllPrincipals') AS tenant_scopes,
                   string_agg(DISTINCT sc.scope, ', ' ORDER BY sc.scope)
                       FILTER (WHERE sc.is_risky AND sc.consent_type IS DISTINCT FROM 'AllPrincipals') AS user_scopes,
                   count(DISTINCT COALESCE(sc.principal_id::text, sc.principal_upn))
                       FILTER (WHERE sc.is_risky AND sc.consent_type IS DISTINCT FROM 'AllPrincipals') AS user_count,
                   (array_agg(DISTINCT COALESCE(sc.principal_upn, sc.principal_id::text) COLLATE "C"
                              ORDER BY COALESCE(sc.principal_upn, sc.principal_id::text) COLLATE "C")
                       FILTER (WHERE sc.is_risky AND sc.consent_type IS DISTINCT FROM 'AllPrincipals'
                                 AND COALESCE(sc.principal_upn, sc.principal_id::text) IS NOT NULL))[1:10]
                       AS user_sample,
                   bool_or(lower(sc.scope) = 'offline_access') AS offline_access
              FROM scoped sc
             GROUP BY sc.client_sp_id
            HAVING bool_or(sc.is_risky)
        ),
        classified AS (
            SELECT pc.*, sp.app_id, sp.app_owner_organization_id, sp.verified_publisher_name,
                   sp.entra_object_id IS NOT NULL AS sp_known,
                   CASE WHEN sp.entra_object_id IS NULL THEN 'unknown'
                        WHEN sp.app_owner_organization_id IN ('f8cdef31-a31e-4b4a-93e4-5f571e91255a'::uuid,
                                                              '72f988bf-86f1-41af-91ab-2d7cd011db47'::uuid)
                        THEN 'microsoft'
                        WHEN sp.app_owner_organization_id = (SELECT t.tenant_id FROM tenant t)
                          OR EXISTS (SELECT 1 FROM entra_application a
                                      WHERE a.client_id = %(client_id)s AND a.app_id = sp.app_id)
                        THEN 'this_tenant'
                        WHEN sp.app_owner_organization_id IS NOT NULL THEN 'third_party'
                        ELSE 'unknown' END AS owner_class
              FROM per_client pc
              LEFT JOIN entra_service_principal sp
                     ON sp.client_id = %(client_id)s AND sp.entra_object_id = pc.client_sp_id
        ),
        graded AS (
            SELECT c.*,
                   (c.owner_class = 'third_party' AND c.verified_publisher_name IS NULL
                    AND (SELECT ok FROM sp_ok)) AS unverified_third_party,
                   least(4, CASE WHEN c.tenant_wide THEN 3 ELSE 2 END
                            + CASE WHEN c.owner_class = 'third_party' AND c.verified_publisher_name IS NULL
                                        AND (SELECT ok FROM sp_ok) THEN 1 ELSE 0 END) AS sev_rank
              FROM classified c
             WHERE c.owner_class <> 'microsoft'
        )
        SELECT
            'fail' AS status,
            g.client_sp_id AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE g.sev_rank WHEN 4 THEN 'critical' WHEN 3 THEN 'high' ELSE 'medium' END AS fd_severity,
            'Application "' || COALESCE(g.client_display_name, g.client_sp_id::text) || '"'
                || CASE WHEN g.unverified_third_party THEN ' (third-party, no verified publisher)'
                        WHEN g.owner_class = 'third_party' THEN ' (third-party)' ELSE '' END
                || ' holds high-risk delegated permissions: '
                || concat_ws('; ',
                       CASE WHEN g.tenant_scopes IS NOT NULL
                            THEN 'tenant-wide admin consent for ' || g.tenant_scopes END,
                       CASE WHEN g.user_scopes IS NOT NULL
                            THEN 'user consent for ' || g.user_scopes END) AS summary,
            jsonb_build_object(
                'client_service_principal_id', g.client_sp_id,
                'client_display_name', g.client_display_name,
                'app_id', g.app_id,
                'owner', g.owner_class,
                'app_owner_organization_id', g.app_owner_organization_id,
                'verified_publisher_name', g.verified_publisher_name,
                'service_principal_collected', g.sp_known,
                'tenant_wide', g.tenant_wide,
                'tenant_wide_scopes', g.tenant_scopes,
                'user_consent_scopes', g.user_scopes,
                'user_consent_count', g.user_count,
                'user_consent_sample', to_jsonb(COALESCE(g.user_sample, ARRAY[]::text[])),
                'offline_access', g.offline_access
            ) AS detail
        FROM graded g
    """,
}

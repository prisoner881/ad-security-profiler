"""
Plugin 10125: Application Sign-Ins Not Covered by Conditional Access (Workload Identities)

Conditional Access policies for users do not apply when an application
signs in as itself with a client secret or certificate (sign-in status
"notApplied"). October-November 2026 brought a run of such sign-ins:
  * Storm-0940 / ConnectWise Cloud Backup (Microsoft Threat Intelligence,
    2026-10-21): app-only tokens against more than 2,250 tenants;
  * stolen client secrets harvested from public code repositories and
    used to sign in as service principals from about 2026-10-28
    (Microsoft Threat Intelligence 2026-11-05, Todyl 2026-11-03);
  * the MSP Process vendor breach (Field Effect, 2026-11-11).
Microsoft's guidance is Conditional Access for workload identities: block
service principals by location (named locations) or when ID Protection
rates them risky (servicePrincipalRiskLevels). It needs Microsoft Entra
Workload ID Premium and covers single-tenant applications (this tenant's
own app registrations), not multi-tenant third-party applications or
managed identities.

Assessed when this tenant's own app registrations hold a client secret or
certificate (they can sign in as themselves). "Covered" = an enabled
policy whose conditions.clientApplications.includeServicePrincipals is not
empty. One finding per tenant (identity md5('10125:' || client_id)):
  * medium 'fail': Workload ID Premium is licensed and no enabled policy
    targets service principals;
  * low 'warn': not licensed (or licences not read) -- the control needs
    the licence; the detail lists the apps that would be in scope.

Data: entra_tenant_setting 'ca_policies_beta', entra_application,
v_entra_tenant_capability. Related: 10005 / 10060 / 10061 (credential
hygiene), 10076 (app management policy), 10066 (dormant privileged
applications).
"""

PLUGIN = {
    "plugin_id": 10125,
    "category": "Hybrid Identity",
    "name": "Application Sign-Ins Not Covered by Conditional Access (Workload Identities)",
    "version": "1.0",
    "revision_date": "2026-11-20",
    "control_id": "HYBRID-10125",
    "requires_sources": ["ca_policies_beta"],
    "framework_tags": [
        "NIST-800-53-AC-2",
        "NIST-800-53-AC-3",
        "NIST-800-53-IA-2",
        "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-8.6.1",
        "CIS-CSC-8-6.7",
        "ISO-27001-2022-A.5.15",
        "SOC2-CC6.1",
        "MITRE-ATTCK-T1078.004",
    ],
    "references": [
        {"title": "Microsoft Threat Intelligence: Threat actors use agentic AI tooling to find and abuse exposed secrets (2026-11-05)",
         "url": "https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-ai-tooling-to-find-and-abuse-exposed-secrets/"},
        {"title": "Microsoft Learn: Conditional Access for workload identities",
         "url": "https://learn.microsoft.com/en-us/entra/identity/conditional-access/workload-identity"},
        {"title": "MITRE ATT&CK T1078.004: Valid Accounts: Cloud Accounts",
         "url": "https://attack.mitre.org/techniques/T1078/004/"},
    ],
    "description": (
        "This tenant's own applications hold client secrets or certificates, but no enabled "
        "Conditional Access policy targets service principals, so an application signing in with "
        "a stolen secret is not restricted by location or risk. Stolen application secrets were "
        "used at scale in October-November 2026. Medium when Workload ID Premium is licensed; low "
        "when it is not (the control needs the licence)."
    ),
    "remediation": (
        "With Workload ID Premium: create a Conditional Access policy for workload identities that "
        "targets this tenant's service principals (assign them directly; group assignment does "
        "not apply to service principals) and blocks sign-ins from outside the named locations "
        "they use, and a second one that blocks high service-principal risk. Start in report-only "
        "mode and review the service principal sign-in logs. Without the licence: remove unused "
        "credentials, prefer certificates or federated credentials to client secrets, shorten "
        "secret lifetimes with an app management policy (plugin 10076), and alert on service "
        "principal sign-ins from new locations."
    ),
    "base_severity": "medium",
    "query": """
        WITH
        ts AS (
            SELECT t.content
              FROM entra_tenant_setting t
             WHERE t.client_id = %(client_id)s
               AND t.setting_name = 'ca_policies_beta'
               AND jsonb_typeof(t.content) = 'array'
        ),
        pol AS (
            SELECT p->>'display_name' AS name, p->>'state' AS state
              FROM ts CROSS JOIN LATERAL jsonb_array_elements(ts.content) p
             WHERE jsonb_typeof(p->'conditions'->'clientApplications'->'includeServicePrincipals') = 'array'
               AND jsonb_array_length(p->'conditions'->'clientApplications'->'includeServicePrincipals') > 0
        ),
        apps AS (
            SELECT a.app_id, a.display_name,
                   CASE WHEN jsonb_typeof(a.password_credentials) = 'array'
                        THEN jsonb_array_length(a.password_credentials) ELSE 0 END AS secrets,
                   COALESCE(a.key_credential_count, 0) AS certificates
              FROM entra_application a
             WHERE a.client_id = %(client_id)s
        ),
        in_scope AS (
            SELECT * FROM apps WHERE secrets > 0 OR certificates > 0
        ),
        lic AS (
            SELECT bool_or(c.license_status = 'ok' AND c.has_workload_id) AS licensed,
                   bool_or(c.license_status = 'ok') AS licences_read
              FROM v_entra_tenant_capability c
             WHERE c.client_id = %(client_id)s
        ),
        summary AS (
            SELECT (SELECT count(*) FROM in_scope) AS app_count,
                   (SELECT count(*) FROM in_scope WHERE secrets > 0) AS secret_app_count,
                   (SELECT jsonb_agg(jsonb_build_object('app', COALESCE(display_name, app_id::text),
                                                        'app_id', app_id, 'client_secrets', secrets,
                                                        'certificates', certificates)
                                     ORDER BY secrets DESC, display_name)
                      FROM (SELECT * FROM in_scope ORDER BY secrets DESC, display_name LIMIT 50) x) AS apps,
                   (SELECT count(*) FROM pol WHERE state = 'enabled') AS enabled_policies,
                   (SELECT jsonb_agg(jsonb_build_object('policy', name, 'state', state)) FROM pol)
                       AS workload_policies,
                   COALESCE((SELECT licensed FROM lic), false) AS licensed,
                   COALESCE((SELECT licences_read FROM lic), false) AS licences_read
        )
        SELECT
            CASE WHEN s.licensed THEN 'fail' ELSE 'warn' END AS status,
            md5('10125:' || %(client_id)s::text)::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN s.licensed THEN 'medium' ELSE 'low' END AS fd_severity,
            'No enabled Conditional Access policy covers application (service principal) sign-ins, while '
                || s.app_count || ' of this tenant''s applications can sign in with their own credentials ('
                || s.secret_app_count || ' with client secrets)'
                || CASE WHEN s.licensed THEN ''
                        WHEN s.licences_read THEN '; Workload ID Premium, which these policies need, is not licensed'
                        ELSE '; licences were not read' END AS summary,
            jsonb_build_object(
                'applications_with_credentials', s.app_count,
                'applications_with_client_secrets', s.secret_app_count,
                'applications', COALESCE(s.apps, '[]'::jsonb),
                'workload_id_premium_licensed', s.licensed,
                'licences_read', s.licences_read,
                'policies_targeting_service_principals', COALESCE(s.workload_policies, '[]'::jsonb),
                'note', 'Conditional Access for workload identities covers single-tenant applications '
                        'and service principals assigned directly; multi-tenant applications and '
                        'managed identities are out of its scope.'
            ) AS detail
        FROM summary s
        WHERE s.app_count > 0 AND s.enabled_policies = 0
    """,
}

"""
Plugin 10076: App Management Policy Does Not Restrict Application Credentials

Reads the tenant-wide default app management policy
(/policies/defaultAppManagementPolicy, entra_tenant_setting
'app_management_policy', source app_management_policy,
entra_graph_collector 0.9.0) and reports each credential restriction that
is not enforced for application registrations
(applicationRestrictions):

- password (client secret) addition not blocked -- restrictionType
  'passwordAddition' (CISA SCuBA MS.AAD.5.5);
- password lifetime not limited to 180 days or less -- 'passwordLifetime'
  with maxLifetime <= P180D (MS.AAD.5.6);
- certificate lifetime not limited to 365 days or less --
  'asymmetricKeyLifetime' in keyCredentials with maxLifetime <= P365D
  (MS.AAD.5.7);
- custom (user-chosen) passwords not blocked -- 'customPasswordAddition'.

A restriction counts when the policy's isEnabled is true and the
restriction's state is 'enabled' (restrictForAppsCreatedAfterDateTime is
shown in detail: a restriction dated in the future, or applying only to
apps created after a date, leaves older apps unrestricted). Why: client
secrets are the credential behind most application takeovers and
persistence (Midnight Blizzard 2024, the Commvault Metallic secret, CISA
AA26-237A); blocking new secrets and bounding credential lifetimes is
Microsoft's own recommendation (Baseline Security Mode).

fail / medium, one tenant-level row listing every gap (object_guid
md5('10076:' || client_id)). Service principal restrictions are listed in
detail but not judged. Needs Microsoft Entra Workload ID licensing for
some restriction types in production; the policy itself can be read and
set in every tenant.

[v1.1] When adding client secrets is blocked (passwordAddition enforced),
the client secret lifetime and custom secret restrictions are not listed as
gaps: no new client secret can be added, so they constrain nothing. Existing
secrets are reported by the credential plugins (10060 and others).
"""

PLUGIN = {
    "plugin_id": 10076,
    "category": "Hybrid Identity",
    "name": "App Management Policy Does Not Restrict Application Credentials",
    "version": "1.1",
    "revision_date": "2026-10-30",
    "control_id": "HYBRID-10076",
    "requires_sources": ["app_management_policy"],
    "framework_tags": [
        "CISA-SCUBA-MS.AAD.5.5",
        "CISA-SCUBA-MS.AAD.5.6",
        "CISA-SCUBA-MS.AAD.5.7",
        "NIST-800-53-IA-5(1)",
        "NIST-800-53-IA-5(2)",
        "NIST-800-53-SC-12",
        "NIST-CSF-2.0-PR.AA-01",
        "CIS-CSC-8-5.2",
        "ISO-27001-2022-A.5.17",
        "SOC2-CC6.1",
        "MITRE-ATTCK-T1098.001",
    ],
    "references": [
        {"title": "CISA SCuBA Microsoft Entra ID baseline (MS.AAD.5.5 - 5.7)",
         "url": "https://github.com/cisagov/ScubaGear/blob/main/PowerShell/ScubaGear/baselines/aad.md"},
        {"title": "Microsoft: Configure app management policies (restrict application credentials)",
         "url": "https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-app-management-policies"},
        {"title": "Microsoft Graph: tenantAppManagementPolicy resource type",
         "url": "https://learn.microsoft.com/en-us/graph/api/resources/tenantappmanagementpolicy"},
        {"title": "MITRE ATT&CK T1098.001: Account Manipulation: Additional Cloud Credentials",
         "url": "https://attack.mitre.org/techniques/T1098/001/"},
    ],
    "description": (
        "The tenant's default app management policy does not block client-secret "
        "creation, limit secret lifetime to 180 days, limit certificate lifetime to 365 "
        "days, or block custom passwords for application registrations (CISA SCuBA "
        "MS.AAD.5.5 - 5.7). Long-lived and newly added secrets are the usual way "
        "attackers take over or persist through applications."
    ),
    "remediation": (
        "Entra admin center > Enterprise applications > Application policies (or Graph "
        "PATCH /policies/defaultAppManagementPolicy): set isEnabled = true and, under "
        "applicationRestrictions, add passwordAddition (enabled), passwordLifetime "
        "(maxLifetime P180D or less), customPasswordAddition (enabled) and, under "
        "keyCredentials, asymmetricKeyLifetime (maxLifetime P365D or less). Use "
        "restrictForAppsCreatedAfterDateTime to phase existing applications in, and "
        "move applications to certificates or federated identity credentials."
    ),
    "base_severity": "medium",
    "query": """
        WITH pol AS (
            SELECT ts.client_id, ts.content,
                   COALESCE(ts.content->>'isEnabled' = 'true', false) AS enabled
              FROM entra_tenant_setting ts
             WHERE ts.client_id = %(client_id)s
               AND ts.setting_name = 'app_management_policy'
               AND jsonb_typeof(ts.content) = 'object'
        ),
        r AS (
            SELECT p.client_id, x->>'restrictionType' AS rtype, lower(x->>'state') AS state,
                   x->>'maxLifetime' AS max_lifetime,
                   (SELECT COALESCE(m[1]::numeric, 0) * 365 + COALESCE(m[2]::numeric, 0) * 30
                           + COALESCE(m[3]::numeric, 0) * 7 + COALESCE(m[4]::numeric, 0)
                      FROM regexp_match(upper(x->>'maxLifetime'),
                                        '^P(?:([0-9]+)Y)?(?:([0-9]+)M)?(?:([0-9]+)W)?(?:([0-9]+)D)?(?:T.*)?$') m
                     WHERE m IS NOT NULL) AS max_days
              FROM pol p
              CROSS JOIN LATERAL (
                  SELECT jsonb_array_elements(CASE WHEN jsonb_typeof(p.content->'applicationRestrictions'->'passwordCredentials') = 'array'
                                                   THEN p.content->'applicationRestrictions'->'passwordCredentials'
                                                   ELSE '[]'::jsonb END)
                  UNION ALL
                  SELECT jsonb_array_elements(CASE WHEN jsonb_typeof(p.content->'applicationRestrictions'->'keyCredentials') = 'array'
                                                   THEN p.content->'applicationRestrictions'->'keyCredentials'
                                                   ELSE '[]'::jsonb END)
              ) q(x)
        ),
        checks(ord, rtype, max_days, label) AS (
            VALUES (1, 'passwordAddition', NULL::numeric, 'adding client secrets is not blocked (SCuBA MS.AAD.5.5)'),
                   (2, 'passwordLifetime', 180, 'client secret lifetime is not limited to 180 days (SCuBA MS.AAD.5.6)'),
                   (3, 'asymmetricKeyLifetime', 365, 'certificate lifetime is not limited to 365 days (SCuBA MS.AAD.5.7)'),
                   (4, 'customPasswordAddition', NULL, 'custom (user-chosen) client secrets are not blocked')
        ),
        missing AS (
            SELECT p.client_id, c.ord, c.label
              FROM pol p CROSS JOIN checks c
             WHERE NOT p.enabled
                OR NOT EXISTS (SELECT 1 FROM r
                                WHERE r.client_id = p.client_id AND r.rtype = c.rtype AND r.state = 'enabled'
                                  AND (c.max_days IS NULL OR r.max_days <= c.max_days))
        ),
        gaps AS (
            -- [v1.1] with adding client secrets blocked, their lifetime and
            -- custom secrets do not matter for new credentials
            SELECT m.* FROM missing m
             WHERE m.ord NOT IN (2, 4)
                OR EXISTS (SELECT 1 FROM missing b WHERE b.client_id = m.client_id AND b.ord = 1)
        )
        SELECT
            'fail' AS status,
            md5('10076:' || p.client_id::text)::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'medium' AS fd_severity,
            'Application credential restrictions not enforced'
                || CASE WHEN NOT p.enabled THEN ' (the default app management policy is disabled)' ELSE '' END
                || ': ' || string_agg(g.label, '; ' ORDER BY g.ord) AS summary,
            jsonb_build_object(
                'policy_enabled', p.enabled,
                'gaps', jsonb_agg(g.label ORDER BY g.ord),
                'application_restrictions', p.content->'applicationRestrictions',
                'service_principal_restrictions', p.content->'servicePrincipalRestrictions'
            ) AS detail
        FROM gaps g
        JOIN pol p ON p.client_id = g.client_id
        GROUP BY p.client_id, p.enabled, p.content
    """,
}

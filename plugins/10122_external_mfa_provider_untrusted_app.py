"""
Plugin 10122: External MFA Provider Backed by an Untrusted Application (TrustSink)

An external authentication method (EAM, Graph
externalAuthenticationMethodConfiguration) makes Entra ID hand the user to a
third-party provider for the MFA step and accept the signed token it sends
back. Varonis's "TrustSink" research (September 2026) showed that an
attacker who already holds Global Administrator or Authentication Policy
Administrator can register a rogue provider: it shows a copy of the
Microsoft password page during the MFA step, collects the plaintext
password of every covered user at each normal sign-in, and returns a valid
token so nothing looks wrong. A password reset does not evict it; the
provider must be removed first. It builds on Dirk-jan Mollema's 2025
finding that a rogue EAM can satisfy MFA without any real check.

Setting one up needs an application and its service principal in the
tenant. Genuine EAM vendors (Cisco Duo, Okta, Ping, RSA and others) publish
multi-tenant applications from their own tenants with a verified publisher;
a provider backed by an application registered in this tenant is the
TrustSink pattern. Plugin 10049 already reports every enabled EAM that
covers privileged users; this plugin asks whether the provider itself can
be trusted, whoever it covers.

One finding per enabled external method (identity md5('10122:' ||
client_id || ':' || method id)):
  * fail / high: its appId is an application registered in this tenant
    (entra_application), or its service principal is owned by this tenant
    (app_owner_organization_id = this tenant's id, read from the
    organization setting or, failing that, from the tenant's own apps as
    plugin 10065 does);
  * fail / high: no service principal with its appId exists -- the method
    points at an application that is not (or no longer) in the tenant;
  * warn / medium: the service principal is a third-party application
    without a verified publisher;
  * not reported: a third-party application with a verified publisher, or
    a Microsoft first-party application.
The detail shows the discovery URL and its host, the publisher, the owner
tenant and the method's targets.

Data: entra_tenant_setting 'auth_methods_policy' (source
auth_methods_policy) and 'organization', entra_service_principal (source
service_principals), entra_application.
"""

PLUGIN = {
    "plugin_id": 10122,
    "category": "Hybrid Identity",
    "name": "External MFA Provider Backed by an Untrusted Application (TrustSink)",
    "version": "1.0",
    "revision_date": "2026-11-01",
    "control_id": "HYBRID-10122",
    "requires_sources": ["auth_methods_policy", "service_principals"],
    "framework_tags": [
        "NIST-800-53-IA-2(1)",
        "NIST-800-53-AC-20",
        "NIST-800-53-CM-3",
        "NIST-CSF-2.0-PR.AA-03",
        "NIST-CSF-2.0-DE.CM-09",
        "CIS-CSC-8-6.5",
        "ISO-27001-2022-A.5.19",
        "SOC2-CC6.1",
        "MITRE-ATTCK-T1556.006",
        "MITRE-ATTCK-T1556.007",
        "MITRE-ATTCK-T1056.003",
    ],
    "references": [
        {"title": "Varonis: TrustSink -- How a Rogue External MFA Provider Steals Passwords",
         "url": "https://www.varonis.com/blog/trustsink"},
        {"title": "BleepingComputer: Rogue external MFA providers can steal passwords during logins",
         "url": "https://www.bleepingcomputer.com/news/security/rogue-external-mfa-providers-can-steal-passwords-during-logins/"},
        {"title": "Microsoft: Manage an external authentication method in Microsoft Entra ID",
         "url": "https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-authentication-external-method-manage"},
        {"title": "MITRE ATT&CK T1556.006: Modify Authentication Process: Multi-Factor Authentication",
         "url": "https://attack.mitre.org/techniques/T1556/006/"},
    ],
    "description": (
        "An enabled external MFA provider (external authentication method) is backed by an "
        "application registered in this tenant, by an application with no service principal, or "
        "by a third-party application without a verified publisher. Genuine providers are "
        "verified multi-tenant applications from their vendor's tenant; a provider registered "
        "in the tenant itself is how the TrustSink technique (Varonis, September 2026) captures "
        "the password of every covered user at sign-in. High for a home-tenant or missing "
        "application, medium for an unverified publisher."
    ),
    "remediation": (
        "Confirm with the identity team that the provider is expected and identify its vendor. "
        "If it is not expected, treat the tenant as compromised: remove the external method from "
        "the authentication methods policy and delete its application, service principal, "
        "credentials, redirect URIs and consent grants FIRST, then reset the passwords of every "
        "user the method covered and revoke their sessions (a reset alone leaves the collector "
        "in place), and review the Entra audit log ('Update authentication methods policy', "
        "'Add external authentication method', role assignments) for who added it. If it is "
        "expected, use the vendor's published multi-tenant application rather than a local "
        "registration. Limit standing Global Administrator and Authentication Policy "
        "Administrator assignments, alert on changes to the authentication methods policy "
        "(plugin 11026), and require a phishing-resistant authentication strength for "
        "administrators, which an external method does not satisfy."
    ),
    "base_severity": "high",
    "query": """
        WITH
        tenant AS (
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
        ext AS (
            SELECT ts.client_id, c AS cfg,
                   lower(COALESCE(c->>'appId', '')) AS app_id_text
              FROM entra_tenant_setting ts
              CROSS JOIN LATERAL jsonb_array_elements(
                  CASE WHEN jsonb_typeof(ts.content->'authenticationMethodConfigurations') = 'array'
                       THEN ts.content->'authenticationMethodConfigurations' ELSE '[]'::jsonb END) c
             WHERE ts.client_id = %(client_id)s
               AND ts.setting_name = 'auth_methods_policy'
               AND c->>'@odata.type' = '#microsoft.graph.externalAuthenticationMethodConfiguration'
               AND lower(COALESCE(c->>'state', '')) = 'enabled'
        ),
        judged AS (
            SELECT e.*, sp.display_name AS sp_name, sp.publisher_name, sp.verified_publisher_name,
                   sp.app_owner_organization_id, sp.account_enabled,
                   (sp.entra_object_id IS NOT NULL) AS has_sp,
                   EXISTS (SELECT 1 FROM entra_application a
                            WHERE a.client_id = e.client_id AND lower(a.app_id::text) = e.app_id_text) AS local_app,
                   (sp.app_owner_organization_id IS NOT NULL
                    AND sp.app_owner_organization_id = (SELECT tenant_id FROM tenant)) AS owned_here,
                   COALESCE(sp.app_owner_organization_id IN @MSTENANTS@, false) AS microsoft_app,
                   substring(e.cfg->'openIdConnectSetting'->>'discoveryUrl' from '^[a-zA-Z]+://([^/:]+)')
                       AS discovery_host
              FROM ext e
              LEFT JOIN LATERAL (
                  SELECT s.* FROM entra_service_principal s
                   WHERE s.client_id = e.client_id AND lower(s.app_id::text) = e.app_id_text
                   ORDER BY s.entra_object_id
                   LIMIT 1) sp ON true
        ),
        graded AS (
            SELECT j.*,
                   CASE WHEN j.local_app OR j.owned_here THEN 'home_tenant'
                        WHEN NOT j.has_sp THEN 'no_service_principal'
                        WHEN NOT j.microsoft_app AND COALESCE(j.verified_publisher_name, '') = ''
                             THEN 'unverified_publisher' END AS reason
              FROM judged j
        )
        SELECT
            CASE WHEN g.reason = 'unverified_publisher' THEN 'warn' ELSE 'fail' END AS status,
            md5('10122:' || g.client_id::text || ':' || lower(COALESCE(g.cfg->>'id', '')))::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN g.reason = 'unverified_publisher' THEN 'medium' ELSE 'high' END AS fd_severity,
            'External MFA method "' || COALESCE(g.cfg->>'displayName', g.cfg->>'id') || '" ('
                || COALESCE(g.discovery_host, 'no discovery URL') || ') '
                || CASE g.reason
                       WHEN 'home_tenant' THEN 'is backed by an application registered in this tenant ('
                            || COALESCE(g.sp_name, g.cfg->>'appId') || '), not a vendor''s multi-tenant '
                            || 'application: the pattern of a rogue provider that collects passwords at '
                            || 'sign-in (TrustSink)'
                       WHEN 'no_service_principal' THEN 'points at application ' || COALESCE(g.cfg->>'appId', '?')
                            || ', which has no service principal in this tenant'
                       ELSE 'is backed by third-party application "' || COALESCE(g.sp_name, g.cfg->>'appId')
                            || '" without a verified publisher' END AS summary,
            jsonb_build_object(
                'method_id', g.cfg->>'id',
                'display_name', g.cfg->>'displayName',
                'app_id', g.cfg->>'appId',
                'reason', g.reason,
                'discovery_url', g.cfg->'openIdConnectSetting'->>'discoveryUrl',
                'discovery_host', g.discovery_host,
                'service_principal_name', g.sp_name,
                'service_principal_enabled', g.account_enabled,
                'publisher_name', g.publisher_name,
                'verified_publisher_name', g.verified_publisher_name,
                'app_owner_organization_id', g.app_owner_organization_id,
                'registered_in_this_tenant', g.local_app OR g.owned_here,
                'include_targets', g.cfg->'includeTargets',
                'exclude_targets', g.cfg->'excludeTargets'
            ) AS detail
        FROM graded g
        WHERE g.reason IS NOT NULL
    """.replace("@MSTENANTS@",
                "('f8cdef31-a31e-4b4a-93e4-5f571e91255a'::uuid, '72f988bf-86f1-41af-91ab-2d7cd011db47'::uuid)"),
}

"""
Plugin 10124: Vendor Application Known to Have Been Abused Across Tenants (ConnectWise / SkyKick)

In October 2026 an attacker took control of the identities of ConnectWise
Cloud Backup (formerly SkyKick) and its sibling "Cloud Management"
multi-tenant applications and used their app-only tokens against customer
tenants (Huntress 2026-10-16: about 1,000 tenants saw sign-in attempts,
over 300 succeeded; Microsoft Threat Intelligence 2026-10-21, Storm-0940:
more than 2,250 tenants targeted). Follow-on activity included adding
credentials to other applications, changing users, groups and roles, one
application assigning itself Global Administrator, and bulk Key Vault
secret reads -- in several cases within three hours. No Microsoft
vulnerability was involved: the applications' own permissions were used.

This check looks for the service principals of those applications
(matched by appId, because older installations still show SkyKick names)
or of any other application published by the same vendor tenant
(appOwnerOrganizationId 3f9cd7a0-127a-4ed4-bf06-2f830d5616b7). AppIds and
tenant from SpecterOps (2026-10-17) and Huntress (2026-10-16); AppGov Score
(2026-10-30) lists the same seven. Extend KNOWN_ABUSED_APPS as further
incidents publish identifiers (the MSP Process incident of November 2026,
Field Effect 2026-11-11, published names only).

One finding per service principal:
  * critical 'fail': enabled;
  * high 'warn': disabled (keep it disabled, not deleted, while the
    investigation needs its sign-in and audit history).
The detail adds the application permissions it holds on Microsoft Graph,
Exchange Online or SharePoint Online and its directory roles.

Data: entra_service_principal, entra_app_role_grant,
entra_directory_role_member. Identity = the service principal's object
id. Related: 10065 (third-party privileged applications), 10060
(credentials on service principals), 11023 (new credentials).
"""

# (appId, name as published, source)
KNOWN_ABUSED_APPS_SQL = """
        known(app_id, app_name, incident) AS (
            VALUES ('506e08f9-6e9a-4da4-942b-a099a03644ae'::uuid, 'ConnectWise Cloud Backup (formerly SkyKick Backup)', 'ConnectWise / SkyKick, October 2026'),
                   ('2399d300-6fca-4e6a-a686-399fefe75b83'::uuid, 'ConnectWise Cloud Management', 'ConnectWise / SkyKick, October 2026'),
                   ('24205314-2b89-4e07-a2a4-579e898a5640'::uuid, 'Cloud Management - MS Teams (formerly SkyKick Cloud Manager - MS Teams)', 'ConnectWise / SkyKick, October 2026'),
                   ('b78f6a77-d4e5-46fb-87e5-d1648bd02519'::uuid, 'Cloud Management - Exchange Online', 'ConnectWise / SkyKick, October 2026'),
                   ('0de14c77-b9b0-4137-9360-34878a929827'::uuid, 'Cloud Management - MS Graph', 'ConnectWise / SkyKick, October 2026'),
                   ('412dcf96-176d-4b3a-a1b0-4981ad66971e'::uuid, 'Cloud Management - Partner Center', 'ConnectWise / SkyKick, October 2026'),
                   ('b2b55f5b-7758-4719-8d8f-88ae172e6bdb'::uuid, 'Cloud Management - SharePoint Online', 'ConnectWise / SkyKick, October 2026')
        ),
        known_tenant(tenant_id, incident) AS (
            VALUES ('3f9cd7a0-127a-4ed4-bf06-2f830d5616b7'::uuid, 'ConnectWise / SkyKick, October 2026')
        )"""

PLUGIN = {
    "plugin_id": 10124,
    "category": "Hybrid Identity",
    "name": "Vendor Application Known to Have Been Abused Across Tenants (ConnectWise / SkyKick)",
    "version": "1.0",
    "revision_date": "2026-11-20",
    "control_id": "HYBRID-10124",
    "requires_sources": ["service_principals"],
    "framework_tags": [
        "NIST-800-53-AC-6",
        "NIST-800-53-AC-20",
        "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-7.2.1",
        "CIS-CSC-8-6.7",
        "ISO-27001-2022-A.5.19",
        "ISO-27001-2022-A.5.23",
        "SOC2-CC6.3",
        "MITRE-ATTCK-T1199",
        "MITRE-ATTCK-T1078.004",
        "MITRE-ATTCK-T1098.003",
    ],
    "references": [
        {"title": "SpecterOps: ConnectWise SkyKick breach and Microsoft 365 (2026-10-17)",
         "url": "https://specterops.io/blog/2026/10/17/connectwise-skykick-breach-microsoft-365/"},
        {"title": "Huntress: Vendor credential enables unauthorized access (2026-10-16)",
         "url": "https://www.huntress.com/blog/vendor-credential-enables-unauthorized-access"},
        {"title": "Microsoft Threat Intelligence: Storm-0940 uses ARTEX agentic AI in ConnectWise supply chain compromise (2026-10-21)",
         "url": "https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/"},
        {"title": "AppGov Score: Inside the ConnectWise attack (2026-10-30)",
         "url": "https://www.appgovscore.com/blog/connectwise-attack-ai-agents-entra-id"},
    ],
    "description": (
        "A service principal of ConnectWise Cloud Backup / Cloud Management (formerly SkyKick), or "
        "another application of the same vendor tenant, is present. Their identities were taken "
        "over in October 2026 and used against more than a thousand customer tenants: adding "
        "credentials, changing roles (one application made itself Global Administrator) and "
        "reading Key Vault secrets. Critical while enabled; high when disabled."
    ),
    "remediation": (
        "Disable the service principal now (do not delete it: its sign-in and audit history is "
        "evidence) and revoke its admin consent. Then investigate from 2026-10-01: service "
        "principal sign-ins of the appIds in the detail, audit events initiated by the "
        "application (role assignments, app role assignments, credentials added to other "
        "applications or service principals, consent grants, Conditional Access and authentication "
        "method changes), Key Vault SecretGet activity, and Exchange / SharePoint access. Remove "
        "any credentials, roles and consents it created, and rotate secrets it could read. Re-enable "
        "only after the vendor confirms remediation, with the fewest permissions the backup needs."
    ),
    "base_severity": "critical",
    "query": """
        WITH
        @KNOWN@,
        hit AS (
            SELECT sp.entra_object_id, sp.app_id, sp.display_name, sp.app_owner_organization_id,
                   sp.account_enabled, sp.publisher_name, sp.last_sign_in_activity_at,
                   COALESCE(k.app_name, 'application of vendor tenant ' || kt.tenant_id::text) AS known_name,
                   COALESCE(k.incident, kt.incident) AS incident
              FROM entra_service_principal sp
              LEFT JOIN known k ON k.app_id = sp.app_id
              LEFT JOIN known_tenant kt ON kt.tenant_id = sp.app_owner_organization_id
             WHERE sp.client_id = %(client_id)s
               AND (k.app_id IS NOT NULL OR kt.tenant_id IS NOT NULL)
        ),
        perms AS (
            SELECT g.principal_id,
                   jsonb_agg(DISTINCT (COALESCE(g.resource_display_name, g.resource_app_id::text) || ': '
                                       || g.permission_name)) AS app_permissions
              FROM entra_app_role_grant g
             WHERE g.client_id = %(client_id)s
               AND g.principal_id IN (SELECT entra_object_id FROM hit)
             GROUP BY g.principal_id
        ),
        roles AS (
            SELECT rm.member_id,
                   jsonb_agg(DISTINCT COALESCE(rm.role_display_name, rm.role_template_id::text)) AS directory_roles
              FROM entra_directory_role_member rm
             WHERE rm.client_id = %(client_id)s
               AND rm.member_id IN (SELECT entra_object_id FROM hit)
             GROUP BY rm.member_id
        )
        SELECT
            CASE WHEN h.account_enabled IS FALSE THEN 'warn' ELSE 'fail' END AS status,
            h.entra_object_id AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN h.account_enabled IS FALSE THEN 'high' ELSE 'critical' END AS fd_severity,
            'Service principal "' || COALESCE(h.display_name, h.app_id::text) || '" (' || h.known_name
                || ') belongs to an application abused across tenants (' || h.incident || ')'
                || CASE WHEN h.account_enabled IS FALSE THEN '; it is disabled -- keep it disabled and investigate'
                        ELSE ': disable it and investigate its activity' END AS summary,
            jsonb_build_object(
                'service_principal_id', h.entra_object_id,
                'display_name', h.display_name,
                'app_id', h.app_id,
                'known_as', h.known_name,
                'incident', h.incident,
                'app_owner_organization_id', h.app_owner_organization_id,
                'publisher_name', h.publisher_name,
                'account_enabled', h.account_enabled,
                'last_sign_in_activity_at', h.last_sign_in_activity_at,
                'application_permissions', COALESCE(p.app_permissions, '[]'::jsonb),
                'directory_roles', COALESCE(r.directory_roles, '[]'::jsonb)
            ) AS detail
        FROM hit h
        LEFT JOIN perms p ON p.principal_id = h.entra_object_id
        LEFT JOIN roles r ON r.member_id = h.entra_object_id
    """.replace("@KNOWN@", KNOWN_ABUSED_APPS_SQL.strip()),
}

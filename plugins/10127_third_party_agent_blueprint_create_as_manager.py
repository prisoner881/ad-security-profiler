"""
Plugin 10127: Third-Party Agent Blueprint Can Create Agent Identities (BluePhishing)

Proofpoint, "BluePhishing: Initial Access via Third-Party Agent Blueprint
Consent" (2026-11-09): an attacker publishes a multi-tenant agent identity
blueprint and phishes a user or administrator into consenting to it. The
blueprint's principal in the victim tenant holds the Microsoft Graph
application permission AgentIdentity.CreateAsManager, so with app-only
tokens the attacker creates agent identities in the tenant (up to 250 per
blueprint) that inherit the blueprint's permissions -- inherited
permissions are not shown in the portal or in Graph. The sponsor required
at creation can be removed afterwards. Until 2026-11-04 Entra granted
AgentIdentity.CreateAsManager to every blueprint principal automatically
(Microsoft MC1506728); from then on it needs explicit admin consent, so
grants made before that date remain.

Reported: service principals owned by another tenant (appOwnerOrganizationId
neither this tenant nor Microsoft) that hold AgentIdentity.CreateAsManager
on Microsoft Graph. One finding per service principal:
  * high 'fail': enabled;
  * medium 'warn': disabled.
The detail lists the blueprint's other Graph application permissions,
which its agent identities inherit, and how many agent identities
(servicePrincipalType 'ServiceIdentity') the tenant holds.

Data: entra_app_role_grant, entra_service_principal, entra_application,
entra_tenant_setting 'organization'. Identity = the service principal.
Related: 10114 (privileged or dormant agent identities), 10038 (risky
agents not blocked), 10016 (user consent).
"""

PLUGIN = {
    "plugin_id": 10127,
    "category": "Hybrid Identity",
    "name": "Third-Party Agent Blueprint Can Create Agent Identities (BluePhishing)",
    "version": "1.0",
    "revision_date": "2026-11-20",
    "control_id": "HYBRID-10127",
    "requires_sources": ["app_role_grants", "service_principals"],
    "framework_tags": [
        "NIST-800-53-AC-6",
        "NIST-800-53-CM-11",
        "NIST-800-53-AC-20",
        "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-7.2.1",
        "CIS-CSC-8-6.7",
        "ISO-27001-2022-A.5.19",
        "ISO-27001-2022-A.5.23",
        "SOC2-CC6.3",
        "MITRE-ATTCK-T1528",
        "MITRE-ATTCK-T1136.003",
    ],
    "references": [
        {"title": "Proofpoint: BluePhishing -- Initial Access via Third-Party Agent Blueprint Consent (2026-11-09)",
         "url": "https://www.proofpoint.com/us/blog/threat-insight/BluePhishing-Initial-Access-via-Third-Party-Agent-Blueprint-Consent"},
        {"title": "Microsoft MC1506728: Changes to AgentIdentity.CreateAsManager permission for agent identities",
         "url": "https://mc.merill.net/message/MC1506728"},
        {"title": "MITRE ATT&CK T1528: Steal Application Access Token",
         "url": "https://attack.mitre.org/techniques/T1528/"},
    ],
    "description": (
        "A service principal published by another organisation holds the Microsoft Graph "
        "permission AgentIdentity.CreateAsManager: the agent blueprint behind it can create agent "
        "identities in this tenant that inherit its permissions, invisibly in the portal "
        "(Proofpoint \"BluePhishing\", November 2026). Entra granted this permission to every "
        "blueprint automatically until 4 November 2026. High while enabled; medium when disabled."
    ),
    "remediation": (
        "Confirm the blueprint is a product the organisation uses and trusts. If not, disable its "
        "service principal, delete the agent identities it created (audit log: \"Add service "
        "principal\" / agent identity creation initiated by the blueprint), and remove the "
        "consent. Where it is legitimate, check that the permissions its agents inherit are the "
        "minimum needed. Restrict user consent (plugin 10016) and use the admin consent workflow, "
        "so a blueprint cannot be consented to by a phished user."
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
                           AND s.app_owner_organization_id NOT IN
                               ('f8cdef31-a31e-4b4a-93e4-5f571e91255a'::uuid, '72f988bf-86f1-41af-91ab-2d7cd011db47'::uuid)
                         GROUP BY s.app_owner_organization_id
                         ORDER BY count(*) DESC, s.app_owner_organization_id
                         LIMIT 1)) AS tenant_id
        ),
        holder AS (
            SELECT DISTINCT g.principal_id
              FROM entra_app_role_grant g
             WHERE g.client_id = %(client_id)s
               AND g.principal_type = 'ServicePrincipal'
               AND g.resource_app_id = '00000003-0000-0000-c000-000000000000'::uuid
               AND g.permission_name = 'AgentIdentity.CreateAsManager'
        ),
        third_party AS (
            SELECT sp.*
              FROM holder h
              JOIN entra_service_principal sp
                ON sp.client_id = %(client_id)s AND sp.entra_object_id = h.principal_id
             WHERE sp.app_owner_organization_id IS NOT NULL
               AND sp.app_owner_organization_id NOT IN
                   ('f8cdef31-a31e-4b4a-93e4-5f571e91255a'::uuid, '72f988bf-86f1-41af-91ab-2d7cd011db47'::uuid)
               AND CASE WHEN (SELECT t.tenant_id FROM tenant t) IS NOT NULL
                        THEN sp.app_owner_organization_id <> (SELECT t.tenant_id FROM tenant t)
                        ELSE NOT EXISTS (SELECT 1 FROM entra_application a
                                          WHERE a.client_id = %(client_id)s AND a.app_id = sp.app_id) END
        ),
        other_perms AS (
            SELECT g.principal_id,
                   jsonb_agg(DISTINCT g.permission_name) AS graph_permissions
              FROM entra_app_role_grant g
             WHERE g.client_id = %(client_id)s
               AND g.resource_app_id = '00000003-0000-0000-c000-000000000000'::uuid
               AND g.principal_id IN (SELECT entra_object_id FROM third_party)
               AND g.permission_name <> 'AgentIdentity.CreateAsManager'
             GROUP BY g.principal_id
        ),
        agents AS (
            SELECT count(*) AS n
              FROM entra_service_principal sp
             WHERE sp.client_id = %(client_id)s AND sp.service_principal_type = 'ServiceIdentity'
        )
        SELECT
            CASE WHEN tp.account_enabled IS FALSE THEN 'warn' ELSE 'fail' END AS status,
            tp.entra_object_id AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN tp.account_enabled IS FALSE THEN 'medium' ELSE 'high' END AS fd_severity,
            'Service principal "' || COALESCE(tp.display_name, tp.app_id::text) || '" of another organisation'
                || COALESCE(' (' || COALESCE(tp.verified_publisher_name, tp.publisher_name) || ')', '')
                || ' holds AgentIdentity.CreateAsManager: it can create agent identities in this tenant that '
                || 'inherit its permissions'
                || CASE WHEN tp.account_enabled IS FALSE THEN ' (service principal disabled)' ELSE '' END AS summary,
            jsonb_build_object(
                'service_principal_id', tp.entra_object_id,
                'display_name', tp.display_name,
                'app_id', tp.app_id,
                'app_owner_organization_id', tp.app_owner_organization_id,
                'publisher_name', tp.publisher_name,
                'verified_publisher_name', tp.verified_publisher_name,
                'service_principal_type', tp.service_principal_type,
                'account_enabled', tp.account_enabled,
                'inherited_graph_permissions', COALESCE(op.graph_permissions, '[]'::jsonb),
                'agent_identities_in_tenant', (SELECT n FROM agents),
                'tenant_id_known', (SELECT t.tenant_id FROM tenant t) IS NOT NULL
            ) AS detail
        FROM third_party tp
        LEFT JOIN other_perms op ON op.principal_id = tp.entra_object_id
    """,
}

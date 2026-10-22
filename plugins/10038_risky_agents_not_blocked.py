"""
Plugin 10038: Risky Agent Identities Not Blocked by Conditional Access

Reports a tenant that has Microsoft Entra agent identities (service
principals with servicePrincipalType 'ServiceIdentity', created for AI
agents through Entra Agent ID) but no enabled Conditional Access policy
that blocks high-risk agent identities.

Why: agents act autonomously with the permissions they hold, often
delegated from users or inherited from their blueprint; ID Protection
scores agent identities for risk (anomalous resource access, leaked
credentials, threat intelligence) the way it scores users. CISA SCuBA
MS.AAD.9.1 (March 2026): "Risky AI agents SHALL be blocked", implemented
as a policy that includes all agent identities, targets all resources,
sets the agent risk condition to High and grants Block.

A policy counts when it is enabled, its grant controls include 'block',
conditions.clientApplications.includeAgentIdServicePrincipals contains
'All', conditions.applications.includeApplications contains 'All', and
conditions.agentIdRiskLevels includes 'high'. Report-only and narrower
policies are listed in detail. These conditions are only returned by the
beta Conditional Access API (entra_tenant_setting 'ca_policies_beta',
entra_graph_collector 0.9.0).

Not reported when the tenant has no agent identity, or when the licence
read shows no Entra ID P2 (agent risk needs P2 plus Microsoft Agent 365 or
Microsoft 365 E7). fail / medium, one tenant-level row (object_guid
md5('10038:' || client_id)).
"""

PLUGIN = {
    "plugin_id": 10038,
    "category": "Hybrid Identity",
    "name": "Risky Agent Identities Not Blocked by Conditional Access",
    "version": "1.0",
    "revision_date": "2026-10-22",
    "control_id": "HYBRID-10038",
    "requires_sources": ["ca_policies_beta", "service_principals"],
    "framework_tags": [
        "CISA-SCUBA-MS.AAD.9.1",
        "NIST-800-53-AC-3",
        "NIST-800-53-AC-6",
        "NIST-CSF-2.0-PR.AA-05",
        "CIS-CSC-8-6.8",
        "ISO-27001-2022-A.8.2",
        "SOC2-CC6.1",
        "MITRE-ATTCK-T1078.004",
    ],
    "references": [
        {"title": "CISA SCuBA Microsoft Entra ID baseline (MS.AAD.9.1)",
         "url": "https://github.com/cisagov/ScubaGear/blob/main/PowerShell/ScubaGear/baselines/aad.md"},
        {"title": "Microsoft: Block access by high-risk agent identities",
         "url": "https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-agent-block-high-risk"},
        {"title": "Microsoft Graph (beta): agentIdentity resource type",
         "url": "https://learn.microsoft.com/en-us/graph/api/resources/agentidentity?view=graph-rest-beta"},
        {"title": "MITRE ATT&CK T1078.004: Valid Accounts: Cloud Accounts",
         "url": "https://attack.mitre.org/techniques/T1078/004/"},
    ],
    "description": (
        "The tenant has Entra agent identities, but no enabled Conditional Access policy "
        "blocks agent identities at high risk for all resources (CISA SCuBA MS.AAD.9.1). "
        "A compromised or misbehaving agent then keeps acting with its permissions after "
        "ID Protection has flagged it."
    ),
    "remediation": (
        "Create a Conditional Access policy: Users, agents or workload identities > Agents > "
        "Include = All agent identities; Target resources = All resources; Conditions > "
        "Agent risk = High; Grant = Block access. Run it in report-only briefly, then switch "
        "it On."
    ),
    "base_severity": "medium",
    "query": """
        WITH agents AS (
            SELECT count(*) AS n,
                   jsonb_agg(sp.display_name ORDER BY sp.display_name) FILTER (WHERE sp.display_name IS NOT NULL)
                       AS names
              FROM entra_service_principal sp
             WHERE sp.client_id = %(client_id)s
               AND sp.service_principal_type = 'ServiceIdentity'
        ),
        ts AS (
            SELECT t.client_id, t.content
              FROM entra_tenant_setting t
             WHERE t.client_id = %(client_id)s
               AND t.setting_name = 'ca_policies_beta'
               AND jsonb_typeof(t.content) = 'array'
               AND NOT EXISTS (SELECT 1 FROM v_entra_tenant_capability c
                                WHERE c.client_id = t.client_id AND c.license_status = 'ok'
                                  AND NOT c.has_p2)
        ),
        pol AS (
            SELECT p->>'id' AS id, p->>'display_name' AS name, p->>'state' AS state,
                   COALESCE(p->'conditions'->'clientApplications'->'includeAgentIdServicePrincipals',
                            '[]'::jsonb) ? 'All' AS all_agents,
                   COALESCE(p->'conditions'->'applications'->'includeApplications', '[]'::jsonb) ? 'All'
                       AS all_apps,
                   position('high' IN lower(COALESCE(p->'conditions'->>'agentIdRiskLevels', ''))) > 0 AS high_risk,
                   COALESCE(p->'grant_controls'->'builtInControls', '[]'::jsonb) ? 'block' AS blocks
              FROM ts CROSS JOIN LATERAL jsonb_array_elements(ts.content) p
             WHERE jsonb_typeof(p->'conditions'->'clientApplications'->'includeAgentIdServicePrincipals') = 'array'
                OR p->'conditions'->>'agentIdRiskLevels' IS NOT NULL
        )
        SELECT
            'fail' AS status,
            md5('10038:' || ts.client_id::text)::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'medium' AS fd_severity,
            'No enabled Conditional Access policy blocks high-risk agent identities ('
                || a.n || ' agent identit' || CASE WHEN a.n = 1 THEN 'y' ELSE 'ies' END
                || ' in the tenant)' AS summary,
            jsonb_build_object(
                'agent_identity_count', a.n,
                'agent_identities_first_50', to_jsonb((SELECT array_agg(x) FROM (
                    SELECT jsonb_array_elements_text(a.names) x LIMIT 50) y)),
                'agent_policies_not_counted', (SELECT jsonb_agg(jsonb_build_object(
                        'policy', p.name, 'id', p.id, 'state', p.state, 'all_agents', p.all_agents,
                        'all_resources', p.all_apps, 'high_risk', p.high_risk, 'blocks', p.blocks)
                    ORDER BY p.name, p.id) FROM pol p),
                'scuba_policy', 'MS.AAD.9.1'
            ) AS detail
        FROM ts
        CROSS JOIN agents a
        WHERE a.n > 0
          AND NOT EXISTS (SELECT 1 FROM pol p
                           WHERE p.state = 'enabled' AND p.all_agents AND p.all_apps AND p.high_risk AND p.blocks)
    """,
}

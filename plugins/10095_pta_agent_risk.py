"""
Plugin 10095: Pass-Through Authentication Agent Sprawl or Agent on a Non-Tier-0 Host

Reads the pass-through authentication (PTA) agents (entra_pta_agent, source
pta_agents: beta onPremisesPublishingProfiles/authentication/agents,
opt-in) and joins each agent's host (machine_name, an FQDN) to the
collected AD computers (ad_computer.dns_hostname, case-insensitive; a
bare host name is matched against the computer's sAMAccountName).

Per agent:
- the host is an AD computer that is not Tier 0 (not in v_tier0_object
  and not a v_privileged_principal) -> high. A PTA agent validates every
  cloud sign-in's password against AD: whoever controls its host can read
  every password in clear text and accept any password for any synced
  user (AADInternals PTASpy). Microsoft says to manage PTA servers as
  Tier 0.
- the host does not resolve to any collected AD computer -> medium,
  "verify": it may be in a domain we do not collect, renamed, or not
  domain-joined at all; its tier cannot be confirmed.
- the agent's status is not 'active' -> low (a stale registration to
  remove; an inactive agent that comes back still authenticates).
- the tenant has more than 3 agents -> low on every agent (each one is a
  host that sees cleartext passwords; Microsoft recommends 3 for
  availability, up to 40 are allowed).
An agent on a Tier 0 host that is active, in a tenant with at most 3
agents, is not reported.

One finding per agent (object_guid md5('10095:' || client_id || ':' ||
lower(agent_id))), worst severity wins, every issue listed. Uses current
AD rows (valid_to IS NULL), independent of the AD run id. status 'fail'
at medium or above, 'warn' at low. Requires source pta_agents.
"""

PLUGIN = {
    "plugin_id": 10095,
    "category": "Hybrid Identity",
    "name": "Pass-Through Authentication Agent Sprawl or Agent on a Non-Tier-0 Host",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "HYBRID-10095",
    "requires_sources": ["pta_agents"],
    "framework_tags": [
        "NIST-800-53-AC-6",
        "NIST-800-53-SC-7",
        "NIST-800-53-CM-8",
        "NIST-CSF-2.0-PR.AA-05",
        "ISO-27001-2022-A.8.2",
        "SOC2-CC6.3",
        "MITRE-ATTCK-T1556.007",
    ],
    "references": [
        {"title": "Microsoft: Microsoft Entra pass-through authentication: security deep dive",
         "url": "https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-pta-security-deep-dive"},
        {"title": "Microsoft: Pass-through authentication: current limitations and agent placement",
         "url": "https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-pta-quick-start"},
        {"title": "MITRE ATT&CK T1556.007 Modify Authentication Process: Hybrid Identity",
         "url": "https://attack.mitre.org/techniques/T1556/007/"},
    ],
    "description": (
        "A pass-through authentication agent runs on an AD computer that "
        "is not Tier 0 (high) or on a host that cannot be matched to a "
        "collected AD computer (medium, verify), is not active (low), or "
        "the tenant has more than 3 agents (low). Every PTA host sees "
        "cloud sign-in passwords in clear text and can accept any "
        "password (PTASpy), so it must be managed as Tier 0. One finding "
        "per agent."
    ),
    "remediation": (
        "Run PTA agents only on Tier 0 servers (the Entra Connect server "
        "and dedicated hardened hosts managed like domain controllers), "
        "keep three for availability, and uninstall the agent from any "
        "other host (Programs and Features -> Microsoft Entra Connect "
        "Authentication Agent). Remove inactive agent registrations in "
        "the Entra admin center -> Entra Connect -> Pass-through "
        "authentication. Move hosts that must keep an agent into the "
        "Tier 0 OU structure and restrict local administrators."
    ),
    "base_severity": "high",
    "query": """
        WITH agent AS (
            SELECT a.*
              FROM entra_pta_agent a
             WHERE a.client_id = %(client_id)s
               AND EXISTS (SELECT 1 FROM entra_collection_status s
                            WHERE s.client_id = a.client_id
                              AND s.source = 'pta_agents' AND s.status = 'ok')
        ),
        n AS (SELECT count(*) AS agents FROM agent),
        tier0 AS (
            SELECT t.object_guid FROM v_tier0_object t WHERE t.client_id = %(client_id)s
            UNION
            SELECT p.object_guid FROM v_privileged_principal p WHERE p.client_id = %(client_id)s
        ),
        resolved AS (
            SELECT a.agent_id,
                   count(c.object_guid) AS matches,
                   bool_or(t.object_guid IS NOT NULL) AS any_tier0,
                   bool_and(t.object_guid IS NOT NULL) FILTER (WHERE c.object_guid IS NOT NULL) AS all_tier0,
                   jsonb_agg(jsonb_build_object(
                       'object_guid', c.object_guid,
                       'sam_account_name', c.sam_account_name,
                       'dns_hostname', c.dns_hostname,
                       'distinguished_name', o.dn_current,
                       'is_domain_controller', c.is_domain_controller,
                       'is_tier0', t.object_guid IS NOT NULL
                   ) ORDER BY c.object_guid) FILTER (WHERE c.object_guid IS NOT NULL) AS computers
              FROM agent a
              LEFT JOIN (ad_computer c
                         JOIN directory_object o
                           ON o.client_id = c.client_id AND o.object_guid = c.object_guid
                          AND NOT o.is_deleted)
                ON c.client_id = a.client_id AND c.valid_to IS NULL
               AND (lower(c.dns_hostname) = lower(a.machine_name)
                    OR (position('.' IN COALESCE(a.machine_name, '')) = 0
                        AND upper(rtrim(c.sam_account_name, '$')) = upper(a.machine_name)))
              LEFT JOIN (SELECT DISTINCT object_guid FROM tier0) t ON t.object_guid = c.object_guid
             GROUP BY a.agent_id
        ),
        issue AS (
            SELECT r.agent_id, 4 AS rank,
                   'runs on an AD computer that is not Tier 0' AS issue
              FROM resolved r WHERE r.matches > 0 AND r.all_tier0 IS FALSE
            UNION ALL
            SELECT r.agent_id, 3,
                   'host does not match any collected AD computer (verify it is a Tier 0 server)'
              FROM resolved r WHERE r.matches = 0
            UNION ALL
            SELECT a.agent_id, 2, 'agent is not active (status ' || COALESCE(a.status, 'unknown') || ')'
              FROM agent a WHERE a.status IS DISTINCT FROM 'active'
            UNION ALL
            SELECT a.agent_id, 2, 'tenant has more than 3 pass-through authentication agents'
              FROM agent a CROSS JOIN n WHERE n.agents > 3
        ),
        agg AS (
            SELECT i.agent_id, max(i.rank) AS rank,
                   string_agg(i.issue, '; ' ORDER BY i.rank DESC, i.issue COLLATE "C") AS summary_text,
                   jsonb_agg(i.issue ORDER BY i.rank DESC, i.issue COLLATE "C") AS issues
              FROM issue i
             GROUP BY i.agent_id
        )
        SELECT
            CASE WHEN g.rank >= 3 THEN 'fail' ELSE 'warn' END AS status,
            md5('10095:' || a.client_id::text || ':' || lower(a.agent_id))::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE g.rank WHEN 4 THEN 'high' WHEN 3 THEN 'medium' ELSE 'low' END AS fd_severity,
            'Pass-through authentication agent on ' || COALESCE(a.machine_name, a.agent_id) || ': '
                || g.summary_text AS summary,
            jsonb_build_object(
                'agent_id', a.agent_id,
                'machine_name', a.machine_name,
                'external_ip', a.external_ip,
                'status', a.status,
                'issues', g.issues,
                'tenant_agent_count', n.agents,
                'matched_ad_computers', COALESCE(r.computers, '[]'::jsonb)
            ) AS detail
        FROM agg g
        JOIN agent a ON a.agent_id = g.agent_id
        LEFT JOIN resolved r ON r.agent_id = g.agent_id
        CROSS JOIN n
    """,
}

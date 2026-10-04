"""
Plugin 2002: Computer Account Has Constrained Delegation With Protocol Transition

TRUSTED_TO_AUTH_FOR_DELEGATION enables S4U2Self -- the computer can obtain
a service ticket on behalf of any user without that user ever having
authenticated to it, a materially more dangerous variant of constrained
delegation. Escalated further if the computer is a domain controller,
since that combination would be highly unusual and worth immediate review.

[v1.4] Read-only DCs are excluded: their default userAccountControl
(0x5001000) includes TRUSTED_TO_AUTH_FOR_DELEGATION, so every RODC was a
false positive (ad_computer.is_read_only_dc, schema v36). The detail now
lists the constrained-delegation targets (delegation_edge plus unresolved
SPNs), and the finding is raised to critical when a target is a Tier 0
object (a DC, CA host, ...) or krbtgt -- S4U2Self + S4U2Proxy to such a
target is domain compromise. Remediation no longer suggests RBCD as the
fix for protocol transition.
"""

PLUGIN = {
    "plugin_id": 2002,
    "category": "Computer Accounts",
    "name": "Computer Account Has Constrained Delegation With Protocol Transition",
    "version": "1.4",
    "revision_date": "2026-10-04",
    "remediation": (
        "Review whether this computer genuinely needs protocol transition "
        "(S4U2Self for users who did not authenticate with Kerberos). If "
        "not, switch it to Kerberos-only constrained delegation (clear "
        "TRUSTED_TO_AUTH_FOR_DELEGATION: Set-ADAccountControl "
        "-TrustedToAuthForDelegation $false) and keep the "
        "msDS-AllowedToDelegateTo list to the exact services the machine's "
        "function requires. Any target on a domain controller or other "
        "Tier 0 host (or krbtgt) must be removed immediately: whoever "
        "controls this computer can impersonate any user, including "
        "Domain Admins, to that service. Treat the computer itself as "
        "Tier 0 while such delegation exists. Read-only DCs carry this "
        "flag by default and are not reported."
    ),
    "control_id": "DELEG-004",
    "framework_tags": ["CISA-AA26-237A", "MITRE-ATTCK-T1550.003"],
    "references": [],
    "description": (
        "TRUSTED_TO_AUTH_FOR_DELEGATION (UAC bit 0x1000000) enables "
        "protocol transition (S4U2Self): the computer can obtain a "
        "service ticket on behalf of any user without that user ever "
        "having authenticated to it -- a materially more dangerous "
        "capability than plain constrained delegation, which requires the "
        "target user to have actually authenticated first. Same "
        "underlying mechanism as user-account plugin 1020, applied to "
        "computer objects. Rated critical on a writable DC or when a "
        "delegation target is a Tier 0 object (domain controller, CA host, "
        "...) or krbtgt; the targets are listed in the detail. Read-only "
        "DCs are excluded (their default userAccountControl 0x5001000 "
        "includes this flag). "
        "NOT downgraded when disabled: delegation configuration persists regardless of account state."
    ),
    "base_severity": "high",
    "query": """
        WITH tgt AS (
            SELECT e.source_guid,
                   COALESCE(o.sam_account_name, o.dn_current, e.target_guid::text) AS target_name,
                   (tc.is_domain_controller IS TRUE
                    OR EXISTS (SELECT 1 FROM v_tier0_object t
                                WHERE t.client_id = e.client_id
                                  AND t.object_guid = e.target_guid)) AS is_tier0
              FROM delegation_edge e
              JOIN directory_object o
                ON o.object_guid = e.target_guid AND o.client_id = e.client_id
              LEFT JOIN ad_computer tc
                ON tc.object_guid = e.target_guid AND tc.client_id = e.client_id
               AND tc.valid_to IS NULL
             WHERE e.client_id = %(client_id)s
               AND e.valid_to IS NULL
               AND e.delegation_type = 'constrained'
            UNION ALL
            SELECT u.source_guid, u.target_spn, u.target_spn ILIKE 'krbtgt/%%'
              FROM unresolved_delegation_target_edge u
             WHERE u.client_id = %(client_id)s
               AND u.valid_to IS NULL
        ),
        tgt_agg AS (
            SELECT source_guid,
                   bool_or(is_tier0) AS any_tier0,
                   jsonb_agg(DISTINCT target_name ORDER BY target_name) AS targets,
                   COALESCE(jsonb_agg(DISTINCT target_name ORDER BY target_name)
                            FILTER (WHERE is_tier0), '[]'::jsonb) AS tier0_targets
              FROM tgt
             GROUP BY source_guid
        )
        SELECT
            'fail' AS status,
            c.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN c.is_domain_controller OR ta.any_tier0 IS TRUE
                 THEN 'critical' ELSE 'high' END AS fd_severity,
            (CASE WHEN c.is_domain_controller THEN 'Domain Controller ' ELSE '' END)
                || 'Computer Account ' || COALESCE(c.sam_account_name, c.object_guid::text)
                || ' has constrained delegation with protocol transition (S4U2Self) enabled'
                || CASE WHEN ta.any_tier0 IS TRUE
                        THEN ' to a Tier 0 target' ELSE '' END AS summary,
            jsonb_build_object(
                'sam_account_name', c.sam_account_name,
                'dns_hostname', c.dns_hostname,
                'operating_system', c.operating_system,
                'is_enabled', c.is_enabled,
                'is_domain_controller', c.is_domain_controller,
                'delegation_targets', COALESCE(ta.targets, '[]'::jsonb),
                'tier0_delegation_targets', COALESCE(ta.tier0_targets, '[]'::jsonb)
            ) AS detail
        FROM ad_computer c
        LEFT JOIN tgt_agg ta ON ta.source_guid = c.object_guid
        WHERE c.valid_to IS NULL
          AND c.client_id = %(client_id)s
          AND c.user_account_control IS NOT NULL
          AND (c.user_account_control & 16777216) != 0
          AND NOT c.is_read_only_dc
    """,
}

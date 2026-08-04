"""
Plugin 1010: Account with Unconstrained Kerberos Delegation

Unconstrained delegation lets a compromised account impersonate any user
who authenticates to it -- including, via forced-authentication
techniques, a Domain Controller itself. This is one of the highest-value
targets in an AD environment when found on any account, computer or user.
"""

PLUGIN = {
    "plugin_id": 1010,
    "category": "User Accounts",
    "name": "User Account Has Unconstrained Kerberos Delegation",
    "version": "1.2",
    "revision_date": "2026-07-15",
    "remediation": (
    'Migrate to constrained delegation, or better, resource-based constrained '
    'delegation -- both limit impersonation to explicitly-defined target '
    'services rather than allowing full TGT reuse against any service in the '
    'domain. If unconstrained delegation is genuinely required (rare, typically '
    'legacy scenarios), ensure any account that might authenticate to this '
    'service is itself protected (Protected Users membership or the "account is '
    'sensitive and cannot be delegated" flag), and restrict network '
    'reachability to the delegating service as tightly as possible.'
),
    "control_id": "DELEG-001",
    "framework_tags": [],
    "references": [
        {"title": "MITRE ATT&CK T1558: Steal or Forge Kerberos Tickets",
         "url": "https://attack.mitre.org/techniques/T1558/"},
    ],
    "description": (
        "Kerberos unconstrained delegation allows a service to reuse a "
        "user's Ticket Granting Ticket (TGT) to authenticate to any "
        "service in the domain. If the delegated account is compromised, "
        "cached TGTs can be extracted and used to impersonate any "
        "authenticating user -- and if a privileged account or a Domain "
        "Controller authenticates to it, potentially via forced "
        "authentication techniques, the attacker can escalate privileges "
        "and compromise the entire domain. Directly quoted from a real "
        "PingCastle report's own rule description for this exact finding."
    ),
    "base_severity": "critical",
    "query": """
        SELECT
            'fail' AS status,
            u.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            'critical' AS tool_severity,
            'PingCastle: unconstrained delegation rule -- "Kerberos unconstrained '
                'delegation allows a service to reuse a user''s Ticket Granting '
                'Ticket (TGT) to authenticate to any service in the domain... the '
                'attacker can escalate privileges and compromise the entire domain."' AS tool_reference,
            'critical' AS fd_severity,
            'User Account ' || COALESCE(u.user_principal_name, u.sam_account_name)
                || ' has unconstrained Kerberos delegation enabled' AS summary,
            jsonb_build_object(
                'sam_account_name', u.sam_account_name,
                'user_principal_name', u.user_principal_name,
                'is_enabled', u.is_enabled,
                'admin_count', u.admin_count
            ) AS detail
        FROM ad_user u
        JOIN delegation_edge de
            ON de.source_guid = u.object_guid AND de.client_id = u.client_id
        WHERE u.valid_to IS NULL
          AND u.client_id = %(client_id)s
          AND de.valid_to IS NULL
          AND de.delegation_type = 'unconstrained'
    """,
}

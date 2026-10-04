"""
Plugin 1020: Constrained Delegation With Protocol Transition (S4U2Self)

TRUSTED_TO_AUTH_FOR_DELEGATION (0x1000000) enables protocol transition --
the account can obtain a ticket on behalf of ANY user via S4U2Self
without that user ever having authenticated to it at all, unlike plain
constrained delegation. A materially more dangerous variant, and not
currently distinguished as its own delegation_edge type, so checked
directly against the UAC bit here.

[v1.5] Severity now depends on where the account can delegate: critical
when an msDS-AllowedToDelegateTo target (delegation_edge 'constrained') is
a domain controller, or an unresolved target SPN is krbtgt/* -- protocol
transition to a DC service is domain compromise; high otherwise. detail
lists the targets (sorted). Such accounts get the summary suffix " to a
domain controller". Disabled accounts are now reported (the query's
is_enabled filter contradicted the description) one level lower (a
disabled account cannot obtain the TGT S4U needs, but the configuration
persists), with the suffix " (account disabled)"; summaries of other
findings are unchanged. Remediation no longer suggests "pairing" T2A4D with
RBCD (a different mechanism configured on the resource) and the
description no longer overstates S4U2Self (any account with an SPN can
do it; T2A4D makes the resulting ticket forwardable, i.e. usable for
S4U2Proxy to the configured targets).
"""

PLUGIN = {
    "plugin_id": 1020,
    "category": "User Accounts",
    "name": "User Account Has Constrained Delegation With Protocol Transition",
    "version": "1.5",
    "revision_date": "2026-10-04",
    "remediation": (
    'Review whether this account genuinely needs protocol transition. If not, '
    'switch it to "Use Kerberos only" (clear TRUSTED_TO_AUTH_FOR_DELEGATION, '
    '`Set-ADAccountControl -TrustedToAuthForDelegation $false`). If it does, '
    'restrict msDS-AllowedToDelegateTo to the minimum set of non-DC services '
    'the application needs, never a domain controller service, and protect '
    'privileged accounts from being impersonated (Protected Users, or '
    '"Account is sensitive and cannot be delegated"). Where the design '
    'allows, prefer resource-based constrained delegation configured on the '
    'target resource instead of msDS-AllowedToDelegateTo.'
),
    "control_id": "DELEG-002",
    "framework_tags": [
        "NIST-800-53-AC-3",
        "NIST-800-53-AC-6",
        "NIST-800-53-AC-6(1)",
        "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-7.2.1",
        "PCI-DSS-4.0-7.2.2",
        "CIS-CSC-8-6.8",
        "CIS-CSC-8-3.3",
        "ISO-27001-2022-A.5.15",
        "ISO-27001-2022-A.8.3",
        "SOC2-CC6.3",
        "HIPAA-164.312(a)(1)",
        "MITRE-ATTCK-T1550.003",
        "CISA-AA26-237A",
    ],
    "references": [],
    "description": (
        "TRUSTED_TO_AUTH_FOR_DELEGATION (UAC bit 0x1000000) enables "
        "protocol transition: the forwardable S4U2Self ticket the account "
        "obtains for ANY user can be passed to S4U2Proxy, so the account "
        "can impersonate any (non-protected) user to every service in its "
        "msDS-AllowedToDelegateTo list without that user ever having "
        "authenticated -- materially more dangerous than plain constrained "
        "delegation, which needs the user's own ticket. Critical when a "
        "target is a domain controller service (or krbtgt), high "
        "otherwise. Not "
        "currently distinguished as its own delegation_edge type in this "
        "project's schema, so checked directly against the UAC bit here "
        "rather than via the edge table plugin 1010 uses. Disabled "
        "accounts are reported one severity level lower: they cannot "
        "obtain the TGT S4U needs, but the configuration persists and "
        "reactivates immediately if the account is re-enabled."
    ),
    "base_severity": "high",
    "query": """
        WITH t2a4d AS (
            SELECT u.*
            FROM ad_user u
            WHERE u.valid_to IS NULL
              AND u.client_id = %(client_id)s
              AND u.user_account_control IS NOT NULL
              AND (u.user_account_control & 16777216) != 0
        ),
        targets AS (
            -- resolved msDS-AllowedToDelegateTo targets
            SELECT t.object_guid AS user_guid,
                   COALESCE(c.dns_hostname, o.sam_account_name, o.dn_current,
                            de.target_guid::text) AS target_name,
                   COALESCE(c.is_domain_controller, false) AS is_dc
            FROM t2a4d t
            JOIN delegation_edge de
                ON de.source_guid = t.object_guid AND de.client_id = t.client_id
               AND de.valid_to IS NULL AND de.delegation_type = 'constrained'
            LEFT JOIN directory_object o
                ON o.object_guid = de.target_guid AND o.client_id = de.client_id
            LEFT JOIN ad_computer c
                ON c.object_guid = de.target_guid AND c.client_id = de.client_id
               AND c.valid_to IS NULL
            UNION
            -- unresolvable target SPNs (krbtgt/<DOMAIN> is never registered)
            SELECT t.object_guid, ue.target_spn,
                   ue.target_spn ILIKE 'krbtgt/%%'
            FROM t2a4d t
            JOIN unresolved_delegation_target_edge ue
                ON ue.source_guid = t.object_guid AND ue.client_id = t.client_id
               AND ue.valid_to IS NULL
        ),
        target_agg AS (
            SELECT user_guid,
                   bool_or(is_dc) AS reaches_dc,
                   jsonb_agg(DISTINCT target_name ORDER BY target_name) AS delegation_targets
            FROM targets
            GROUP BY user_guid
        )
        SELECT
            'fail' AS status,
            u.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE GREATEST(0,
                    (CASE WHEN ta.reaches_dc THEN 4 ELSE 3 END)
                    - (CASE WHEN u.is_enabled THEN 0 ELSE 1 END))
                WHEN 4 THEN 'critical'
                WHEN 3 THEN 'high'
                WHEN 2 THEN 'medium'
                ELSE 'low'
            END AS fd_severity,
            'User Account ' || COALESCE(u.user_principal_name, u.sam_account_name)
                || ' has constrained delegation with protocol transition (S4U2Self) enabled'
                || CASE WHEN ta.reaches_dc THEN ' to a domain controller' ELSE '' END
                || CASE WHEN u.is_enabled IS NOT TRUE THEN ' (account disabled)' ELSE '' END AS summary,
            jsonb_build_object(
                'sam_account_name', u.sam_account_name,
                'user_principal_name', u.user_principal_name,
                'user_account_control', u.user_account_control,
                'is_enabled', u.is_enabled,
                'admin_count', u.admin_count,
                'delegation_targets', COALESCE(ta.delegation_targets, '[]'::jsonb),
                'reaches_domain_controller', COALESCE(ta.reaches_dc, false)
            ) AS detail
        FROM t2a4d u
        LEFT JOIN target_agg ta ON ta.user_guid = u.object_guid
    """,
}

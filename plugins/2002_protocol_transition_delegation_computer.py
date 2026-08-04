"""
Plugin 2002: Computer Account Has Constrained Delegation With Protocol Transition

TRUSTED_TO_AUTH_FOR_DELEGATION enables S4U2Self -- the computer can obtain
a service ticket on behalf of any user without that user ever having
authenticated to it, a materially more dangerous variant of constrained
delegation. Escalated further if the computer is a domain controller,
since that combination would be highly unusual and worth immediate review.
"""

PLUGIN = {
    "plugin_id": 2002,
    "category": "Computer Accounts",
    "name": "Computer Account Has Constrained Delegation With Protocol Transition",
    "version": "1.2",
    "revision_date": "2026-07-15",
    "remediation": (
        "Review whether this computer genuinely needs S4U2Self (protocol "
        "transition) capability at all. If so, pair it with resource-based "
        "constrained delegation (the modern replacement for the older "
        "msDS-AllowedToDelegateTo-based approach) and restrict the "
        "specific services it can obtain tickets for as tightly as "
        "possible, rather than leaving delegation scope broader than the "
        "machine's actual function requires."
    ),
    "control_id": "DELEG-004",
    "framework_tags": [],
    "references": [],
    "description": (
        "TRUSTED_TO_AUTH_FOR_DELEGATION (UAC bit 0x1000000) enables "
        "protocol transition (S4U2Self): the computer can obtain a "
        "service ticket on behalf of any user without that user ever "
        "having authenticated to it -- a materially more dangerous "
        "capability than plain constrained delegation, which requires the "
        "target user to have actually authenticated first. Same "
        "underlying mechanism as user-account plugin 1020, applied to "
        "computer objects. "
        "NOT downgraded when disabled: delegation configuration persists regardless of account state."
    ),
    "base_severity": "high",
    "query": """
        SELECT
            'fail' AS status,
            c.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN c.is_domain_controller THEN 'critical' ELSE 'high' END AS fd_severity,
            (CASE WHEN c.is_domain_controller THEN 'Domain Controller ' ELSE '' END)
                || 'Computer Account ' || c.sam_account_name
                || ' has constrained delegation with protocol transition (S4U2Self) enabled' AS summary,
            jsonb_build_object(
                'sam_account_name', c.sam_account_name,
                'dns_hostname', c.dns_hostname,
                'operating_system', c.operating_system,
                'is_enabled', c.is_enabled,
                'is_domain_controller', c.is_domain_controller
            ) AS detail
        FROM ad_computer c
        WHERE c.valid_to IS NULL
          AND c.client_id = %(client_id)s
          AND c.user_account_control IS NOT NULL
          AND (c.user_account_control & 16777216) != 0
    """,
}

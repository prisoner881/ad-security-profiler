"""
Plugin 1020: Constrained Delegation With Protocol Transition (S4U2Self)

TRUSTED_TO_AUTH_FOR_DELEGATION (0x1000000) enables protocol transition --
the account can obtain a ticket on behalf of ANY user via S4U2Self
without that user ever having authenticated to it at all, unlike plain
constrained delegation. A materially more dangerous variant, and not
currently distinguished as its own delegation_edge type, so checked
directly against the UAC bit here.
"""

PLUGIN = {
    "plugin_id": 1020,
    "category": "User Accounts",
    "name": "User Account Has Constrained Delegation With Protocol Transition",
    "version": "1.3",
    "revision_date": "2026-07-15",
    "remediation": (
    'Review whether this account genuinely needs S4U2Self (protocol transition) '
    'capability at all. If so, pair it with resource-based constrained '
    'delegation (the modern replacement for the older '
    'msDS-AllowedToDelegateTo-based approach) and restrict the specific '
    'services it can obtain tickets for as tightly as possible, rather than '
    "leaving delegation scope broader than the account's actual function "
    'requires.'
),
    "control_id": "DELEG-002",
    "framework_tags": [],
    "references": [],
    "description": (
        "TRUSTED_TO_AUTH_FOR_DELEGATION (UAC bit 0x1000000) enables "
        "protocol transition (S4U2Self): the account can obtain a "
        "service ticket on behalf of any user without that user ever "
        "having authenticated to it -- a materially more dangerous "
        "capability than plain constrained delegation, which requires "
        "the target user to have actually authenticated first. Not "
        "currently distinguished as its own delegation_edge type in this "
        "project's schema, so checked directly against the UAC bit here "
        "rather than via the edge table plugin 1010 uses. NOT downgraded "
        "when disabled, for the same reason as plugin 1010: delegation "
        "settings are configuration that persists regardless of account "
        "state, and reactivate immediately if the account is re-enabled."
    ),
    "base_severity": "high",
    "query": """
        SELECT
            'fail' AS status,
            u.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'high' AS fd_severity,
            'User Account ' || COALESCE(u.user_principal_name, u.sam_account_name)
                || ' has constrained delegation with protocol transition (S4U2Self) enabled' AS summary,
            jsonb_build_object(
                'sam_account_name', u.sam_account_name,
                'user_principal_name', u.user_principal_name,
                'user_account_control', u.user_account_control,
                'admin_count', u.admin_count
            ) AS detail
        FROM ad_user u
        WHERE u.valid_to IS NULL
          AND u.client_id = %(client_id)s
          AND u.is_enabled
          AND u.user_account_control IS NOT NULL
          AND (u.user_account_control & 16777216) != 0
    """,
}

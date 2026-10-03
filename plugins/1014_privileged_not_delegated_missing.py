"""
Plugin 1014: Privileged Account Missing "Cannot Be Delegated" Protection

The NOT_DELEGATED UAC bit (0x100000) prevents this account's security
context from being delegated even to a service explicitly trusted for
delegation -- a specific, independent protection against delegation-based
impersonation, distinct from (and complementary to) Protected Users
membership. Soft recommendation for privileged accounts specifically.

[v1.5] "Privileged" now comes from the shared Tier 0 view
v_privileged_principal (schema v34) instead of an inline subquery that
counted GenericAll/GenericWrite/WriteDACL/WriteOwner on, or ownership of,
ANY object with a collected ACL -- every OU, every certificate template --
so OU delegates and whoever created an OU were treated as privileged.
Protected-group membership, control of or ownership of a Tier 0 object
(domain root, AdminSDHolder, DCs, CAs, ...), DCSync, and membership in a
group holding any of those still count. detail gains privilege_sources
(the view's reasons, sorted); summary wording is unchanged.
"""

PLUGIN = {
    "plugin_id": 1014,
    "category": "User Accounts",
    "name": "Privileged Account Missing NOT_DELEGATED Protection",
    "version": "1.5",
    "revision_date": "2026-10-03",
    "remediation": (
    'Enable the "account is sensitive and cannot be delegated" flag '
    "(NOT_DELEGATED) for the account via ADUC's Account tab or "
    '`Set-ADAccountControl -AccountNotDelegated $true`.'
),
    "control_id": "PRIV-105",
    "framework_tags": [],
    "references": [
        {"title": "MITRE ATT&CK T1558: Steal or Forge Kerberos Tickets",
         "url": "https://attack.mitre.org/techniques/T1558/"},
    ],
    "description": (
        "The NOT_DELEGATED UAC bit (0x100000) prevents this account's "
        "security context from being delegated to a service even if that "
        "service is trusted for Kerberos delegation -- a specific, "
        "independent protection against delegation-based impersonation "
        "attacks, distinct from Protected Users group membership. Soft "
        "recommendation, evaluated only against already-privileged "
        "accounts here; not every organization enables this broadly, so "
        "treat as informational context rather than a standalone "
        "compliance failure."
    ),
    "base_severity": "low",
    "query": """
        WITH privileged_check AS (
            -- [v1.5] "Privileged" is the shared Tier 0 definition in
            -- v_privileged_principal (schema v34): membership, direct or
            -- nested, in an AdminSDHolder-protected group; a control right
            -- (GenericAll/GenericWrite/WriteDACL/WriteOwner) on, or
            -- ownership of, a Tier 0 object; DCSync on the domain root; or
            -- membership in a group that holds any of those. The inline
            -- subquery this replaces counted such a right on, or ownership
            -- of, ANY object with a collected ACL, so every OU delegate and
            -- OU creator was treated as privileged.
            SELECT object_guid,
                   array_agg(DISTINCT privilege_source ORDER BY privilege_source) AS privilege_sources
            FROM v_privileged_principal
            WHERE client_id = %(client_id)s
            GROUP BY object_guid
        )
        SELECT
            'warn' AS status,
            u.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN u.is_enabled THEN 'low' ELSE 'info' END AS fd_severity,
            'Privileged User Account ' || COALESCE(u.user_principal_name, u.sam_account_name)
                || ' does not have the "account is sensitive and cannot be delegated" '
                || 'protection enabled'
                || CASE WHEN NOT u.is_enabled
                        THEN ' (severity reduced: account is disabled)'
                        ELSE '' END AS summary,
            jsonb_build_object(
                'sam_account_name', u.sam_account_name,
                'user_principal_name', u.user_principal_name,
                'is_enabled', u.is_enabled,
                'admin_count', u.admin_count,
                'privileged_group_member', pc.object_guid IS NOT NULL,
                'privilege_sources', pc.privilege_sources
            ) AS detail
        FROM ad_user u
        LEFT JOIN privileged_check pc
            ON pc.object_guid = u.object_guid
        WHERE u.valid_to IS NULL
          AND u.client_id = %(client_id)s
          AND u.user_account_control IS NOT NULL
          AND (u.user_account_control & 1048576) = 0
          AND (u.admin_count = 1 OR pc.object_guid IS NOT NULL)
    """,
}

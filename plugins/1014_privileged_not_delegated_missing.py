"""
Plugin 1014: Privileged Account Missing "Cannot Be Delegated" Protection

The NOT_DELEGATED UAC bit (0x100000) prevents this account's security
context from being delegated even to a service explicitly trusted for
delegation -- a specific, independent protection against delegation-based
impersonation, distinct from (and complementary to) Protected Users
membership. Soft recommendation for privileged accounts specifically.
"""

PLUGIN = {
    "plugin_id": 1014,
    "category": "User Accounts",
    "name": "Privileged Account Missing NOT_DELEGATED Protection",
    "version": "1.4",
    "revision_date": "2026-07-15",
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
            -- [v1.x, ACL-aware] "Privileged" now means group-membership-based
            -- privilege (the original, sole definition) OR ACL-derived
            -- privilege: directly holding a dangerous right or DCSync rights
            -- on the domain root/AdminSDHolder, or owning either object.
            -- A user with none of the classic admin-group memberships but
            -- who directly holds GenericAll on the domain root is privileged
            -- in every meaningful sense -- arguably more concerning than a
            -- managed Domain Admin, since this kind of privilege is often
            -- unmanaged/accidental rather than deliberately delegated.
            SELECT DISTINCT vem.member_guid AS object_guid
            FROM v_effective_group_membership vem
            JOIN directory_object pgo
                ON pgo.object_guid = vem.group_guid AND pgo.client_id = vem.client_id
            JOIN ad_group pg
                ON pg.object_guid = pgo.object_guid AND pg.valid_to IS NULL
            WHERE vem.client_id = %(client_id)s
              AND pg.is_protected_group
            UNION
            SELECT do_acl.object_guid
            FROM acl_edge a
            JOIN directory_object do_acl ON do_acl.object_sid = a.trustee_sid AND do_acl.client_id = a.client_id
            WHERE a.client_id = %(client_id)s
              AND a.valid_to IS NULL
              AND a.ace_type = 'allow'
              AND (
                    (a.access_mask & (268435456 | 1073741824 | 262144 | 524288)) != 0
                    OR a.object_type_guid IN ('1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',
                                               '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2')
                  )
            UNION
            SELECT do_owner.object_guid
            FROM directory_object owned_target
            JOIN directory_object do_owner
                ON do_owner.object_sid = owned_target.owner_sid AND do_owner.client_id = owned_target.client_id
            WHERE owned_target.client_id = %(client_id)s
              AND owned_target.owner_sid IS NOT NULL
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
                'privileged_group_member', pc.object_guid IS NOT NULL
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

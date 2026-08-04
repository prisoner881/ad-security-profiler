"""
Plugin 1015: Privileged Account Not a Member of Protected Users

The Protected Users group (Windows Server 2012 R2+) forces a bundle of
hardening on its members simultaneously: no NTLM, no DES/RC4 Kerberos,
no delegation of any kind, shorter ticket lifetimes, no cached
credentials. Microsoft's own recommended hardening step for Tier-0
accounts specifically. Soft recommendation, not a hard finding.
"""

PLUGIN = {
    "plugin_id": 1015,
    "category": "User Accounts",
    "name": "Privileged Account Not a Member of Protected Users",
    "version": "1.4",
    "revision_date": "2026-07-15",
    "remediation": (
    'Add the account to the Protected Users group -- but test in a '
    'non-production/staging context first. Protected Users membership disables '
    'NTLM, DES/RC4 Kerberos, delegation, and credential caching for the account '
    'entirely; any legacy application or workflow depending on those will break '
    'immediately upon membership. A phased rollout starting with the '
    'highest-value Tier-0 accounts, with monitoring for authentication failures '
    'after each addition, is the standard recommended approach rather than '
    'adding every privileged account at once.'
),
    "control_id": "PRIV-106",
    "framework_tags": [],
    "references": [
        {"title": "Microsoft: Protected Users Security Group in Windows Server",
         "url": "https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group"},
    ],
    "description": (
        "The Protected Users group forces a bundle of hardening on its "
        "members: no NTLM authentication, no DES or RC4 Kerberos "
        "encryption, no Kerberos delegation of any kind, shorter maximum "
        "ticket lifetimes, and no cached credentials on the "
        "authenticating host. This is Microsoft's own recommended "
        "hardening step specifically for Tier-0/highly-privileged "
        "accounts. Soft recommendation -- adopting Protected Users has "
        "real operational implications (some legacy auth stops working "
        "entirely for members) and needs deliberate rollout, not blanket "
        "enablement."
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
                || ' is not a member of the Protected Users group'
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
          AND NOT u.protected_users_member
          AND (u.admin_count = 1 OR pc.object_guid IS NOT NULL)
    """,
}

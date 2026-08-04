"""
Plugin 1002: Password Not Required (PASSWD_NOTREQD)

The PASSWD_NOTREQD UAC bit (0x0020) permits an account to be assigned a
blank password, bypassing the domain password policy entirely -- not just
weakening it the way pwd_never_expires does. Confirmed as a real,
well-known finding by BloodHound's own Cypher query for this exact
condition (MATCH (n:User {enabled: True, passwordnotreqd: True})).
"""

PLUGIN = {
    "plugin_id": 1002,
    "category": "User Accounts",
    "name": "Enabled User Account Does Not Require a Password",
    "version": "1.4",
    "revision_date": "2026-07-15",
    "remediation": (
    'Remove the PASSWD_NOTREQD flag (`Set-ADAccountControl -PasswordNotRequired '
    '$false` or the equivalent ADUC checkbox), then immediately force a '
    'policy-compliant password reset on the account -- removing the flag alone '
    'does not retroactively validate whatever password (if any) is currently '
    'set. Investigate why the flag was set in the first place; a legacy '
    'application requirement is the most common legitimate reason, and if '
    "that's confirmed still necessary, document it explicitly as an accepted "
    'exception rather than leaving it unexplained.'
),
    "control_id": "CRED-002",
    "framework_tags": [],
    "references": [],
    "description": (
        "The PASSWD_NOTREQD flag (userAccountControl bit 0x0020) permits "
        "this account to be assigned a blank password, bypassing the "
        "domain's password policy entirely -- not merely weakening it. "
        "No DISA AD STIG rule directly and solely covers this specific "
        "flag; BloodHound's own attack-path tooling checks for this exact "
        "condition (enabled + passwordnotreqd) as a real attack surface item."
    ),
    "base_severity": "high",
    # Disabled accounts get a two-level severity downgrade (floored at
    # info), same reasoning and mechanism as plugin 1001: this finding is
    # about being able to authenticate with a blank password, which a
    # disabled account cannot do regardless of what its password is.
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
            'fail' AS status,
            u.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            'high' AS tool_severity,
            'BloodHound: attack-path query for enabled + PASSWD_NOTREQD accounts '
                '(a blank-password-eligible account is directly requestable without '
                'any credential guess)' AS tool_reference,
            CASE GREATEST(0,
                GREATEST(
                    CASE WHEN oc.tier = 0 THEN 4 WHEN oc.tier = 1 THEN 3 ELSE 3 END,
                    CASE WHEN u.admin_count = 1 OR pc.object_guid IS NOT NULL THEN 3 ELSE 3 END
                ) - (CASE WHEN u.is_enabled THEN 0 ELSE 2 END)
            )
                WHEN 4 THEN 'critical'
                WHEN 3 THEN 'high'
                WHEN 2 THEN 'medium'
                WHEN 1 THEN 'low'
                ELSE 'info'
            END AS fd_severity,
            (CASE
                WHEN oc.tier = 0 THEN 'Tier-0 '
                WHEN oc.tier = 1 THEN 'Tier-1 '
                WHEN u.admin_count = 1 OR pc.object_guid IS NOT NULL THEN 'Privileged '
                ELSE ''
             END)
                || 'User Account ' || COALESCE(u.user_principal_name, u.sam_account_name)
                || ' does not require a password (PASSWD_NOTREQD)'
                || CASE WHEN NOT u.is_enabled
                        THEN ' (severity reduced: account is disabled)'
                        ELSE '' END AS summary,
            jsonb_build_object(
                'sam_account_name', u.sam_account_name,
                'user_principal_name', u.user_principal_name,
                'user_account_control', u.user_account_control,
                'is_enabled', u.is_enabled,
                'last_logon_timestamp', u.last_logon_timestamp,
                'admin_count', u.admin_count,
                'tier', oc.tier,
                'privileged_group_member', pc.object_guid IS NOT NULL
            ) AS detail
        FROM ad_user u
        LEFT JOIN object_classification oc
            ON oc.object_guid = u.object_guid AND oc.client_id = u.client_id
        LEFT JOIN privileged_check pc
            ON pc.object_guid = u.object_guid
        WHERE u.valid_to IS NULL
          AND u.client_id = %(client_id)s
          AND (u.user_account_control & 32) != 0
    """,
}

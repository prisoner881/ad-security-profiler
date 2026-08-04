"""
Plugin 1013: AS-REP Roastable Account (Kerberos Pre-Authentication Disabled)

DONT_REQ_PREAUTH (0x400000) lets anyone who knows or guesses this
account's username request an AS-REP from the KDC with zero valid
credentials -- not even a wrong password attempt is needed. The encrypted
portion is derived from the account's password and can be cracked
offline. More dangerous than Kerberoasting in one specific way: no
authentication of any kind is a prerequisite.
"""

PLUGIN = {
    "plugin_id": 1013,
    "category": "User Accounts",
    "name": "AS-REP Roastable Account (Kerberos Pre-Authentication Disabled)",
    "version": "1.5",
    "revision_date": "2026-07-15",
    "remediation": (
    'Remove the DONT_REQ_PREAUTH flag to re-enable Kerberos pre-authentication. '
    'There is essentially no legitimate reason to leave this disabled on a '
    'modern, all-Windows-Kerberos-client AD environment -- it historically '
    'existed for certain non-Windows Kerberos client compatibility scenarios '
    'that are now rare; confirm no such legacy client actually depends on it '
    "before assuming it's safe to change, but treat that as the exception to "
    'investigate, not the default assumption.'
),
    "control_id": "CRED-007",
    "framework_tags": [],
    "references": [
        {"title": "MITRE ATT&CK T1558.004: Steal or Forge Kerberos Tickets -- AS-REP Roasting",
         "url": "https://attack.mitre.org/techniques/T1558/004/"},
    ],
    "description": (
        "The DONT_REQ_PREAUTH UAC bit (0x400000) lets anyone who knows or "
        "guesses this account's username request an AS-REP from the KDC "
        "without presenting any credentials at all -- not even a failed "
        "password attempt occurs. The encrypted portion of that response "
        "is derived from the account's password and can be extracted and "
        "cracked entirely offline. This is operationally more dangerous "
        "than Kerberoasting in one specific respect: Kerberoasting "
        "requires a valid authenticated domain identity to request a "
        "service ticket; this does not require any valid credentials at "
        "all, only a correctly-guessed username."
    ),
    "base_severity": "high",
    # Even though disabled accounts genuinely cannot be AS-REP roasted
    # (KDC_ERR_CLIENT_REVOKED fires on the AS-REQ itself -- this is
    # foundational Kerberos protocol behavior, not tool-dependent), the
    # finding is still shown at floored severity rather than excluded
    # entirely, for audit completeness and because the account could be
    # re-enabled at any time.
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
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE GREATEST(0,
                GREATEST(
                    CASE WHEN oc.tier = 0 THEN 4 WHEN oc.tier = 1 THEN 4 ELSE 3 END,
                    CASE WHEN u.admin_count = 1 OR pc.object_guid IS NOT NULL THEN 4 ELSE 3 END
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
                || ' does not require Kerberos pre-authentication (AS-REP roastable)'
                || CASE WHEN NOT u.is_enabled
                        THEN ' (Disabled Account)'
                        ELSE '' END AS summary,
            jsonb_build_object(
                'sam_account_name', u.sam_account_name,
                'user_principal_name', u.user_principal_name,
                'is_enabled', u.is_enabled,
                'pwd_last_set', u.pwd_last_set,
                'password_age_days', CASE WHEN u.pwd_last_set IS NOT NULL
                                           THEN EXTRACT(DAY FROM now() - u.pwd_last_set)::int
                                           ELSE NULL END,
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
          AND u.user_account_control IS NOT NULL
          AND (u.user_account_control & 4194304) != 0
    """,
}

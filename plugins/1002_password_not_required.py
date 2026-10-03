"""
Plugin 1002: Password Not Required (PASSWD_NOTREQD)

The PASSWD_NOTREQD UAC bit (0x0020) permits an account to be assigned a
blank password, bypassing the domain password policy entirely -- not just
weakening it the way pwd_never_expires does. Confirmed as a real,
well-known finding by BloodHound's own Cypher query for this exact
condition (MATCH (n:User {enabled: True, passwordnotreqd: True})).

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
    "plugin_id": 1002,
    "category": "User Accounts",
    "name": "Enabled User Account Does Not Require a Password",
    "version": "1.5",
    "revision_date": "2026-10-03",
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
                'privileged_group_member', pc.object_guid IS NOT NULL,
                'privilege_sources', pc.privilege_sources
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

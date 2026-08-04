"""
Plugin 1001: User Account Password Set to Never Expire

Enabled user accounts configured to never require a password change bypass
the domain's maximum password age policy entirely, regardless of how that
policy is configured.
"""

PLUGIN = {
    "plugin_id": 1001,
    "category": "User Accounts",
    "name": "User Account Password Set to Never Expire",
    "version": "1.4",
    "revision_date": "2026-07-15",
    "remediation": (
    'Remove the DONT_EXPIRE_PASSWORD flag (uncheck "Password never expires" in '
    'ADUC, or `Set-ADUser -PasswordNeverExpires $false`) and let the account '
    "fall under the domain's standard password expiration policy or an "
    'appropriate Fine-Grained Password Policy. For service accounts '
    'specifically -- the most common legitimate reason this flag gets set, '
    'usually to avoid an outage from an expired password -- the better '
    'long-term fix is migrating to a Group Managed Service Account (gMSA), '
    'which handles its own automatic password rotation with no service downtime '
    'risk, removing the need for this flag entirely rather than just tolerating '
    'it.'
),

    # Optional -- used for compliance-framework mapping (control_catalog).
    # A plugin doesn't need one if it isn't tied to a formal control.
    "control_id": "CRED-001",
    "framework_tags": ["DISA-STIG"],
    "references": [],
    "description": (
        "Enabled user accounts configured to never require a password "
        "change bypass the domain's maximum password age policy entirely, "
        "regardless of how that policy is configured. Comparable to DISA "
        "Windows Server STIG WN22-AC-000050 (V-254289, CAT II) at the "
        "individual-account level, and to PingCastle's \"non-expiring "
        "password\" rule (Stale Objects)."
    ),

    # This control's baseline severity before any tier-based adjustment --
    # what fd_severity resolves to for an account with no tier classification.
    "base_severity": "medium",

    # The plugin itself. Must return zero or more rows shaped exactly as:
    # (status, object_guid, stig_severity, stig_reference, tool_severity,
    #  tool_reference, fd_severity, summary, detail). Zero rows = clean
    # pass. May reference %(client_id)s / %(run_id)s as bound parameters --
    # always parameter-bound by the runner, never string-interpolated.
    #
    # fd_severity is escalated by two independent signals, combined as
    # worst-of-two (not stacked/summed):
    #   - object_classification.tier (0 -> critical, 1 -> high) -- the
    #     authoritative signal, once populated; currently unpopulated on
    #     every real deployment so far, which is why this alone wasn't
    #     enough to differentiate real findings.
    #   - "privileged" via admin_count=1 OR current/nested membership in
    #     an AdminSDHolder-protected group (ad_group.is_protected_group,
    #     already verified against real data; membership resolved through
    #     v_effective_group_membership so nested privilege is caught, not
    #     just direct) -- treated as 'high', available today with no
    #     dependency on tier ever being populated.
    #
    # A disabled account is then floor(0)-capped two severity levels
    # DOWN from whatever the above computed: this finding is fundamentally
    # about being able to authenticate as the account, and a disabled
    # account cannot authenticate via normal logon at all, regardless of
    # whether the password is known -- a near-complete closure of the
    # specific risk, not a marginal one. Never dropped from the report
    # entirely, since the account could be re-enabled at any time, at
    # which point the next collection run naturally restores full
    # severity with no extra logic needed.
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
            'CAT_II' AS stig_severity,
            'DISA Windows Server STIG WN22-AC-000050 (V-254289): maximum '
                'password age must be 60 days or less -- pwd_never_expires '
                'bypasses this control entirely at the account level' AS stig_reference,
            'medium' AS tool_severity,
            'PingCastle: "Non expiring password" (Stale Objects category)' AS tool_reference,
            CASE GREATEST(0,
                GREATEST(
                    CASE WHEN oc.tier = 0 THEN 4 WHEN oc.tier = 1 THEN 3 ELSE 2 END,
                    CASE WHEN u.admin_count = 1 OR pc.object_guid IS NOT NULL THEN 3 ELSE 2 END
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
                || ' has a password set to never expire'
                || CASE WHEN NOT u.is_enabled
                        THEN ' (severity reduced: account is disabled)'
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
          AND u.pwd_never_expires
    """,
}

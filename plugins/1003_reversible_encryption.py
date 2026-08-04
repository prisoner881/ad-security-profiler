"""
Plugin 1003: Reversible Encryption Enabled

Storing a password using reversible encryption is functionally equivalent
to storing it in plaintext -- anyone who can read the stored value (any
DC, or an attacker with DCSync-equivalent access) can recover the actual
password, not just a hash. This is a rare setting to find enabled and
should essentially always be treated as a real finding when it is.
"""

PLUGIN = {
    "plugin_id": 1003,
    "category": "User Accounts",
    "name": "User Account Password Stored Using Reversible Encryption",
    "version": "1.4",
    "revision_date": "2026-07-15",
    "remediation": (
    'Remove the reversible-encryption UAC flag, then force a password reset -- '
    'unlike most UAC changes, simply clearing this flag does not purge the '
    'already-stored recoverable password; a new password must actually be set '
    'to invalidate the exposed one. Identify and migrate away from whatever '
    'legacy CHAP/Digest authentication requirement caused this to be enabled, '
    'since modern authentication protocols have no legitimate need for it.'
),
    "control_id": "CRED-003",
    "framework_tags": [],
    "references": [
        {"title": "Microsoft: Store passwords using reversible encryption",
         "url": "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption"},
    ],
    "description": (
        "Storing a password with reversible encryption is functionally "
        "equivalent to storing it in plaintext -- the actual password, "
        "not just a hash, can be recovered by anyone able to read the "
        "stored value. This is a well-known, universally-discouraged AD "
        "anti-pattern with essentially no legitimate modern use case "
        "(historically used for specific legacy CHAP/Digest auth "
        "scenarios). No specific STIG/tool citation is asserted here "
        "without direct confirmation; severity is reasoned directly from "
        "the impact (full plaintext credential exposure) rather than a "
        "borrowed rating. NOT downgraded when the account is disabled: "
        "unlike findings that require the ability to authenticate, the "
        "recoverable password material already sits in AD's database "
        "regardless of the account's enabled state, and remains fully "
        "exploitable via DCSync-equivalent access -- disabling this "
        "account does not remove or reduce that exposure, and if the "
        "same password is reused anywhere else, that reuse risk is "
        "entirely unaffected by this account's state too."
    ),
    "base_severity": "critical",
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
            'critical' AS fd_severity,
            (CASE
                WHEN oc.tier = 0 THEN 'Tier-0 '
                WHEN oc.tier = 1 THEN 'Tier-1 '
                WHEN u.admin_count = 1 OR pc.object_guid IS NOT NULL THEN 'Privileged '
                ELSE ''
             END)
                || 'User Account ' || COALESCE(u.user_principal_name, u.sam_account_name)
                || ' stores its password using reversible encryption' AS summary,
            jsonb_build_object(
                'sam_account_name', u.sam_account_name,
                'user_principal_name', u.user_principal_name,
                'is_enabled', u.is_enabled,
                'pwd_last_set', u.pwd_last_set,
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
          AND u.reversible_encryption
    """,
}

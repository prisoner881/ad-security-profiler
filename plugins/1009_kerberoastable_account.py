"""
Plugin 1009: Kerberoastable User Account (SPN Set on a User Account)

Any user account with a registered SPN can be Kerberoasted by any
authenticated domain user -- request a service ticket for it, take the
ticket offline, and attempt to crack it without triggering a single
failed logon. This is normal/expected for computer accounts (excluded
here) but is a real, well-known finding whenever it occurs on a user
account, and considerably more severe when that user account is also
privileged.
"""

PLUGIN = {
    "plugin_id": 1009,
    "category": "User Accounts",
    "name": "Kerberoastable User Account (SPN Registered)",
    "version": "1.3",
    "revision_date": "2026-07-15",
    "remediation": (
    'Where possible, eliminate the need for this account to be a standalone '
    'service account with an SPN at all by migrating to a Group Managed Service '
    'Account (gMSA) -- gMSA passwords are long, random, and automatically '
    'rotated, making them impractical to crack offline even if Kerberoasted. '
    "Where gMSA migration isn't feasible, ensure the account has a long, "
    'high-entropy password (25+ characters) and AES-only Kerberos encryption '
    '(disable RC4 support specifically) so an obtained ticket is not '
    'realistically crackable even if captured.'
),
    "control_id": "CRED-005",
    "framework_tags": ["MITRE-ATTCK-T1558.003"],
    "references": [
        {"title": "MITRE ATT&CK T1558.003: Kerberoasting",
         "url": "https://attack.mitre.org/techniques/T1558/003/"},
    ],
    "description": (
        "Any authenticated domain user can request a Kerberos service "
        "ticket for an account with a registered SPN and attempt to crack "
        "it offline (Kerberoasting) -- no failed logon is generated in "
        "the process. This is routine for computer accounts (excluded "
        "here) but a genuine finding on a user account, since it means "
        "that account's effective password strength is the only defense "
        "against offline cracking. Comparable to PingCastle's "
        "Kerberoasting-relevant checks in its Privileged Accounts "
        "category (exact rule name/points not independently confirmed "
        "this session -- general comparability noted, not a precise "
        "citation)."
    ),
    "base_severity": "medium",
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
            'medium' AS tool_severity,
            'Comparable to PingCastle''s Kerberoasting-relevant privileged-account '
                'checks (general comparability, not an exact quoted rule)' AS tool_reference,
            CASE GREATEST(
                CASE WHEN oc.tier = 0 THEN 4 WHEN oc.tier = 1 THEN 3 ELSE 2 END,
                CASE WHEN u.admin_count = 1 OR pc.object_guid IS NOT NULL THEN 3 ELSE 2 END
            )
                WHEN 4 THEN 'critical'
                WHEN 3 THEN 'high'
                ELSE 'medium'
            END AS fd_severity,
            (CASE
                WHEN oc.tier = 0 THEN 'Tier-0 '
                WHEN oc.tier = 1 THEN 'Tier-1 '
                WHEN u.admin_count = 1 OR pc.object_guid IS NOT NULL THEN 'Privileged '
                ELSE ''
             END)
                || 'User Account ' || COALESCE(u.user_principal_name, u.sam_account_name)
                || ' is Kerberoastable (SPN registered on a user account)' AS summary,
            jsonb_build_object(
                'sam_account_name', u.sam_account_name,
                'user_principal_name', u.user_principal_name,
                'service_principal_names', u.service_principal_names,
                'pwd_last_set', u.pwd_last_set,
                'supported_encryption_types', u.supported_encryption_types,
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
          AND u.is_enabled
          AND u.service_principal_names IS NOT NULL
          AND array_length(u.service_principal_names, 1) > 0
    """,
}

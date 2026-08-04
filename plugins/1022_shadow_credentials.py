"""
Plugin 1022: Account Has Shadow Credentials (msDS-KeyCredentialLink) Registered

Presence is not itself evidence of compromise -- legitimate on any
Windows Hello for Business or hybrid-Entra-join-enrolled account. Flagged
as a data point worth reviewing, not a confirmed finding: full validation
(is this key legitimate, does the DeviceID match a real enrolled device)
needs cross-referencing with Entra/Intune device records, which this
read-only on-prem collector has no visibility into.
"""

PLUGIN = {
    "plugin_id": 1022,
    "category": "User Accounts",
    "name": "Account Has Shadow Credentials (msDS-KeyCredentialLink) Registered",
    "version": "1.4",
    "revision_date": "2026-07-15",
    "remediation": (
    "Review each entry's legitimacy by cross-referencing against known Windows "
    'Hello for Business or hybrid-Entra-join device enrollment records for that '
    "user. Remove any key credential entries that can't be confirmed as "
    "legitimate device enrollments. If an entry can't be attributed to a known, "
    'expected enrollment, investigate who or what held the delegated rights '
    'needed to write msDS-KeyCredentialLink on this account -- writing this '
    'attribute requires specific elevated rights, so an illegitimate entry '
    'implies a separate privilege issue worth finding, not just a key to '
    'delete.'
),
    "control_id": "CRED-010",
    "framework_tags": ["MITRE-ATTCK-T1556"],
    "references": [
        {"title": "MITRE ATT&CK T1556: Modify Authentication Process",
         "url": "https://attack.mitre.org/techniques/T1556/"},
    ],
    "description": (
        "msDS-KeyCredentialLink stores Key Credential material used for "
        "passwordless authentication (Windows Hello for Business) via "
        "PKINIT. Anyone with write access to this attribute on an "
        "account (GenericWrite, GenericAll, or explicit attribute-level "
        "write) can add a rogue key and authenticate as that account via "
        "PKINIT without ever touching its password -- the 'Shadow "
        "Credentials' technique (MITRE ATT&CK T1556). Presence alone is "
        "NOT evidence of compromise; it is entirely legitimate on any "
        "WHfB-enrolled or hybrid-Entra-joined account, and this finding "
        "will fire broadly in any environment using either. Full "
        "validation of whether a given entry is legitimate requires "
        "cross-referencing its DeviceID against real Entra/Intune device "
        "records -- out of scope for this read-only on-prem AD "
        "collector. Flagged as a data point worth review, particularly "
        "on accounts that would not normally be expected to use WHfB "
        "(most service accounts), not as a confirmed finding."
    ),
    "base_severity": "low",
    # Shadow Credentials authenticate via PKINIT, which -- like normal
    # password auth -- goes through the AS-REQ exchange, so the same
    # protocol-level reasoning as plugin 1013 should extend here: a
    # disabled account's AS-REQ should be rejected regardless of whether
    # PKINIT or a password is being used. Downgraded, not excluded, for
    # the same audit-completeness/re-enablement reasoning as elsewhere.
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
            CASE GREATEST(0,
                GREATEST(
                    CASE WHEN oc.tier = 0 THEN 3 WHEN oc.tier = 1 THEN 2 ELSE 1 END,
                    CASE WHEN u.admin_count = 1 OR pc.object_guid IS NOT NULL THEN 2 ELSE 1 END
                ) - (CASE WHEN u.is_enabled THEN 0 ELSE 2 END)
            )
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
                || ' has ' || u.key_credential_count || ' Shadow Credential(s) registered '
                || '-- review for legitimacy, not automatically a finding'
                || CASE WHEN NOT u.is_enabled
                        THEN ' (severity reduced: account is disabled)'
                        ELSE '' END AS summary,
            jsonb_build_object(
                'sam_account_name', u.sam_account_name,
                'user_principal_name', u.user_principal_name,
                'is_enabled', u.is_enabled,
                'key_credential_count', u.key_credential_count,
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
          AND u.key_credential_count IS NOT NULL
          AND u.key_credential_count > 0
    """,
}

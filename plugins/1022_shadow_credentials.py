"""
Plugin 1022: Account Has Shadow Credentials (msDS-KeyCredentialLink) Registered

Presence is not itself evidence of compromise -- legitimate on any
Windows Hello for Business or hybrid-Entra-join-enrolled account. Flagged
as a data point worth reviewing, not a confirmed finding: full validation
(is this key legitimate, does the DeviceID match a real enrolled device)
needs cross-referencing with Entra/Intune device records, which this
read-only on-prem collector has no visibility into.

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
    "plugin_id": 1022,
    "category": "User Accounts",
    "name": "Account Has Shadow Credentials (msDS-KeyCredentialLink) Registered",
    "version": "1.5",
    "revision_date": "2026-10-03",
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
          AND u.key_credential_count IS NOT NULL
          AND u.key_credential_count > 0
    """,
}

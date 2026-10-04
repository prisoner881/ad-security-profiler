"""
Plugin 1003: Reversible Encryption Enabled

Storing a password using reversible encryption is functionally equivalent
to storing it in plaintext -- anyone who can read the stored value (any
DC, or an attacker with DCSync-equivalent access) can recover the actual
password, not just a hash. This is a rare setting to find enabled and
should essentially always be treated as a real finding when it is.

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
    "plugin_id": 1003,
    "category": "User Accounts",
    "name": "User Account Password Stored Using Reversible Encryption",
    "version": "1.5",
    "revision_date": "2026-10-03",
    "remediation": (
    'Remove the reversible-encryption UAC flag, then force a password reset -- '
    'unlike most UAC changes, simply clearing this flag does not purge the '
    'already-stored recoverable password; a new password must actually be set '
    'to invalidate the exposed one. Identify and migrate away from whatever '
    'legacy CHAP/Digest authentication requirement caused this to be enabled, '
    'since modern authentication protocols have no legitimate need for it.'
),
    "control_id": "CRED-003",
    "framework_tags": [
        "NIST-800-53-IA-5(1)",
        "NIST-800-53-SC-28",
        "NIST-CSF-2.0-PR.DS-01",
        "PCI-DSS-4.0-8.3.2",
        "PCI-DSS-4.0-8.6.2",
        "CIS-CSC-8-3.11",
        "ISO-27001-2022-A.5.17",
        "SOC2-CC6.1",
        "HIPAA-164.312(a)(2)(iv)",
        "MITRE-ATTCK-T1003.006",
    ],
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
          AND u.reversible_encryption
    """,
}

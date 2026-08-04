"""
Plugin 1019: DES-Only Kerberos Encryption Enforced (USE_DES_KEY_ONLY)

USE_DES_KEY_ONLY (0x200000) is the older, Windows 2000/2003-era UAC
mechanism for restricting an account to DES exclusively -- distinct from
(and independent of) the newer msDS-SupportedEncryptionTypes attribute
checked by plugin 1011. Worse than 1011's finding: this doesn't just
permit DES alongside other types, it forces DES and only DES.
"""

PLUGIN = {
    "plugin_id": 1019,
    "category": "User Accounts",
    "name": "User Account Restricted to DES-Only Kerberos Encryption",
    "version": "1.2",
    "revision_date": "2026-07-15",
    "remediation": (
    'Remove the USE_DES_KEY_ONLY UAC flag entirely -- this is a legacy Windows '
    '2000/2003-era mechanism with essentially no modern legitimate use case. '
    'After removing it, verify msDS-SupportedEncryptionTypes is separately '
    'configured with AES support (see the companion DES-encryption-types '
    "finding) so the account isn't left without any explicitly configured "
    'encryption type at all.'
),
    "control_id": "CRED-008",
    "framework_tags": [],
    "references": [
        {"title": "Microsoft: Network security -- Configure encryption types allowed for Kerberos",
         "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-configure-encryption-types-allowed-for-kerberos"},
    ],
    "description": (
        "The USE_DES_KEY_ONLY UAC bit (0x200000) is the older, Windows "
        "2000/2003-era mechanism for restricting an account to DES "
        "exclusively -- independent of, and potentially conflicting with, "
        "the newer msDS-SupportedEncryptionTypes attribute (plugin 1011). "
        "Worse than plugin 1011's finding specifically because this "
        "forces DES-only rather than merely permitting DES alongside "
        "stronger types."
    ),
    "base_severity": "high",
    "query": """
        SELECT
            'fail' AS status,
            u.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'high' AS fd_severity,
            'User Account ' || COALESCE(u.user_principal_name, u.sam_account_name)
                || ' is restricted to DES-only Kerberos encryption (USE_DES_KEY_ONLY)' AS summary,
            jsonb_build_object(
                'sam_account_name', u.sam_account_name,
                'user_principal_name', u.user_principal_name,
                'user_account_control', u.user_account_control,
                'supported_encryption_types', u.supported_encryption_types
            ) AS detail
        FROM ad_user u
        WHERE u.valid_to IS NULL
          AND u.client_id = %(client_id)s
          AND u.is_enabled
          AND u.user_account_control IS NOT NULL
          AND (u.user_account_control & 2097152) != 0
    """,
}

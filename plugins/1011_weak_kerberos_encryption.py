"""
Plugin 1011: Weak/Legacy Kerberos Encryption Types Enabled (DES)

msDS-SupportedEncryptionTypes bits 0x1 (DES-CBC-CRC) and 0x2 (DES-CBC-MD5)
enable DES for this account's Kerberos tickets. DES is cryptographically
broken and has been deprecated/disabled by default in Windows for years;
an account with these bits explicitly set represents a deliberate
downgrade, not just an absence of modern encryption.
"""

PLUGIN = {
    "plugin_id": 1011,
    "category": "User Accounts",
    "name": "User Account Supports Deprecated DES Kerberos Encryption",
    "version": "1.2",
    "revision_date": "2026-07-15",
    "remediation": (
    'Update msDS-SupportedEncryptionTypes to remove the DES bits, leaving AES '
    '(and RC4 only if still genuinely required during a migration window) -- a '
    'value of 24 (AES128+AES256 only) is the modern target for most '
    'environments. Audit for any legacy system that might actually depend on '
    'DES specifically before removing it; such systems should be a priority for '
    'replacement, not a reason to leave this enabled indefinitely.'
),
    "control_id": "CRED-006",
    "framework_tags": ["DISA-STIG"],
    "references": [
        {"title": "Microsoft: Network security -- Configure encryption types allowed for Kerberos",
         "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-configure-encryption-types-allowed-for-kerberos"},
    ],
    "description": (
        "msDS-SupportedEncryptionTypes bits 0x1 (DES-CBC-CRC) and 0x2 "
        "(DES-CBC-MD5) enable the DES encryption type for this account's "
        "Kerberos tickets. DES is cryptographically broken and has been "
        "disabled by default in Windows Kerberos for years; an account "
        "with these bits explicitly set represents a deliberate "
        "downgrade, not merely an absence of AES support. Weak/legacy "
        "Kerberos encryption types are a recurring theme across DISA "
        "Windows STIG families; a specific AD-domain-level V-ID for this "
        "exact per-account bit was not directly confirmed this session."
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
                || ' has deprecated DES Kerberos encryption enabled' AS summary,
            jsonb_build_object(
                'sam_account_name', u.sam_account_name,
                'user_principal_name', u.user_principal_name,
                'supported_encryption_types', u.supported_encryption_types,
                'des_cbc_crc_enabled', (u.supported_encryption_types & 1) != 0,
                'des_cbc_md5_enabled', (u.supported_encryption_types & 2) != 0
            ) AS detail
        FROM ad_user u
        WHERE u.valid_to IS NULL
          AND u.client_id = %(client_id)s
          AND u.is_enabled
          AND u.supported_encryption_types IS NOT NULL
          AND (u.supported_encryption_types & 3) != 0
    """,
}

"""
Plugin 2005: Computer Account Supports Deprecated DES Kerberos Encryption

Same check as user-account plugin 1011, applied to computer objects.
DES is cryptographically broken; an account with these bits explicitly
set represents a deliberate downgrade, not just an absence of modern
encryption support.
"""

PLUGIN = {
    "plugin_id": 2005,
    "category": "Computer Accounts",
    "name": "Computer Account Supports Deprecated DES Kerberos Encryption",
    "version": "1.2",
    "revision_date": "2026-07-15",
    "remediation": (
        "Update msDS-SupportedEncryptionTypes to remove the DES bits, "
        "leaving AES (and RC4 only if still genuinely required during a "
        "migration window) -- a value of 24 (AES128+AES256 only) is the "
        "modern target for most environments. Audit for any legacy "
        "system or application on this machine that might actually "
        "depend on DES specifically before removing it."
    ),
    "control_id": "CRED-102",
    "framework_tags": ["DISA-STIG"],
    "references": [
        {"title": "Microsoft: Network security -- Configure encryption types allowed for Kerberos",
         "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-configure-encryption-types-allowed-for-kerberos"},
    ],
    "description": (
        "msDS-SupportedEncryptionTypes bits 0x1 (DES-CBC-CRC) and 0x2 "
        "(DES-CBC-MD5) enable the DES encryption type for this computer "
        "account's Kerberos tickets. DES is cryptographically broken and "
        "has been disabled by default in Windows Kerberos for years; an "
        "account with these bits explicitly set represents a deliberate "
        "downgrade, not merely an absence of AES support. Downgraded "
        "when disabled: this governs the account's own Kerberos "
        "authentication, which a disabled account cannot perform."
    ),
    "base_severity": "high",
    "query": """
        SELECT
            'fail' AS status,
            c.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE GREATEST(0,
                (CASE WHEN c.is_domain_controller THEN 3 ELSE 2 END)
                - (CASE WHEN c.is_enabled THEN 0 ELSE 2 END)
            )
                WHEN 3 THEN 'critical'
                WHEN 2 THEN 'high'
                WHEN 1 THEN 'medium'
                ELSE 'low'
            END AS fd_severity,
            (CASE WHEN c.is_domain_controller THEN 'Domain Controller ' ELSE '' END)
                || 'Computer Account ' || c.sam_account_name
                || ' has deprecated DES Kerberos encryption enabled'
                || CASE WHEN NOT c.is_enabled
                        THEN ' (severity reduced: account is disabled)'
                        ELSE '' END AS summary,
            jsonb_build_object(
                'sam_account_name', c.sam_account_name,
                'dns_hostname', c.dns_hostname,
                'supported_encryption_types', c.supported_encryption_types,
                'des_cbc_crc_enabled', (c.supported_encryption_types & 1) != 0,
                'des_cbc_md5_enabled', (c.supported_encryption_types & 2) != 0,
                'is_enabled', c.is_enabled,
                'is_domain_controller', c.is_domain_controller
            ) AS detail
        FROM ad_computer c
        WHERE c.valid_to IS NULL
          AND c.client_id = %(client_id)s
          AND c.supported_encryption_types IS NOT NULL
          AND (c.supported_encryption_types & 3) != 0
    """,
}

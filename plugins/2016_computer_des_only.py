"""
Plugin 2016: Computer Account Restricted to DES-Only Kerberos Encryption

Same UAC bit (USE_DES_KEY_ONLY, 0x200000) as user-account plugin 1019,
applied to computer objects -- distinct from and worse than plugin 2005's
msDS-SupportedEncryptionTypes check, since this forces DES-only rather
than merely permitting it.

Downgraded when the computer account is disabled: this specifically
governs Kerberos authentication AS this account, which a disabled
account cannot perform, unlike the persistent-configuration findings
elsewhere in this category.
"""

PLUGIN = {
    "plugin_id": 2016,
    "category": "Computer Accounts",
    "name": "Computer Account Restricted to DES-Only Kerberos Encryption",
    "version": "1.1",
    "revision_date": "2026-07-15",
    "remediation": (
        "Remove the USE_DES_KEY_ONLY UAC flag entirely -- this is a "
        "legacy Windows 2000/2003-era mechanism with essentially no "
        "modern legitimate use case. After removing it, verify "
        "msDS-SupportedEncryptionTypes is separately configured with AES "
        "support (see the companion DES-encryption-types finding, "
        "plugin 2005) so the account isn't left without any explicitly "
        "configured encryption type at all."
    ),
    "control_id": "CRED-108",
    "framework_tags": [],
    "references": [
        {"title": "Microsoft: Network security -- Configure encryption types allowed for Kerberos",
         "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-configure-encryption-types-allowed-for-kerberos"},
    ],
    "description": (
        "The USE_DES_KEY_ONLY UAC bit (0x200000) is the older, Windows "
        "2000/2003-era mechanism for restricting an account to DES "
        "exclusively -- independent of, and potentially conflicting "
        "with, the newer msDS-SupportedEncryptionTypes attribute (plugin "
        "2005). Same underlying mechanism as user-account plugin 1019, "
        "applied here to computer objects. Downgraded when disabled, "
        "unlike most other computer-account findings in this category: "
        "this specifically governs the account's own ability to "
        "authenticate via Kerberos, which a disabled account cannot do "
        "regardless of this setting -- distinct from findings like "
        "unconstrained delegation or SID history that are persistent "
        "configuration unaffected by the account's enabled state."
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
                || ' is restricted to DES-only Kerberos encryption (USE_DES_KEY_ONLY)'
                || CASE WHEN NOT c.is_enabled
                        THEN ' (severity reduced: account is disabled)'
                        ELSE '' END AS summary,
            jsonb_build_object(
                'sam_account_name', c.sam_account_name,
                'dns_hostname', c.dns_hostname,
                'user_account_control', c.user_account_control,
                'supported_encryption_types', c.supported_encryption_types,
                'is_enabled', c.is_enabled,
                'is_domain_controller', c.is_domain_controller
            ) AS detail
        FROM ad_computer c
        WHERE c.valid_to IS NULL
          AND c.client_id = %(client_id)s
          AND c.user_account_control IS NOT NULL
          AND (c.user_account_control & 2097152) != 0
    """,
}

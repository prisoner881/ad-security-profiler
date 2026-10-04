"""
Plugin 1038: Account Configured to Allow DES Kerberos Encryption

DES (both DES-CBC-CRC and DES-CBC-MD5) is a 56-bit-effective-key
symmetric cipher, trivially brute-forceable with commodity hardware
today -- any Kerberos ticket issued using it is not meaningfully
protected. Bit values confirmed directly against Microsoft's own
[MS-KILE] specification (section on msDS-SupportedEncryptionTypes)
before building this: bit 0x1 = DES-CBC-CRC, bit 0x2 = DES-CBC-MD5,
within the msDS-SupportedEncryptionTypes bitmask. Separately,
userAccountControl bit 0x200000 (USE_DES_KEY_ONLY) forces DES
regardless of what msDS-SupportedEncryptionTypes otherwise allows --
both are checked, matching PingCastle's own S-DesEnabled rule's
combined detection approach (independently confirmed against
Microsoft's own documented UAC flag semantics, not just copied from
that rule).

Covers both users and computers, since either can hold a
Kerberos-usable credential with DES explicitly enabled.

[v1.1] Absorbs plugin 1011 (User Account Supports Deprecated DES Kerberos
Encryption), now retired with superseded_by=1038. 1011 checked only the
0x1/0x2 bits on enabled users -- a strict subset of this query -- so it
reported every one of its accounts a second time. Its Microsoft
encryption-types reference and its "target value 24 (AES128+AES256)"
remediation note are carried over; the query, summary and severity are
unchanged, so existing 1038 findings do not churn.

[v1.2] Disabled accounts are rated 'low' instead of 'high' (they cannot
obtain or be issued tickets until re-enabled; the merge with 1011, which
looked at enabled users only, had widened scope to long-disabled legacy
computer objects at full severity). The DES list in the summary is
aggregated in an explicit order.
"""

PLUGIN = {
    "plugin_id": 1038,
    "category": "User Accounts",
    "name": "Account Configured to Allow DES Kerberos Encryption",
    "version": "1.2",
    "revision_date": "2026-10-04",
    "remediation": (
        "Remove DES support: clear bits 0x1 and 0x2 from "
        "msDS-SupportedEncryptionTypes (e.g. via `Set-ADAccountControl` "
        "or `Set-ADUser`/`Set-ADComputer -KerberosEncryptionType` "
        "specifying only AES128/AES256 -- an msDS-SupportedEncryptionTypes "
        "value of 24 is the modern target for most environments), and uncheck 'Use Kerberos DES "
        "encryption for this account' in the account's Account tab if "
        "present (clears userAccountControl bit 0x200000). Confirm no "
        "legacy system genuinely requires DES before removing it -- "
        "this is rare today, but worth a quick check rather than "
        "assuming."
    ),
    "control_id": "USR-138",
    "framework_tags": [
        "NIST-800-53-SC-13",
        "NIST-CSF-2.0-PR.DS-02",
        "PCI-DSS-4.0-12.3.3",
        "CIS-CSC-8-3.10",
        "ISO-27001-2022-A.8.24",
        "SOC2-CC6.1",
        "HIPAA-164.312(e)(1)",
        "MITRE-ATTCK-T1558",
    ],
    "references": [
        {"title": "Microsoft [MS-KILE]: msDS-SupportedEncryptionTypes bit flags",
         "url": "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/6cfc7b50-11ed-4b4d-846d-6f08f0812919"},
        {"title": "Microsoft: Network security -- Configure encryption types allowed for Kerberos",
         "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-configure-encryption-types-allowed-for-kerberos"},
        {"title": "PingCastle: Old authentication protocols rules -- S-DesEnabled",
         "url": "https://pingcastle.com/PingCastleFiles/ad_hc_rules_list.html"},
    ],
    "description": (
        "An account's msDS-SupportedEncryptionTypes explicitly permits "
        "DES-CBC-CRC and/or DES-CBC-MD5 (bits 0x1/0x2), or "
        "userAccountControl has USE_DES_KEY_ONLY (0x200000) set, "
        "forcing DES regardless of the encryption-types bitmask. DES's "
        "56-bit effective key length is trivially broken with commodity "
        "hardware; any Kerberos ticket using it offers no meaningful "
        "protection."
    ),
    "base_severity": "high",
    "query": """
        WITH des_accounts AS (
            SELECT u.object_guid, u.sam_account_name, u.user_principal_name,
                   u.is_enabled, u.supported_encryption_types, u.user_account_control,
                   'user' AS object_class
            FROM ad_user u
            WHERE u.client_id = %(client_id)s AND u.valid_to IS NULL
              AND ((COALESCE(u.supported_encryption_types, 0) & 3) != 0
                   OR (COALESCE(u.user_account_control, 0) & 2097152) != 0)
            UNION ALL
            SELECT c.object_guid, c.sam_account_name, NULL AS user_principal_name,
                   c.is_enabled, c.supported_encryption_types, c.user_account_control,
                   'computer' AS object_class
            FROM ad_computer c
            WHERE c.client_id = %(client_id)s AND c.valid_to IS NULL
              AND ((COALESCE(c.supported_encryption_types, 0) & 3) != 0
                   OR (COALESCE(c.user_account_control, 0) & 2097152) != 0)
        )
        SELECT
            'fail' AS status,
            d.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN d.is_enabled IS FALSE THEN 'low' ELSE 'high' END AS fd_severity,  -- [v1.2]
            (CASE WHEN d.object_class = 'computer' THEN 'Computer ' ELSE 'User ' END)
                || 'Account ' || COALESCE(d.user_principal_name, d.sam_account_name, d.object_guid::text)
                || ' permits DES Kerberos encryption ('
                || (SELECT string_agg(x, ', ' ORDER BY n) FROM (VALUES
                        (1, CASE WHEN (COALESCE(d.supported_encryption_types, 0) & 1) != 0 THEN 'DES-CBC-CRC' END),
                        (2, CASE WHEN (COALESCE(d.supported_encryption_types, 0) & 2) != 0 THEN 'DES-CBC-MD5' END),
                        (3, CASE WHEN (COALESCE(d.user_account_control, 0) & 2097152) != 0 THEN 'USE_DES_KEY_ONLY flag' END)
                    ) AS v(n, x) WHERE x IS NOT NULL)
                || ')' AS summary,
            jsonb_build_object(
                'sam_account_name', d.sam_account_name,
                'object_class', d.object_class,
                'is_enabled', d.is_enabled,
                'supported_encryption_types', d.supported_encryption_types,
                'use_des_key_only_flag', (COALESCE(d.user_account_control, 0) & 2097152) != 0
            ) AS detail
        FROM des_accounts d
    """,
}

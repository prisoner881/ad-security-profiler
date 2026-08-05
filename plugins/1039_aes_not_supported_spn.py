"""
Plugin 1039: Service Account (SPN-Bearing) Does Not Support AES Encryption

Distinct from plugin 1038 (DES enabled, a real vulnerability) -- this
is a modernization gap, not a broken cipher: an account with a
registered SPN (making it Kerberoastable by definition -- see plugin
1009) whose msDS-SupportedEncryptionTypes doesn't include AES128 or
AES256 (bits 0x8/0x10) will have its service tickets issued using
whatever weaker cipher the domain still permits, most commonly RC4.
RC4 tickets remain crackable offline once obtained via Kerberoasting;
AES support doesn't prevent the Kerberoasting request itself but makes
the resulting ticket meaningfully more resistant to offline cracking.

Matches PingCastle's own S-AesNotEnabled rule in spirit and bit
values, but deliberately kept as its own low/informational-severity
finding rather than folded into plugin 1009 -- 1009 is about whether
an account CAN be Kerberoasted at all (already a "should this SPN
exist" question); this is specifically about cipher strength for
accounts where an SPN is legitimately needed.
"""

PLUGIN = {
    "plugin_id": 1039,
    "category": "User Accounts",
    "name": "Service Account (SPN-Bearing) Does Not Support AES Encryption",
    "version": "1.0",
    "revision_date": "2026-08-05",
    "remediation": (
        "Enable AES for this account: `Set-ADUser -Identity <name> "
        "-KerberosEncryptionType AES128,AES256` (or check both AES "
        "boxes in the account's Account tab). After changing this "
        "setting, the account's password must be rotated once for the "
        "new AES keys to actually be generated -- flipping the "
        "attribute alone does not retroactively create them. For gMSA "
        "accounts, edit msDS-SupportedEncryptionTypes directly, since "
        "gMSAs don't expose this via the standard account UI."
    ),
    "control_id": "USR-139",
    "framework_tags": [],
    "references": [
        {"title": "Microsoft [MS-KILE]: msDS-SupportedEncryptionTypes bit flags",
         "url": "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/6cfc7b50-11ed-4b4d-846d-6f08f0812919"},
        {"title": "PingCastle: Old authentication protocols rules -- S-AesNotEnabled",
         "url": "https://pingcastle.com/PingCastleFiles/ad_hc_rules_list.html"},
    ],
    "description": (
        "An account with a registered SPN (Kerberoastable by "
        "definition) does not have AES128 or AES256 enabled in "
        "msDS-SupportedEncryptionTypes, meaning its service tickets "
        "fall back to a weaker cipher (typically RC4). Doesn't prevent "
        "Kerberoasting itself, but AES support makes the resulting "
        "ticket meaningfully more resistant to offline cracking. A "
        "modernization gap, not a broken cipher -- kept at low/"
        "informational severity, distinct from plugin 1038's DES "
        "finding."
    ),
    "base_severity": "low",
    "query": """
        SELECT
            'warn' AS status,
            u.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'low' AS fd_severity,
            'Service Account ' || COALESCE(u.user_principal_name, u.sam_account_name)
                || ' has a registered SPN but does not support AES Kerberos encryption' AS summary,
            jsonb_build_object(
                'sam_account_name', u.sam_account_name,
                'supported_encryption_types', u.supported_encryption_types,
                'service_principal_names', u.service_principal_names,
                'pwd_last_set', u.pwd_last_set
            ) AS detail
        FROM ad_user u
        WHERE u.client_id = %(client_id)s
          AND u.valid_to IS NULL
          AND u.is_enabled
          AND u.service_principal_names IS NOT NULL
          AND array_length(u.service_principal_names, 1) > 0
          AND (COALESCE(u.supported_encryption_types, 0) & 24) = 0
    """,
}
